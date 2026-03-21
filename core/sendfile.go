package core

import (
	"os"
	"path/filepath"
	"strings"
)

// SendFileOption configures the behavior of Response.SendFile.
type SendFileOption func(*sendFileConfig)

type sendFileConfig struct {
	attachment  string
	rateLimit   int64
	burstSize   int64
	contentType string
}

// WithAttachment sets the Content-Disposition header to "attachment" with the
// given filename, triggering a file download in the browser.
//
//	resp.SendFile("data/export.csv", core.WithAttachment("export-2024.csv"))
func WithAttachment(filename string) SendFileOption {
	return func(c *sendFileConfig) { c.attachment = filename }
}

// WithRateLimit caps the file transfer speed to the given rate in megabits per
// second and sets the burst size equal to the rate. Valid range is 1-250000 Mbps.
//
//	resp.SendFile("video.mp4", core.WithRateLimit(50))  // 50 Mbps
func WithRateLimit(mbps int64) SendFileOption {
	return func(c *sendFileConfig) {
		if mbps < 1 {
			mbps = 1
		}
		if mbps > 250000 {
			mbps = 250000
		}
		bytesPerSec := mbps * 125000
		c.rateLimit = bytesPerSec
		if c.burstSize == 0 {
			c.burstSize = bytesPerSec
		}
	}
}

// WithRateLimitBurst is like WithRateLimit but also sets a separate burst size
// in Mbps, allowing short bursts above the steady-state rate.
//
//	resp.SendFile("file.zip", core.WithRateLimitBurst(10, 50))  // 10 Mbps steady, 50 Mbps burst
func WithRateLimitBurst(mbps, burstMbps int64) SendFileOption {
	return func(c *sendFileConfig) {
		if mbps < 1 {
			mbps = 1
		}
		if mbps > 250000 {
			mbps = 250000
		}
		if burstMbps < 1 {
			burstMbps = 1
		}
		c.rateLimit = mbps * 125000
		c.burstSize = burstMbps * 125000
	}
}

// WithContentType overrides the auto-detected MIME type for the file.
//
//	resp.SendFile("data.bin", core.WithContentType("application/pdf"))
func WithContentType(ct string) SendFileOption {
	return func(c *sendFileConfig) { c.contentType = ct }
}

func sanitizePath(path string) (string, error) {
	cleaned := filepath.Clean(path)
	if filepath.IsAbs(cleaned) {
		return "", os.ErrPermission
	}
	for _, part := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if part == ".." {
			return "", os.ErrPermission
		}
	}
	return cleaned, nil
}

func sanitizeFilename(name string) string {
	var b [256]byte
	buf := b[:0]
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '"' || c == '\\' || c == '\r' || c == '\n' || c < 0x20 {
			continue
		}
		buf = append(buf, c)
	}
	return string(buf)
}

// SendFile streams a file to the client with automatic MIME type detection,
// optional download attachment headers, and optional bandwidth rate limiting.
// The path is sanitized to prevent directory traversal.
//
//	// Serve a file inline:
//	resp.SendFile("static/image.png")
//
//	// Force download with a custom filename:
//	resp.SendFile("data/report.csv",
//	    core.WithAttachment("report-2024.csv"))
//
//	// Rate-limit to 10 Mbps:
//	resp.SendFile("videos/demo.mp4",
//	    core.WithRateLimit(10),
//	    core.WithAttachment("demo.mp4"))
func (r *Response) SendFile(path string, opts ...SendFileOption) error {
	var cfg sendFileConfig
	for _, o := range opts {
		o(&cfg)
	}

	safe, err := sanitizePath(path)
	if err != nil {
		r.Status(403).String("forbidden")
		return err
	}

	resolved, err := filepath.EvalSymlinks(safe)
	if err != nil {
		r.Status(404).String("not found")
		return err
	}

	absResolved, err := filepath.Abs(resolved)
	if err != nil {
		r.Status(403).String("forbidden")
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		r.Status(500).String("internal error")
		return err
	}
	relPath, err := filepath.Rel(cwd, absResolved)
	if err != nil {
		r.Status(403).String("forbidden")
		return err
	}
	if relPath == ".." || strings.HasPrefix(relPath, ".."+string(filepath.Separator)) {
		r.Status(403).String("forbidden")
		return os.ErrPermission
	}
	safe = resolved

	f, err := os.Open(safe)
	if err != nil {
		r.Status(404).String("not found")
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		r.Status(500).String("stat error")
		return err
	}

	if fi.IsDir() {
		r.Status(403).String("forbidden")
		return os.ErrPermission
	}

	ct := cfg.contentType
	if ct == "" {
		ct = detectMIME(path)
	}

	var hdrs [][2]string
	if cfg.attachment != "" {
		hdrs = append(hdrs, [2]string{
			"content-disposition",
			"attachment; filename=\"" + sanitizeFilename(cfg.attachment) + "\"",
		})
	}
	var clBuf [20]byte
	hdrs = append(hdrs, [2]string{
		"content-length",
		string(appendUint(clBuf[:0], fi.Size())),
	})

	sw := r.ensureSW()
	if sw == nil {
		r.Status(500).String("no stream writer available")
		return ErrStreamClosed
	}
	if err := sw.WriteHeader(200, hdrs, ct); err != nil {
		return err
	}
	r.SetStreamer(sw)

	var limiter *TokenBucket
	if cfg.rateLimit > 0 {
		burst := cfg.burstSize
		if burst <= 0 {
			burst = cfg.rateLimit
		}
		limiter = NewTokenBucket(cfg.rateLimit, burst)
	}

	bp := FileReadBufPool.Get().(*[]byte)
	buf := *bp
	defer FileReadBufPool.Put(bp)

	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			if limiter != nil {
				limiter.Wait(int64(n))
			}
			if writeErr := sw.WriteChunk(buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if readErr != nil {
			break
		}
	}
	return sw.Close()
}

// Filename extracts the filename component from a file path, stripping any
// directory prefix.
//
//	core.Filename("/var/data/report.csv")  // "report.csv"
//	core.Filename("report.csv")            // "report.csv"
func Filename(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[i+1:]
		}
	}
	return path
}

func detectMIME(path string) string {
	dot := -1
	for i := len(path) - 1; i >= 0 && path[i] != '/' && path[i] != '\\'; i-- {
		if path[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return "application/octet-stream"
	}
	ext := path[dot:]
	var buf [16]byte
	if len(ext) <= len(buf) {
		n := copy(buf[:], ext)
		for i := 0; i < n; i++ {
			if buf[i] >= 'A' && buf[i] <= 'Z' {
				buf[i] += 0x20
			}
		}
		ext = UnsafeString(buf[:n])
	}
	switch ext {
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js", ".mjs":
		return "application/javascript"
	case ".json":
		return "application/json; charset=utf-8"
	case ".xml":
		return "application/xml; charset=utf-8"
	case ".txt", ".md", ".toml":
		return "text/plain; charset=utf-8"
	case ".csv":
		return "text/csv; charset=utf-8"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	case ".webp":
		return "image/webp"
	case ".avif":
		return "image/avif"
	case ".mp4":
		return "video/mp4"
	case ".webm":
		return "video/webm"
	case ".mp3":
		return "audio/mpeg"
	case ".ogg":
		return "audio/ogg"
	case ".wav":
		return "audio/wav"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ttf":
		return "font/ttf"
	case ".otf":
		return "font/otf"
	case ".pdf":
		return "application/pdf"
	case ".zip":
		return "application/zip"
	case ".gz":
		return "application/gzip"
	case ".tar":
		return "application/x-tar"
	case ".exe", ".bin", ".dll", ".so":
		return "application/octet-stream"
	case ".wasm":
		return "application/wasm"
	case ".yaml", ".yml":
		return "text/yaml; charset=utf-8"
	}
	return "application/octet-stream"
}
