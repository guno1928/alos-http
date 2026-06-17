package core

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

type StaticConfig struct {
	Root   string
	Index  string
	Browse bool
}

// staticStreamThreshold is the file size above which the static handler streams
// from the open file (sendfile / chunked) instead of buffering it whole, so a
// request for a large file cannot pin its size in heap memory.
const staticStreamThreshold = 1 << 20 // 1 MiB

func sanitizeStaticPath(p string) (string, bool) {
	if strings.ContainsAny(p, "\x00\\") {
		return "", false
	}
	if strings.Contains(p, "..") {
		return "", false
	}
	return p, true
}

func Static(urlPrefix string, cfg StaticConfig) HandlerFunc {
	if !strings.HasPrefix(urlPrefix, "/") {
		urlPrefix = "/" + urlPrefix
	}
	urlPrefix = strings.TrimRight(urlPrefix, "/")

	if cfg.Index == "" {
		cfg.Index = "index.html"
	}

	// Open the configured root once and confine every request to it at the
	// kernel boundary. os.Root refuses path components that escape the root and
	// refuses to traverse symlinks that point outside it, which a string-prefix
	// jail cannot do. Fail closed: if the root cannot be opened, serve nothing.
	root, rootErr := os.OpenRoot(cfg.Root)

	return func(req *Request, resp *Response) {
		if rootErr != nil {
			resp.Status(404).String("Not Found")
			return
		}

		reqPath := strings.TrimPrefix(req.Path, urlPrefix)
		if reqPath == "" {
			reqPath = "/"
		}

		if !strings.HasPrefix(reqPath, "/") {
			reqPath = "/" + reqPath
		}

		cleanRel, ok := sanitizeStaticPath(reqPath)
		if !ok {
			resp.Status(400).String("Bad Request")
			return
		}

		// os.Root treats its argument as relative to the root; a leading slash
		// would be rejected as absolute.
		cleanRel = strings.TrimPrefix(cleanRel, "/")
		if cleanRel == "" {
			cleanRel = "."
		}

		info, err := root.Stat(cleanRel)
		if err != nil {
			resp.Status(404).String("Not Found")
			return
		}

		if info.IsDir() {
			indexRel := path.Join(cleanRel, cfg.Index)
			if indexInfo, err := root.Stat(indexRel); err == nil && !indexInfo.IsDir() {
				serveStaticFile(resp, root, indexRel, indexInfo.Size())
				return
			}

			if cfg.Browse {
				entries, err := fs.ReadDir(root.FS(), cleanRel)
				if err != nil {
					resp.Status(500).String("Internal Server Error")
					return
				}
				dirURL := urlPrefix + "/" + cleanRel
				if !strings.HasSuffix(dirURL, "/") {
					dirURL += "/"
				}
				var b strings.Builder
				b.WriteString("<html><head><title>Index of ")
				b.WriteString(dirURL)
				b.WriteString("</title></head><body><h1>Index of ")
				b.WriteString(dirURL)
				b.WriteString("</h1><ul>")
				for _, entry := range entries {
					name := entry.Name()
					if entry.IsDir() {
						name += "/"
					}
					b.WriteString(fmt.Sprintf("<li><a href=\"%s%s\">%s</a></li>", dirURL, name, name))
				}
				b.WriteString("</ul></body></html>")
				resp.Status(200).SetHeader("Content-Type", "text/html; charset=utf-8").SetBody([]byte(b.String()))
				return
			}

			resp.Status(404).String("Not Found")
			return
		}

		serveStaticFile(resp, root, cleanRel, info.Size())
	}
}

// serveStaticFile serves a regular file resolved within root. Small files are
// read into memory (cheap and lets the existing buffered response path handle
// them); files above staticStreamThreshold are streamed from the open file via
// the sendfile fast path so their size never lands on the heap.
func serveStaticFile(resp *Response, root *os.Root, rel string, size int64) {
	mime := detectMIME(rel)

	if size <= staticStreamThreshold {
		data, err := readStaticFile(root, rel, size)
		if err != nil {
			resp.Status(500).String("Internal Server Error")
			return
		}
		resp.Status(200).SetHeader("Content-Type", mime).SetBody(data)
		return
	}

	f, err := root.Open(rel)
	if err != nil {
		resp.Status(404).String("Not Found")
		return
	}
	defer f.Close()

	var clBuf [20]byte
	hdrs := [][2]string{{
		"content-length",
		string(appendUint(clBuf[:0], size)),
	}}
	if err := streamFile(resp, f, size, mime, hdrs, nil); err != nil {
		// Headers may already be on the wire; nothing safe to send now.
		return
	}
}

// readStaticFile reads exactly size bytes from the root-confined file. A short
// read is treated as an error so a truncated file is never served as complete.
func readStaticFile(root *os.Root, rel string, size int64) ([]byte, error) {
	f, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data := make([]byte, size)
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, err
	}
	return data, nil
}

func StaticDir(urlPrefix, root string) HandlerFunc {
	return Static(urlPrefix, StaticConfig{Root: root})
}
