package core

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
)

// StaticConfig configures the file server returned by Static.
//
// Root is the filesystem directory whose contents are served; paths are resolved against it and confined to it.
//
//	Example: Root: "./public".
//	Example: Root: "/var/www/site".
//
// Index is the file served for directory requests; defaults to "index.html".
//
//	Example: Index: "index.html".
//	Example: Index: "home.html".
//
// Browse enables an HTML directory listing when a directory has no index file; defaults to false (such requests get 404).
//
//	Example: Browse: true.
//	Example: Browse: false.
type StaticConfig struct {
	Root   string
	Index  string
	Browse bool
}

const maxStaticFileSize = 64 << 20

func sanitizeStaticPath(p string) (string, bool) {
	if strings.ContainsAny(p, "\x00\\") {
		return "", false
	}
	if strings.Contains(p, "..") {
		return "", false
	}
	for _, seg := range strings.Split(p, "/") {
		if len(seg) > 0 && seg[0] == '.' && seg != ".well-known" {
			return "", false
		}
	}
	return p, true
}

// Static returns a handler that serves files from cfg.Root under urlPrefix, stripping urlPrefix from the request path and rejecting traversal outside the root. Register it on a catch-all route so every path below the prefix reaches the handler.
//
// Example: s.Router.GET("/static/*filepath", Static("/static", StaticConfig{Root: "./public"}))
// Example: s.Router.GET("/files/*filepath", Static("/files", StaticConfig{Root: "/var/www", Browse: true}))
func Static(urlPrefix string, cfg StaticConfig) HandlerFunc {
	if !strings.HasPrefix(urlPrefix, "/") {
		urlPrefix = "/" + urlPrefix
	}
	urlPrefix = strings.TrimRight(urlPrefix, "/")

	if cfg.Index == "" {
		cfg.Index = "index.html"
	}

	absRoot, err := filepath.Abs(cfg.Root)
	if err != nil {
		absRoot = cfg.Root
	}

	return func(req *Request, resp *Response) {
		reqPath := req.Path
		if strings.HasPrefix(reqPath, urlPrefix) {
			reqPath = reqPath[len(urlPrefix):]
		}
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

		if strings.HasPrefix(cleanRel, "/") {
			cleanRel = cleanRel[1:]
		}

		fullPath := filepath.Join(absRoot, filepath.FromSlash(cleanRel))

		absFullPath, err := filepath.Abs(fullPath)
		if err != nil {
			resp.Status(404).String("Not Found")
			return
		}

		rootWithSep := absRoot
		if !strings.HasSuffix(rootWithSep, string(os.PathSeparator)) {
			rootWithSep += string(os.PathSeparator)
		}
		if absFullPath != absRoot && !strings.HasPrefix(absFullPath, rootWithSep) {
			resp.Status(403).String("Forbidden")
			return
		}
		if resolved, rerr := filepath.EvalSymlinks(absFullPath); rerr == nil {
			if resolved != absRoot && !strings.HasPrefix(resolved, rootWithSep) {
				resp.Status(403).String("Forbidden")
				return
			}
		}

		info, err := os.Stat(absFullPath)
		if err != nil {
			resp.Status(404).String("Not Found")
			return
		}

		if info.IsDir() {
			indexPath := filepath.Join(absFullPath, cfg.Index)
			if indexInfo, err := os.Stat(indexPath); err == nil && !indexInfo.IsDir() {
				data, err := os.ReadFile(indexPath)
				if err != nil {
					resp.Status(500).String("Internal Server Error")
					return
				}
				mime := detectMIME(indexPath)
				resp.Status(200).SetHeader("Content-Type", mime).SetBody(data)
				return
			}

			if cfg.Browse {
				entries, err := os.ReadDir(absFullPath)
				if err != nil {
					resp.Status(500).String("Internal Server Error")
					return
				}
				dirURL := urlPrefix + "/" + cleanRel
				if !strings.HasSuffix(dirURL, "/") {
					dirURL += "/"
				}
				safeDir := html.EscapeString(dirURL)
				var b strings.Builder
				b.WriteString("<html><head><title>Index of ")
				b.WriteString(safeDir)
				b.WriteString("</title></head><body><h1>Index of ")
				b.WriteString(safeDir)
				b.WriteString("</h1><ul>")
				for _, entry := range entries {
					name := entry.Name()
					if entry.IsDir() {
						name += "/"
					}
					b.WriteString(fmt.Sprintf("<li><a href=\"%s\">%s</a></li>", html.EscapeString(dirURL+name), html.EscapeString(name)))
				}
				b.WriteString("</ul></body></html>")
				resp.Status(200).SetHeader("Content-Type", "text/html; charset=utf-8").SetBody([]byte(b.String()))
				return
			}

			resp.Status(404).String("Not Found")
			return
		}

		if fi, serr := os.Stat(absFullPath); serr == nil && fi.Size() > maxStaticFileSize {
			resp.Status(413).String("File Too Large")
			return
		}
		data, err := os.ReadFile(absFullPath)
		if err != nil {
			resp.Status(500).String("Internal Server Error")
			return
		}
		mime := detectMIME(absFullPath)
		resp.Status(200).SetHeader("Content-Type", mime).SetBody(data)
	}
}

// StaticDir serves the directory root under urlPrefix using default StaticConfig; it is shorthand for Static(urlPrefix, StaticConfig{Root: root}).
//
// Example: s.Router.GET("/assets/*filepath", StaticDir("/assets", "./assets"))
// Example: s.Router.GET("/dl/*filepath", StaticDir("/dl", "/srv/downloads"))
func StaticDir(urlPrefix, root string) HandlerFunc {
	return Static(urlPrefix, StaticConfig{Root: root})
}
