package core

import (
	"html"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type StaticConfig struct {
	Root   string
	Index  string
	Browse bool
}

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

		if !strings.HasPrefix(absFullPath, absRoot) {
			resp.Status(403).String("Forbidden")
			return
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
				// dirURL is request-derived and entry names come from the
				// filesystem; both are untrusted in the HTML output context.
				// Escape names for the text node and percent-encode + attribute-
				// escape them for the href to prevent stored/reflected XSS.
				safeDirURL := html.EscapeString(dirURL)
				var b strings.Builder
				b.WriteString("<html><head><title>Index of ")
				b.WriteString(safeDirURL)
				b.WriteString("</title></head><body><h1>Index of ")
				b.WriteString(safeDirURL)
				b.WriteString("</h1><ul>")
				for _, entry := range entries {
					name := entry.Name()
					href := dirURL + url.PathEscape(name)
					display := name
					if entry.IsDir() {
						href += "/"
						display += "/"
					}
					b.WriteString("<li><a href=\"")
					b.WriteString(html.EscapeString(href))
					b.WriteString("\">")
					b.WriteString(html.EscapeString(display))
					b.WriteString("</a></li>")
				}
				b.WriteString("</ul></body></html>")
				resp.Status(200).SetHeader("Content-Type", "text/html; charset=utf-8").SetBody([]byte(b.String()))
				return
			}

			resp.Status(404).String("Not Found")
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

func StaticDir(urlPrefix, root string) HandlerFunc {
	return Static(urlPrefix, StaticConfig{Root: root})
}
