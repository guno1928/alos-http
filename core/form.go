package core

import (
	"bytes"
	"strings"
)

type FileHeader struct {
	Filename    string
	Size        int64
	ContentType string
	Data        []byte
}

func parseFormURLEncoded(body []byte) map[string][]string {
	return parseQueryString(string(body))
}

func parseMultipart(body []byte, boundary string) (map[string][]string, map[string][]FileHeader) {
	values := make(map[string][]string)
	files := make(map[string][]FileHeader)

	delim := []byte("--" + boundary)
	endMarker := []byte("--" + boundary + "--")

	parts := bytes.Split(body, delim)
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		if bytes.HasPrefix(bytes.TrimSpace(part), []byte("--")) {
			continue
		}

		part = bytes.TrimPrefix(part, []byte("\r\n"))
		if bytes.Equal(bytes.TrimSpace(part), endMarker) {
			continue
		}

		headerEnd := bytes.Index(part, []byte("\r\n\r\n"))
		if headerEnd < 0 {
			continue
		}

		headerSection := string(part[:headerEnd])
		bodySection := part[headerEnd+4:]

		if len(bodySection) >= 2 && bytes.HasSuffix(bodySection, []byte("\r\n")) {
			bodySection = bodySection[:len(bodySection)-2]
		}

		var name, filename, contentType string
		hasFilename := false

		headerLines := strings.Split(headerSection, "\r\n")
		for _, line := range headerLines {
			colonIdx := strings.IndexByte(line, ':')
			if colonIdx < 0 {
				continue
			}
			headerName := trimASCIISpace(line[:colonIdx])
			headerValue := trimASCIISpace(line[colonIdx+1:])

			if EqualFoldASCII(headerName, "Content-Disposition") {
				name = extractParam(headerValue, "name")
				fn := extractParam(headerValue, "filename")
				if fn != "" {
					filename = fn
					hasFilename = true
				} else if strings.Contains(headerValue, "filename=\"\"") {
					hasFilename = true
				}
			} else if EqualFoldASCII(headerName, "Content-Type") {
				contentType = headerValue
			}
		}

		if name == "" {
			continue
		}

		if hasFilename {
			if contentType == "" {
				contentType = "application/octet-stream"
			}
			fh := FileHeader{
				Filename:    filename,
				Size:        int64(len(bodySection)),
				ContentType: contentType,
				Data:        append([]byte(nil), bodySection...),
			}
			files[name] = append(files[name], fh)
		} else {
			values[name] = append(values[name], string(bodySection))
		}
	}

	return values, files
}

func extractParam(header, param string) string {
	search := param + "=\""
	idx := strings.Index(header, search)
	if idx < 0 {
		return ""
	}
	start := idx + len(search)
	end := strings.IndexByte(header[start:], '"')
	if end < 0 {
		return ""
	}
	return header[start : start+end]
}

func extractBoundary(contentType string) string {
	idx := strings.Index(contentType, "boundary=")
	if idx < 0 {
		return ""
	}
	boundary := contentType[idx+len("boundary="):]
	if semi := strings.IndexByte(boundary, ';'); semi >= 0 {
		boundary = boundary[:semi]
	}
	boundary = trimASCIISpace(boundary)
	if len(boundary) >= 2 && boundary[0] == '"' && boundary[len(boundary)-1] == '"' {
		boundary = boundary[1 : len(boundary)-1]
	}
	return boundary
}
