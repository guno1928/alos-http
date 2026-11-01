//go:build linux && amd64

package core

import "bytes"

func parseMultipartInMem(body []byte, boundary string) (map[string][]string, map[string][]FileHeader, error) {
	values := make(map[string][]string)
	files := make(map[string][]FileHeader)
	dash := []byte("--" + boundary)
	delim := []byte("\r\n--" + boundary)
	pos := 0
	for {
		if _, _, ok := multipartBoundaryLine(body[pos:], dash); ok {
			break
		}
		i := bytes.Index(body[pos:], delim)
		if i < 0 {
			return values, files, errMultipartMalformed
		}
		pos += i + 2
	}
	for parts := 0; ; parts++ {
		lineLen, final, ok := multipartBoundaryLine(body[pos:], dash)
		if !ok {
			return values, files, errMultipartMalformed
		}
		if final {
			return values, files, nil
		}
		pos += lineLen
		if parts == maxMultipartParts {
			return values, files, errMultipartTooManyParts
		}
		var block []byte
		if bytes.HasPrefix(body[pos:], []byte("\r\n")) {
			pos += 2
		} else {
			limit := min(len(body), pos+maxMultipartHeaderBytes+4)
			end := bytes.Index(body[pos:limit], []byte("\r\n\r\n"))
			if end < 0 {
				return values, files, errMultipartMalformed
			}
			block = body[pos : pos+end]
			pos += end + 4
		}
		contentEnd, nextLine, ok := multipartContentEnd(body, pos, dash, delim)
		if !ok {
			return values, files, errMultipartMalformed
		}
		content := body[pos:contentEnd]
		header, ok := parseMultipartHeaderLines(block)
		if !ok {
			return values, files, errMultipartMalformed
		}
		part, ok := interpretMultipartHeader(header)
		if !ok {
			return values, files, errMultipartMalformed
		}
		switch {
		case part.name == "":
		case part.hasFilename:
			addMultipartFile(files, part, FileHeader{Size: int64(len(content)), Data: content})
		default:
			addMultipartValue(values, part, content)
		}
		pos = nextLine
	}
}

func multipartBoundaryLine(line, dash []byte) (lineLen int, final, ok bool) {
	if !bytes.HasPrefix(line, dash) {
		return 0, false, false
	}
	lineLen = len(dash)
	final = bytes.HasPrefix(line[lineLen:], []byte("--"))
	if final {
		lineLen += 2
	}
	for lineLen < len(line) && (line[lineLen] == ' ' || line[lineLen] == '\t') {
		lineLen++
	}
	if final && lineLen == len(line) {
		return lineLen, true, true
	}
	if !bytes.HasPrefix(line[lineLen:], []byte("\r\n")) {
		return 0, false, false
	}
	return lineLen + 2, final, true
}

func multipartContentEnd(body []byte, pos int, dash, delim []byte) (contentEnd, nextLine int, ok bool) {
	if bytes.HasPrefix(body[pos:], dash) && multipartDelimiterEndsAt(body[pos+len(dash):]) {
		return pos, pos, true
	}
	for search := pos; ; {
		i := bytes.Index(body[search:], delim)
		if i < 0 {
			return 0, 0, false
		}
		contentEnd = search + i
		search = contentEnd + len(delim)
		if multipartDelimiterEndsAt(body[search:]) {
			return contentEnd, contentEnd + 2, true
		}
	}
}

func multipartDelimiterEndsAt(rest []byte) bool {
	if len(rest) == 0 {
		return true
	}
	switch rest[0] {
	case ' ', '\t', '\r', '\n':
		return true
	case '-':
		return len(rest) > 1 && rest[1] == '-'
	}
	return false
}
