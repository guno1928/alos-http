package core

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

func TestStdnetReadChunkedBodyConsumesTrailers(t *testing.T) {
	raw := "5\r\nhello\r\n0\r\nX-Checksum: abc\r\nX-Other: 1\r\n\r\nHTTP/1.1 200 OK\r\n"
	br := bufio.NewReader(strings.NewReader(raw))
	body, ok := readChunkedBody(br, 1<<20)
	if !ok || string(body) != "hello" {
		t.Fatalf("body = %q ok=%v", body, ok)
	}
	rest, _ := io.ReadAll(br)
	if string(rest) != "HTTP/1.1 200 OK\r\n" {
		t.Fatalf("bytes left on the pooled connection after the chunked body = %q; trailers were not consumed so the next response would be misframed", rest)
	}
}

func TestStdnetTransferEncodingTokenMatch(t *testing.T) {
	head := "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(head))
	_, _, _, isChunked, _, _, err := parseHTTPResponse(br)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !isChunked {
		t.Fatalf("Transfer-Encoding: gzip, chunked not recognised as chunked")
	}
}
