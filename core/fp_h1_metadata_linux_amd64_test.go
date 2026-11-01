package core

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

type h1MetadataSink struct {
	stream      bool
	allowTunnel bool
	headerCalls int
	tunnelCalls int
	status      int
	body        []byte
}

func (*h1MetadataSink) exchangeDone(*Exchange)                             {}
func (sink *h1MetadataSink) shouldStreamResponse(*backendConn, int64) bool { return sink.stream }
func (sink *h1MetadataSink) beginStreamResponse(_ *backendConn, parser *h1Parser, _ int64) {
	sink.headerCalls++
	sink.status = parser.status
}
func (sink *h1MetadataSink) streamResponseChunk(_ *backendConn, data []byte) {
	sink.body = append(sink.body, data...)
}
func (*h1MetadataSink) endStreamResponse(*Exchange) {}
func (sink *h1MetadataSink) beginTunnel(_ *backendConn, parser *h1Parser) bool {
	sink.tunnelCalls++
	sink.status = parser.status
	return sink.allowTunnel
}
func (*h1MetadataSink) tunnelToClient(*backendConn, []byte) {}
func (*h1MetadataSink) closeTunnelPeer(*backendConn)        {}

func h1MetadataConn(limit int, sink *h1MetadataSink) *backendConn {
	configuration := &fpConfig{MaxHeaderBytes: limit}
	configuration.fill(1)
	connection := &backendConn{
		be:  &beLoop{cfg: configuration, sink: sink},
		cur: &Exchange{req: &fpRequest{Method: "GET"}},
	}
	connection.h1.reset()
	return connection
}

func h1MetadataHead(prefix string, size int) string {
	return prefix + strings.Repeat("a", size-len(prefix)-4) + "\r\n\r\n"
}

func h1MetadataTrailers(size int, many bool) string {
	if !many {
		return "X: " + strings.Repeat("a", size-7) + "\r\n\r\n"
	}
	suffix := strings.Repeat("Y: b\r\n", 8) + "\r\n"
	return "X: " + strings.Repeat("a", size-len(suffix)-5) + "\r\n" + suffix
}

func h1MetadataSegments(data string, width int) []string {
	if width == 0 {
		return []string{data}
	}
	var fragments []string
	for len(data) > 0 {
		take := min(width, len(data))
		fragments = append(fragments, data[:take])
		data = data[take:]
	}
	return fragments
}

func h1MetadataFeed(t *testing.T, connection *backendConn, fragments []string) (bool, error) {
	t.Helper()
	for _, fragment := range fragments {
		connection.rbuf.write([]byte(fragment))
		done, err := connection.h1.advance(connection)
		if err != nil || done {
			return done, err
		}
		if again, err := connection.h1.advance(connection); again || err != nil {
			t.Fatalf("advance without new bytes changed parser result: done=%v err=%v", again, err)
		}
	}
	return false, nil
}

func TestH1MetadataHeadBoundaries(t *testing.T) {
	for _, limit := range []int{64, 97, defaultMaxHeader} {
		for _, delta := range []int{-1, 0, 1, 3} {
			head := h1MetadataHead("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX: ", limit+delta)
			if len(head) != limit+delta {
				t.Fatal("head fixture has incorrect wire size")
			}
			layouts := [][]string{{head}, {head[:7], head[7:]}}
			for split := len(head) - 4; split < len(head); split++ {
				layouts = append(layouts, []string{head[:split], head[split:]})
			}
			if limit != defaultMaxHeader {
				layouts = append(layouts, h1MetadataSegments(head, 1))
			}
			for layout, fragments := range layouts {
				t.Run(fmt.Sprintf("limit%d/delta%d/layout%d", limit, delta, layout), func(t *testing.T) {
					sink := &h1MetadataSink{}
					connection := h1MetadataConn(limit, sink)
					done, err := h1MetadataFeed(t, connection, fragments)
					if delta > 0 {
						if err != errFPHeaderTooLarge || done || len(connection.h1.hdrBuf) != 0 || sink.headerCalls != 0 {
							t.Fatalf("oversized head: done=%v err=%v copied=%d callbacks=%d", done, err, len(connection.h1.hdrBuf), sink.headerCalls)
						}
					} else if err != nil || !done || connection.h1.status != 200 || len(connection.h1.hdr) != 2 {
						t.Fatalf("valid head: done=%v status=%d fields=%d err=%v", done, connection.h1.status, len(connection.h1.hdr), err)
					}
				})
			}
		}
	}
	connection := h1MetadataConn(64, &h1MetadataSink{})
	incomplete := h1MetadataHead("HTTP/1.1 200 OK\r\nX: ", 69)
	if done, err := h1MetadataFeed(t, connection, []string{incomplete[:len(incomplete)-4]}); err != errFPHeaderTooLarge || done {
		t.Fatalf("oversized incomplete head: done=%v err=%v", done, err)
	}
}

func TestH1MetadataCoReadBody(t *testing.T) {
	body := strings.Repeat("b", 512)
	for _, stream := range []bool{false, true} {
		for _, framing := range []string{"fixed", "chunked", "te-cl", "eof"} {
			t.Run(fmt.Sprintf("%s/stream%v", framing, stream), func(t *testing.T) {
				sink := &h1MetadataSink{stream: stream}
				connection := h1MetadataConn(96, sink)
				var head, encoded string
				switch framing {
				case "fixed":
					head = "HTTP/1.1 200 OK\r\nContent-Length: 512\r\n\r\n"
					encoded = body
				case "chunked", "te-cl":
					head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
					if framing == "te-cl" {
						head += "Content-Length: 0\r\n"
					}
					head += "\r\n"
					encoded = "200\r\n" + body + "\r\n0\r\n\r\n"
				case "eof":
					head = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
					encoded = body
				}
				if len(head) > connection.be.cfg.MaxHeaderBytes || len(head+encoded) <= connection.be.cfg.MaxHeaderBytes {
					t.Fatal("fixture does not separate head bytes from co-read body")
				}
				done, err := h1MetadataFeed(t, connection, []string{head + encoded})
				if err != nil || done != (framing != "eof") || connection.rbuf.length() != 0 {
					t.Fatalf("body framing: done=%v err=%v unread=%d", done, err, connection.rbuf.length())
				}
				actual := connection.h1.body
				if stream {
					actual = sink.body
					if sink.headerCalls != 1 || sink.status != 200 || len(connection.h1.body) != 0 {
						t.Fatal("stream headers/body ownership changed")
					}
				}
				if string(actual) != body {
					t.Fatalf("body has %d bytes, want %d exact bytes", len(actual), len(body))
				}
				if framing == "eof" && (connection.h1.phase != h1PhaseBodyEOF || connection.h1.keepAlive) {
					t.Fatal("EOF response phase/reuse changed")
				}
			})
		}
	}
}

func TestH1MetadataInformationalAndNoBody(t *testing.T) {
	limit := 80
	interim := h1MetadataHead("HTTP/1.1 103 Early Hints\r\nX: ", limit)
	final := h1MetadataHead("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX: ", limit)
	for _, delta := range []int{0, 1, 2} {
		first, second := interim, final
		if delta == 1 {
			first = h1MetadataHead("HTTP/1.1 103 Early Hints\r\nX: ", limit+1)
		}
		if delta == 2 {
			second = h1MetadataHead("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX: ", limit+1)
		}
		connection := h1MetadataConn(limit, &h1MetadataSink{})
		done, err := h1MetadataFeed(t, connection, []string{first + second})
		if delta == 0 {
			if err != nil || !done || connection.h1.status != 200 || len(connection.h1.hdr) != 2 {
				t.Fatalf("separate valid 1xx/final heads: done=%v err=%v", done, err)
			}
		} else if err != errFPHeaderTooLarge || done {
			t.Fatalf("oversized 1xx/final head: done=%v err=%v", done, err)
		}
	}
	for _, status := range []int{200, 204, 304} {
		connection := h1MetadataConn(80, &h1MetadataSink{})
		if status == 200 {
			connection.cur.req.Method = "HEAD"
		}
		payload := strings.Repeat("p", 256)
		head := fmt.Sprintf("HTTP/1.1 %d Status\r\nContent-Length: 256\r\n\r\n", status)
		done, err := h1MetadataFeed(t, connection, []string{head + payload})
		if err != nil || !done || !connection.h1.noBody || len(connection.h1.body) != 0 || string(connection.rbuf.unread()) != payload {
			t.Fatalf("no-body status%d: done=%v err=%v buffered=%d remainder=%d", status, done, err, len(connection.h1.body), connection.rbuf.length())
		}
	}
}

func TestH1MetadataUpgradeBounds(t *testing.T) {
	for _, requested := range []bool{false, true} {
		for _, size := range []int{127, 128, 129} {
			sink := &h1MetadataSink{allowTunnel: true}
			connection := h1MetadataConn(128, sink)
			if requested {
				connection.cur.req.Upgrade = "websocket"
			}
			head := h1MetadataHead("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX: ", size)
			payload := strings.Repeat("t", 256)
			connection.rbuf.write([]byte(head + payload))
			done, err := connection.h1.advance(connection)
			if size > 128 {
				if err != errFPHeaderTooLarge || done || sink.tunnelCalls != 0 || len(connection.h1.hdrBuf) != 0 {
					t.Fatalf("oversized upgrade: done=%v err=%v calls=%d", done, err, sink.tunnelCalls)
				}
			} else if !requested {
				if err != errFPBadResponse || sink.tunnelCalls != 0 {
					t.Fatalf("unsolicited upgrade: err=%v calls=%d", err, sink.tunnelCalls)
				}
			} else if err != nil || done || sink.tunnelCalls != 1 || sink.status != 101 || string(connection.rbuf.unread()) != payload {
				t.Fatalf("requested upgrade: done=%v err=%v calls=%d status=%d unread=%d", done, err, sink.tunnelCalls, sink.status, connection.rbuf.length())
			}
		}
	}
}

func h1MetadataStartTrailers(t *testing.T, connection *backendConn) {
	t.Helper()
	done, err := h1MetadataFeed(t, connection, []string{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n"})
	if err != nil || done || connection.h1.phase != h1PhaseTrailers || connection.rbuf.length() != 0 {
		t.Fatalf("trailer precondition: done=%v err=%v phase=%d unread=%d", done, err, connection.h1.phase, connection.rbuf.length())
	}
}

func TestH1MetadataTrailerBoundaries(t *testing.T) {
	for _, limit := range []int{64, 97, defaultMaxHeader} {
		for _, delta := range []int{-1, 0, 1} {
			for _, many := range []bool{false, true} {
				section := h1MetadataTrailers(limit+delta, many)
				if len(section) != limit+delta {
					t.Fatal("trailer fixture has incorrect wire size")
				}
				layouts := [][]string{{section}, strings.SplitAfter(section, "\n")}
				if limit != defaultMaxHeader {
					layouts = append(layouts, h1MetadataSegments(section, 1))
				}
				for layout, fragments := range layouts {
					for _, stream := range []bool{false, true} {
						t.Run(fmt.Sprintf("limit%d/delta%d/many%v/layout%d/stream%v", limit, delta, many, layout, stream), func(t *testing.T) {
							sink := &h1MetadataSink{stream: stream}
							connection := h1MetadataConn(limit, sink)
							h1MetadataStartTrailers(t, connection)
							done, err := h1MetadataFeed(t, connection, fragments)
							if delta > 0 {
								if err != errFPHeaderTooLarge || done || connection.rbuf.length() == 0 {
									t.Fatalf("oversized trailers: done=%v err=%v unread=%d", done, err, connection.rbuf.length())
								}
							} else if err != nil || !done || connection.rbuf.length() != 0 {
								t.Fatalf("valid trailers: done=%v err=%v unread=%d", done, err, connection.rbuf.length())
							}
							body := connection.h1.body
							if stream {
								body = sink.body
							}
							if string(body) != "abc" {
								t.Fatalf("chunk body changed: %q", body)
							}
						})
					}
				}
			}
		}
	}
}

func TestH1MetadataTrailerPendingAndReset(t *testing.T) {
	connection := h1MetadataConn(64, &h1MetadataSink{})
	h1MetadataStartTrailers(t, connection)
	if done, err := h1MetadataFeed(t, connection, []string{strings.Repeat("X: a\r\n", 10), "Y: a"}); err != nil || done {
		t.Fatalf("pending trailer exactly at cap: done=%v err=%v", done, err)
	}
	if connection.rbuf.length() != 4 {
		t.Fatal("fixture did not retain exactly one incomplete line")
	}
	connection.rbuf.write([]byte("a"))
	if done, err := connection.h1.advance(connection); err != errFPHeaderTooLarge || done || connection.rbuf.length() != 5 {
		t.Fatalf("consumed lines plus partial line exceed cap: done=%v err=%v pending=%d", done, err, connection.rbuf.length())
	}
	connection = h1MetadataConn(64, &h1MetadataSink{})
	for exchange := 0; exchange < 2; exchange++ {
		connection.h1.reset()
		h1MetadataStartTrailers(t, connection)
		if done, err := h1MetadataFeed(t, connection, h1MetadataSegments(h1MetadataTrailers(64, true), 1)); err != nil || !done {
			t.Fatalf("exchange%d after reset: done=%v err=%v", exchange, done, err)
		}
	}
	connection = h1MetadataConn(64, &h1MetadataSink{})
	h1MetadataStartTrailers(t, connection)
	if done, err := h1MetadataFeed(t, connection, []string{strings.Repeat("x", 65)}); err != errFPHeaderTooLarge || done {
		t.Fatalf("incomplete long trailer: done=%v err=%v", done, err)
	}
}

func TestH1MetadataTrailerRemainder(t *testing.T) {
	for _, section := range []string{"\r\n", "\n", "X: a\n\n", h1MetadataTrailers(64, false)} {
		connection := h1MetadataConn(64, &h1MetadataSink{})
		h1MetadataStartTrailers(t, connection)
		remainder := "HTTP/1.1 200 OK\r\nX: " + strings.Repeat("r", 128) + "\r\n\r\n"
		done, err := h1MetadataFeed(t, connection, []string{section + remainder})
		if err != nil || !done || string(connection.rbuf.unread()) != remainder {
			t.Fatalf("trailer remainder: done=%v err=%v unread=%d", done, err, connection.rbuf.length())
		}
	}
}

func TestH1MetadataChunkLineBoundaries(t *testing.T) {
	for _, delta := range []int{-1, 0, 1} {
		line := "200;x=" + strings.Repeat("a", 4096+delta-len("200;x=")-2) + "\r\n"
		body := strings.Repeat("b", 512)
		if len(line) != 4096+delta {
			t.Fatal("chunk-size fixture has incorrect wire size")
		}
		for _, width := range []int{0, 1, 127} {
			connection := h1MetadataConn(64, &h1MetadataSink{})
			done, err := h1MetadataFeed(t, connection, []string{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"})
			if err != nil || done || connection.h1.phase != h1PhaseChunkSize {
				t.Fatal("chunk-size precondition failed")
			}
			done, err = h1MetadataFeed(t, connection, h1MetadataSegments(line+body+"\r\n0\r\n\r\n", width))
			if delta > 0 {
				if err != errFPBadResponse || done || len(connection.h1.body) != 0 {
					t.Fatalf("oversized chunk line: width=%d done=%v err=%v body=%d", width, done, err, len(connection.h1.body))
				}
			} else if err != nil || !done || string(connection.h1.body) != body {
				t.Fatalf("valid chunk line: width=%d done=%v err=%v body=%d", width, done, err, len(connection.h1.body))
			}
		}
	}
	connection := h1MetadataConn(64, &h1MetadataSink{})
	_, _ = h1MetadataFeed(t, connection, []string{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"})
	if done, err := h1MetadataFeed(t, connection, []string{"1;x=" + strings.Repeat("a", 4093)}); err != errFPBadResponse || done {
		t.Fatalf("incomplete chunk-size bound: done=%v err=%v", done, err)
	}
}

func FuzzH1MetadataWireBudgets(f *testing.F) {
	f.Add(uint8(0), uint8(0), uint8(0), false)
	f.Add(uint8(1), uint8(1), uint8(1), true)
	f.Add(uint8(2), uint8(2), uint8(7), false)
	f.Fuzz(func(t *testing.T, headChoice, trailerChoice, segmentation uint8, stream bool) {
		limit := 96 + int(segmentation%32)
		head := h1MetadataHead("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX: ", limit-1+int(headChoice%3))
		trailers := h1MetadataTrailers(limit-1+int(trailerChoice%3), trailerChoice&4 != 0)
		sink := &h1MetadataSink{stream: stream}
		connection := h1MetadataConn(limit, sink)
		wire := head + "3\r\nabc\r\n0\r\n" + trailers
		done, err := h1MetadataFeed(t, connection, h1MetadataSegments(wire, int(segmentation%32)))
		if len(head) > limit || len(trailers) > limit {
			if err != errFPHeaderTooLarge || done {
				t.Fatalf("oversized section accepted: head=%d trailers=%d limit=%d done=%v err=%v", len(head), len(trailers), limit, done, err)
			}
		} else if err != nil || !done || connection.rbuf.length() != 0 {
			t.Fatalf("valid sections rejected: done=%v err=%v unread=%d", done, err, connection.rbuf.length())
		}
		body := connection.h1.body
		if stream {
			body = sink.body
		}
		wantBody := []byte("abc")
		if len(head) > limit {
			wantBody = nil
		}
		if !bytes.Equal(body, wantBody) {
			t.Fatalf("body=%q, want %q", body, wantBody)
		}
	})
}
