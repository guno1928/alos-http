//go:build linux && amd64

package core

import "testing"

const (
	h3DateHandlerValue = "Tue, 20 Oct 2026 02:06:23 GMT"
	h3DateAllocRuns    = 200
)

func h3DateEncodedFields(t *testing.T, headers [][2]string) [][2]string {
	t.Helper()
	bp := qpackEncodeResponseHeaders(200, "text/plain", 2, headers, "alos")
	defer putBoxedBufCapped(&qpackEncodeBufPool, bp, qpackEncodeBufPoolMaxCap)
	var dec QPACKDecoder
	fields, err := dec.Decode(*bp)
	if err != nil {
		t.Fatal(err)
	}
	return fields
}

func TestH3ResponseCarriesDate(t *testing.T) {
	perfH2AssertFreshDate(t, h3DateEncodedFields(t, [][2]string{{"X-Kept", "yes"}}))
}

func TestH3ResponseKeepsHandlerDate(t *testing.T) {
	for _, name := range []string{"Date", "date", "DATE"} {
		dates := perfH2DateValues(h3DateEncodedFields(t, [][2]string{{name, h3DateHandlerValue}}))
		if len(dates) != 1 || dates[0] != h3DateHandlerValue {
			t.Fatalf("handler %s header: dates %q, want only %q", name, dates, h3DateHandlerValue)
		}
	}
}

func TestH3ServedResponseCarriesDate(t *testing.T) {
	p := newQUICTestPeer(t, func(r *Router) {
		r.GET("/dated", func(_ *Request, resp *Response) { resp.Status(200).String("ok") })
	})
	p.send(quicStreamBytes(0, 0, h3TestRequest("/dated"), true))
	p.awaitFin(0)
	reader := h3FrameReader{data: quicFixStreamData(p, 0)}
	frameType, payload, ok := reader.next()
	if !ok || frameType != h3FrameHeaders {
		t.Fatal("response does not start with HEADERS")
	}
	var dec QPACKDecoder
	fields, err := dec.Decode(payload)
	if err != nil {
		t.Fatal(err)
	}
	perfH2AssertFreshDate(t, fields)
}

func TestH3ResponseDateEncodeAllocs(t *testing.T) {
	headers := [][2]string{{"Cache-Control", "no-store"}}
	encode := func() {
		bp := qpackEncodeResponseHeaders(200, "text/plain", 128, headers, "alos")
		putBoxedBufCapped(&qpackEncodeBufPool, bp, qpackEncodeBufPoolMaxCap)
	}
	encode()
	if allocs := testing.AllocsPerRun(h3DateAllocRuns, encode); allocs != 0 {
		t.Fatalf("H3 response header encode allocates %.2f times per response, want 0", allocs)
	}
}
