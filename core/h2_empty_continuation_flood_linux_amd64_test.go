//go:build linux && amd64

package core

import "testing"

func TestH2EmptyContinuationFloodIsRateLimited(t *testing.T) {
	addr := startH2FixServer(t, nil, nil)
	rc := h2RawDial(t, addr, nil)
	rc.write(H2FrameHeaders, 0, 1, h2FixRequestBlock("GET", "/ok"))
	var flood []byte
	for range h2FixPaddedFloodCount {
		flood = appendH2Frame(flood, H2FrameContinuation, 0, 1, nil)
	}
	rc.writeRaw(flood)
	_ = rc.conn.SetReadDeadline(wallDeadline(h2FixCeiling))
	code, err := rc.awaitGoAway()
	if err != nil {
		t.Fatalf("%d empty CONTINUATION frames drew no GOAWAY: %v", h2FixPaddedFloodCount, err)
	}
	if code != H2ErrEnhanceYourCalm {
		t.Fatalf("GOAWAY code = %d, want ENHANCE_YOUR_CALM", code)
	}
}

func TestH2EmptyContinuationWithinBudgetCompletesRequest(t *testing.T) {
	addr := startH2FixServer(t, nil, func(s *Server) {
		s.Router.GET("/ok", func(_ *Request, resp *Response) { resp.Status(200).String("ok") })
	})
	rc := h2RawDial(t, addr, nil)
	block := h2FixRequestBlock("GET", "/ok")
	rc.write(H2FrameHeaders, H2FlagEndStream, 1, block[:1])
	rc.write(H2FrameContinuation, 0, 1, nil)
	rc.write(H2FrameContinuation, H2FlagEndHeaders, 1, block[1:])
	if f, err := rc.awaitStreamOutcome(1); err != nil || f.typ != H2FrameHeaders {
		t.Fatalf("request split across an empty CONTINUATION failed: frame %d err %v", f.typ, err)
	}
}
