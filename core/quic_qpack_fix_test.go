package core

import (
	"testing"
)

func qpackPrefix() []byte { return []byte{0x00, 0x00} }

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func adversarialQPACKInputs() [][]byte {
	var in [][]byte

	hugeIndexed := append(qpackPrefix(), 0xFF)
	hugeIndexed = append(hugeIndexed, repeatByte(0xFF, 9)...)
	hugeIndexed = append(hugeIndexed, 0x00)
	in = append(in, hugeIndexed)

	hugeNameRef := append(qpackPrefix(), 0x5F)
	hugeNameRef = append(hugeNameRef, repeatByte(0xFF, 9)...)
	hugeNameRef = append(hugeNameRef, 0x00)
	in = append(in, hugeNameRef)

	hugeNameLen := append(qpackPrefix(), 0x27)
	hugeNameLen = append(hugeNameLen, repeatByte(0xFF, 9)...)
	hugeNameLen = append(hugeNameLen, 0x00)
	in = append(in, hugeNameLen)

	hugeStrLen := append(qpackPrefix(), 0x20)
	hugeStrLen = append(hugeStrLen, 0xFF)
	hugeStrLen = append(hugeStrLen, repeatByte(0xFF, 9)...)
	hugeStrLen = append(hugeStrLen, 0x00)
	in = append(in, hugeStrLen)

	return in
}

func TestQPACKDecodeAdversarialNoPanic(t *testing.T) {
	var d QPACKDecoder
	for i, in := range adversarialQPACKInputs() {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("QPACK Decode panicked on adversarial input %d: %v", i, r)
				}
			}()
			_, _ = d.Decode(in)
		}()
	}
}

func FuzzQPACKDecode(f *testing.F) {
	for _, seed := range adversarialQPACKInputs() {
		f.Add(seed)
	}
	f.Add([]byte{0x00, 0x00, 0xC1})
	f.Add([]byte{0x00, 0x00})
	var d QPACKDecoder
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = d.Decode(b)
	})
}

func TestParseACKHugeRangeCountNoOOM(t *testing.T) {
	data := []byte{
		0x00,
		0x00,
		0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
		0x00,
	}
	p := &quicFrameParser{data: data}
	_, err := p.parseACK(false)
	if err != ErrTruncated {
		t.Fatalf("expected ErrTruncated for an ACK declaring 2^30 ranges with no payload, got %v", err)
	}
}

func TestHandleStreamFrameHugeOffsetBounded(t *testing.T) {
	s := newQUICStream(1, nil)
	s.handleStreamFrame(quicStreamFrame{streamID: 1, offset: 1 << 40, data: []byte{1, 2, 3}})
	if uint64(len(s.recvBuf)) > s.maxRecv {
		t.Fatalf("recvBuf grew to %d, exceeding maxRecv %d (unbounded alloc)", len(s.recvBuf), s.maxRecv)
	}
	if len(s.recvBuf) != 0 {
		t.Fatalf("out-of-window frame should be dropped, recvBuf len=%d", len(s.recvBuf))
	}
}

func TestHandleStreamFrameInWindowStillWorks(t *testing.T) {
	s := newQUICStream(1, nil)
	s.handleStreamFrame(quicStreamFrame{streamID: 1, offset: 0, data: []byte("hello")})
	if string(s.recvBuf) != "hello" {
		t.Fatalf("in-order frame should append, got %q", s.recvBuf)
	}
}
