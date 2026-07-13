//go:build linux

package core

type byteBuffer struct {
	b []byte
	r int
}

func (bb *byteBuffer) write(p []byte) {
	bb.b = append(bb.b, p...)
}

func (bb *byteBuffer) unread() []byte {
	return bb.b[bb.r:]
}

func (bb *byteBuffer) consume(n int) {
	bb.r += n
	if bb.r >= len(bb.b) {
		bb.b = bb.b[:0]
		bb.r = 0
	}
}

func (bb *byteBuffer) length() int {
	return len(bb.b) - bb.r
}

func (bb *byteBuffer) reset() {
	bb.b = bb.b[:0]
	bb.r = 0
}

func (bb *byteBuffer) compact() {
	if bb.r == 0 {
		return
	}
	n := copy(bb.b, bb.b[bb.r:])
	bb.b = bb.b[:n]
	bb.r = 0
}
