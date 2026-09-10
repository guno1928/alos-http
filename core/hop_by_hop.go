package core

var hopByHopHeaderNames = [...]string{
	"connection",
	"keep-alive",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"proxy-connection",
	"proxy-authenticate",
	"proxy-authorization",
}

var hopByHopLengthMask = func() uint64 {
	var mask uint64
	for _, h := range hopByHopHeaderNames {
		mask |= 1 << uint(len(h))
	}
	return mask
}()

func hopByHopLengthPossible(n int) bool {
	return n < 64 && hopByHopLengthMask&(1<<uint(n)) != 0
}

func isHopByHopName[T ~string | ~[]byte](name T) bool {
	if !hopByHopLengthPossible(len(name)) {
		return false
	}
	for _, h := range hopByHopHeaderNames {
		if len(h) == len(name) && string(name) == h {
			return true
		}
	}
	return false
}

func isHopByHopBytes(name []byte) bool { return isHopByHopName(name) }

func isHopByHopStr(name string) bool { return isHopByHopName(name) }

func isHopByHopFold(name string) bool {
	if !hopByHopLengthPossible(len(name)) {
		return false
	}
	for _, h := range hopByHopHeaderNames {
		if len(h) == len(name) && EqualFoldASCII(name, h) {
			return true
		}
	}
	return false
}
