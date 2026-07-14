package core

const maxAckRanges = 32

type pnRange struct {
	lo, hi uint64
}

func (qc *QUICConn) recordRecvPN(space int, pn uint64) {
	rs := qc.ackRanges[space]
	idx := len(rs)
	for i := range rs {
		if pn >= rs[i].lo && pn <= rs[i].hi {
			return
		}
		if pn > rs[i].hi {
			idx = i
			break
		}
	}
	rs = append(rs, pnRange{})
	copy(rs[idx+1:], rs[idx:])
	rs[idx] = pnRange{pn, pn}

	merged := rs[:1]
	for i := 1; i < len(rs); i++ {
		last := &merged[len(merged)-1]
		if rs[i].hi+1 >= last.lo {
			if rs[i].lo < last.lo {
				last.lo = rs[i].lo
			}
		} else {
			merged = append(merged, rs[i])
		}
	}
	if len(merged) > maxAckRanges {
		merged = merged[:maxAckRanges]
	}
	qc.ackRanges[space] = merged
}

func quicAppendACKFrameRanges(dst []byte, ackDelay uint64, ranges []pnRange) []byte {
	if len(ranges) == 0 {
		return dst
	}
	dst = quicAppendVarint(dst, quicFrameACK)
	dst = quicAppendVarint(dst, ranges[0].hi)
	dst = quicAppendVarint(dst, ackDelay)
	dst = quicAppendVarint(dst, uint64(len(ranges)-1))
	dst = quicAppendVarint(dst, ranges[0].hi-ranges[0].lo)

	prevLo := ranges[0].lo
	for i := 1; i < len(ranges); i++ {
		dst = quicAppendVarint(dst, prevLo-ranges[i].hi-2)
		dst = quicAppendVarint(dst, ranges[i].hi-ranges[i].lo)
		prevLo = ranges[i].lo
	}
	return dst
}
