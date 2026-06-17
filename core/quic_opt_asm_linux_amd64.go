//go:build linux && amd64 && alos_asm

package core

func quicParseVarintASM(data []byte) (uint64, int)
func quicVarintLenASM(v uint64) int
func quicIsLongHeaderASM(data []byte) bool
func quicReadPacketNumberASM(data []byte, pnLen int) uint64
func quicDecodePacketNumberASM(truncated uint64, truncatedLen int, largestAcked int64) uint64
func quicEncodePacketNumberASM(pn uint64, largestAcked int64) (uint64, int)
func quicPutVarintASM(dst []byte, v uint64) int
