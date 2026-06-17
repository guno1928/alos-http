//go:build alos_asm

package core

func benchAsmStringHash(s string) uint64

func benchAsmEqualFoldASCII(a, b string) bool

func benchAsmValidateHost(host string) bool

func benchAsmParseUint(s string) (int, bool)

func benchAsmContainsCRLF(s string) bool

func benchAsmHuffmanLen(s string) int

func benchAsmPathQuickHash(s string) uint32
