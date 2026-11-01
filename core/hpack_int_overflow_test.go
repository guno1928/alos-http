//go:build linux && amd64

package core

import (
	"math/big"
	"testing"
)

func hpackIntOverflowEncode(value *big.Int, prefixBits uint8) []byte {
	prefixMax := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(prefixBits)), big.NewInt(1))
	if value.Cmp(prefixMax) < 0 {
		return []byte{byte(value.Uint64())}
	}
	encoded := []byte{byte(prefixMax.Uint64())}
	remaining := new(big.Int).Sub(value, prefixMax)
	base := big.NewInt(128)
	for {
		quotient, digit := new(big.Int).QuoRem(remaining, base, new(big.Int))
		if quotient.Sign() == 0 {
			return append(encoded, byte(digit.Uint64()))
		}
		encoded = append(encoded, byte(digit.Uint64())|0x80)
		remaining = quotient
	}
}

func TestHpackDecodeIntRoundTripsUint64Range(t *testing.T) {
	for prefixBits := uint8(1); prefixBits <= 8; prefixBits++ {
		prefixMax := uint64(1)<<prefixBits - 1
		for _, value := range []uint64{0, prefixMax - 1, prefixMax, prefixMax + 1, 127, 128, 1 << 32, 1 << 63, ^uint64(0) - 1, ^uint64(0)} {
			encoded := hpackIntOverflowEncode(new(big.Int).SetUint64(value), prefixBits)
			got, n := HpackDecodeInt(append(encoded, 0xff), prefixBits)
			if got != value || n != len(encoded) {
				t.Fatalf("prefix %d value %d: decoded (%d, %d), want (%d, %d)", prefixBits, value, got, n, value, len(encoded))
			}
		}
	}
}

func TestHpackDecodeIntRejectsOverflow(t *testing.T) {
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	for prefixBits := uint8(1); prefixBits <= 8; prefixBits++ {
		prefixMax := big.NewInt(int64(uint64(1)<<prefixBits - 1))
		for _, value := range []*big.Int{two64, new(big.Int).Add(two64, prefixMax), new(big.Int).Lsh(big.NewInt(1), 69)} {
			encoded := hpackIntOverflowEncode(value, prefixBits)
			if got, n := HpackDecodeInt(encoded, prefixBits); n != 0 || got != 0 {
				t.Fatalf("prefix %d value %s (% x): decoded (%d, %d), want rejection", prefixBits, value, encoded, got, n)
			}
		}
	}
}

func TestHpackDecodeIntRejectsInvalidPrefix(t *testing.T) {
	for _, prefixBits := range []uint8{0, 9, 64, 255} {
		if got, n := HpackDecodeInt([]byte{0x01, 0x00}, prefixBits); n != 0 || got != 0 {
			t.Fatalf("prefix %d: decoded (%d, %d), want rejection", prefixBits, got, n)
		}
	}
}
