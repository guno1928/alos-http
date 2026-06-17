package core

import (
	"encoding/binary"
	"testing"
)

// buildLongHeaderPacket constructs a minimal version-1 long-header QUIC packet
// with the given long-packet type and DCID length, padded enough that the DCID
// length bound check (6+dcidLen < len) passes for the tested lengths.
func buildLongHeaderPacket(longType byte, dcidLen int) []byte {
	pkt := make([]byte, 0, 64)
	first := quicLongHeaderBit | quicFixedBit | (longType << 4)
	pkt = append(pkt, first)

	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], quicVersion1)
	pkt = append(pkt, ver[:]...)

	pkt = append(pkt, byte(dcidLen))
	pkt = append(pkt, make([]byte, dcidLen)...)

	// SCID length 0.
	pkt = append(pkt, 0x00)

	// For Initial: token length varint (0) then packet length varint.
	if longType == quicInitialType {
		pkt = quicAppendVarint(pkt, 0)
	}
	// Packet length varint covering a small payload, plus the payload bytes.
	const payloadLen = 8
	pkt = quicAppendVarint(pkt, uint64(payloadLen))
	pkt = append(pkt, make([]byte, payloadLen)...)
	return pkt
}

func TestQUICInitialDCIDMinLength(t *testing.T) {
	// RFC 9000 §7.2: Initial packets with DCID < 8 must be dropped.
	for _, dcidLen := range []int{0, 7} {
		pkt := buildLongHeaderPacket(quicInitialType, dcidLen)
		_, _, err := quicParseLongHeader(pkt)
		if err == nil {
			t.Fatalf("Initial DCID len %d: expected reject, got accept", dcidLen)
		}
	}

	// DCID len 8 is the minimum acceptable length and must parse.
	pkt := buildLongHeaderPacket(quicInitialType, 8)
	hdr, _, err := quicParseLongHeader(pkt)
	if err != nil {
		t.Fatalf("Initial DCID len 8: expected accept, got %v", err)
	}
	if hdr.pktType != quicPktInitial {
		t.Fatalf("Initial DCID len 8: pktType = %d, want %d", hdr.pktType, quicPktInitial)
	}
	if len(hdr.dcid) != 8 {
		t.Fatalf("Initial DCID len 8: parsed dcid len = %d, want 8", len(hdr.dcid))
	}
}

func TestQUICNonInitialShortDCIDAccepted(t *testing.T) {
	// The < 8 restriction must NOT apply to non-Initial long-header packets.
	// A Handshake packet with a short DCID must still parse.
	pkt := buildLongHeaderPacket(quicHandshakeType, 4)
	hdr, _, err := quicParseLongHeader(pkt)
	if err != nil {
		t.Fatalf("Handshake DCID len 4: expected accept, got %v", err)
	}
	if hdr.pktType != quicPktHandshake {
		t.Fatalf("Handshake DCID len 4: pktType = %d, want %d", hdr.pktType, quicPktHandshake)
	}
	if len(hdr.dcid) != 4 {
		t.Fatalf("Handshake DCID len 4: parsed dcid len = %d, want 4", len(hdr.dcid))
	}
}
