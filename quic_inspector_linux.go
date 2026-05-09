//go:build linux

package main

import (
	"context"
	"log"

	"github.com/florianl/go-nfqueue"
)

// startQUICInspector opens NFQUEUE queue 0 and issues per-packet verdicts.
// Packets that are valid QUIC are dropped; all others are accepted.
// This function blocks until the context is cancelled or a fatal error occurs.
func startQUICInspector() {
	cfg := nfqueue.Config{
		NfQueue:      0,
		MaxQueueLen:  100,
		MaxPacketLen: 0xFFFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		AfFamily:     0, // AF_UNSPEC – handles both IPv4 and IPv6
	}

	nf, err := nfqueue.Open(&cfg)
	if err != nil {
		log.Fatalf("Failed to open NFQUEUE: %v", err)
	}
	defer nf.Close()

	ctx := context.Background()

	hookFn := func(attr nfqueue.Attribute) int {
		id := *attr.PacketID

		if attr.Payload == nil || len(*attr.Payload) == 0 {
			// No payload – accept and move on
			nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

		payload := extractUDPPayload(*attr.Payload)
		if isQUICPacket(payload) {
			log.Printf("[QUIC] Dropping QUIC packet (first byte: 0x%02x)", payload[0])
			nf.SetVerdict(id, nfqueue.NfDrop)
		} else {
			nf.SetVerdict(id, nfqueue.NfAccept)
		}
		return 0
	}

	errFn := func(e error) int {
		log.Printf("NFQUEUE error: %v", e)
		return 0
	}

	if err := nf.RegisterWithErrorFunc(ctx, hookFn, errFn); err != nil {
		log.Fatalf("Failed to register NFQUEUE hook: %v", err)
	}

	// Block until the context is done (program shutdown via signal)
	<-ctx.Done()
}

// extractUDPPayload parses a raw IP packet (IPv4 or IPv6) and returns the
// bytes after the UDP header, i.e. the application-layer payload.
// Returns nil if the packet is too short or not UDP.
func extractUDPPayload(packet []byte) []byte {
	if len(packet) < 1 {
		return nil
	}

	version := packet[0] >> 4
	var udpOffset int

	switch version {
	case 4:
		if len(packet) < 20 {
			return nil
		}
		// IHL field (lower nibble of first byte) counts 32-bit words
		ihl := int(packet[0]&0x0f) * 4
		if len(packet) < ihl+8 {
			return nil
		}
		udpOffset = ihl
	case 6:
		// IPv6 has a fixed 40-byte header (next-header byte at offset 6)
		if len(packet) < 48 {
			return nil
		}
		udpOffset = 40
	default:
		return nil
	}

	// Skip the 8-byte UDP header (src port, dst port, length, checksum)
	payloadOffset := udpOffset + 8
	if len(packet) <= payloadOffset {
		return nil
	}
	return packet[payloadOffset:]
}

// isQUICPacket returns true if the UDP payload looks like a QUIC packet.
//
// Detection rules (RFC 9000 §17):
//   - The "fixed bit" (bit 6, mask 0x40) MUST be 1 in every valid QUIC header.
//   - Long-header packets (bit 7 = 1) additionally carry a 4-byte version field
//     in bytes 1–4; we verify it against known QUIC versions for extra precision.
//   - Short-header packets (bit 7 = 0) have no version field; the fixed bit
//     alone is considered sufficient.
func isQUICPacket(payload []byte) bool {
	if len(payload) < 1 {
		return false
	}

	// Fixed bit must be 1 for any valid QUIC packet
	if payload[0]&0x40 == 0 {
		return false
	}

	// Long-header packet: verify known QUIC version in bytes 1–4
	if payload[0]&0x80 != 0 {
		if len(payload) < 5 {
			return false
		}
		version := uint32(payload[1])<<24 | uint32(payload[2])<<16 |
			uint32(payload[3])<<8 | uint32(payload[4])
		switch version {
		case 0x00000000, // Version Negotiation (also QUIC)
			0x00000001, // QUIC v1 – RFC 9000
			0x6b3343cf, // QUIC v2 – RFC 9369
			0xff00001d, // draft-29
			0xff00001e, // draft-30
			0xff00001f, // draft-31
			0xff000020: // draft-32
			return true
		}
		return false
	}

	// Short-header (1-RTT): fixed bit alone is sufficient
	return true
}
