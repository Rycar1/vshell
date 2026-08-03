package main

// messageWire implements the agent wire frame format recovered from the
// binary (sessions 532-533, gdb/bpftrace verified):
//
//	wire   = <u32 LE len><frame>            (4-byte little-endian length header)
//	frame  = [16B IV][ct]                   (no footer)
//	ct     = payload XOR keystream           (keystream = msgKeyStream)
//	IV     = independent random per message  (NOT the session key)
//
// Message sizes observed on the wire: 37B (=16 IV + 21 ct), 60B, 32B, 334B.
// The block cipher is the 0x458f00 chain (msgBlockEncrypt for 16B blocks,
// msgDualBlockEncrypt for the 0x10<len<=0x20 window), implemented in
// message_crypto.go and verified byte-exact against gdb XMM captures.

import (
	"crypto/rand"
	"encoding/binary"
)

// sessionKeys holds the per-session key material used by the message cipher.
// In the original binary these live at 0xbb20e0 (key0) / 0xbb20f0 (key2) and
// are populated at session setup; rbx is the per-message counter.
type sessionKeys struct {
	rbx  uint64
	key0 [16]byte
	key2 [16]byte
}

// messageCounter is the per-session message counter. Each outgoing message
// uses rbx = base + seq, mirroring the incrementing rbx observed in the
// 0x43f780-family encrypt loop.
type messageCounter struct {
	base uint64
	seq  uint64
}

// next advances the per-message counter and returns the rbx for the next
// message encryption.
func (c *messageCounter) next() uint64 {
	r := c.base + c.seq
	c.seq++
	return r
}

// newIV generates a 16-byte random IV (independent per message).
func newIV() [16]byte {
	var iv [16]byte
	rand.Read(iv[:])
	return iv
}

// encryptFrame builds a wire message: <u32 LE len><[16B IV][ct]>.
// ct = payload XOR keystream, keystream = msgKeyStream(payload, rbx, key0, key2).
// NOTE: the decrypt direction is NOT yet reversed (keystream depends on the
// plaintext input as recovered from the binary's CBC chain); see README.
func encryptFrame(sk *sessionKeys, counter *messageCounter, payload []byte) []byte {
	rbx := counter.next()
	ks := msgKeyStream(payload, rbx, sk.key0[:], sk.key2[:])
	iv := newIV()
	frame := make([]byte, 16+len(payload))
	copy(frame[:16], iv[:])
	for i := 0; i < len(payload); i++ {
		frame[16+i] = payload[i] ^ ks[i]
	}
	out := make([]byte, 4+len(frame))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(frame)))
	copy(out[4:], frame)
	return out
}
