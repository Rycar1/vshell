package main

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Wire frame structure: <u32 LE len><16B IV><ct>, ct = payload XOR keystream.
// Lengths on the wire were observed as 37B (=16 IV + 21 ct), 60B, 32B, 334B.
func TestWireFrame37(t *testing.T) {
	sk := &sessionKeys{
		rbx:  0x5fe6b8f3,
		key0: mustHex16("dad420eef21af100ca3f6cd876de42ad"),
		key2: mustHex16("8a2b884182271a05cfb61bbc2f714f37"),
	}
	counter := &messageCounter{base: 0x5fe6b8f3}
	payload := make([]byte, 21)
	for i := range payload {
		payload[i] = byte('A' + i%26)
	}
	msg := encryptFrame(sk, counter, payload)
	if len(msg) != 4+16+21 {
		t.Fatalf("wire len = %d, want 4+16+21=41 (4 hdr + 37 frame)", len(msg))
	}
	hdr := binary.LittleEndian.Uint32(msg[:4])
	if int(hdr) != 37 {
		t.Fatalf("hdr len = %d, want 37", hdr)
	}
	// IV is random, must differ between messages
	msg2 := encryptFrame(sk, counter, payload)
	if hex.EncodeToString(msg[4:20]) == hex.EncodeToString(msg2[4:20]) {
		t.Fatal("IV reused across messages")
	}
	t.Logf("wire[0:4] hdr=%d, frame=%d bytes ([16 IV][21 ct])", hdr, len(msg)-4)
}

func mustHex16(s string) [16]byte {
	var b [16]byte
	d, err := hex.DecodeString(s)
	if err != nil || len(d) != 16 {
		panic("bad hex16: " + s)
	}
	copy(b[:], d)
	return b
}
