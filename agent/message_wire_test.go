package main

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Wire frame structure: <u32 LE len><AES-256-GCM frame>.
// Frame = [12B nonce][ct][16B tag]; key = "ceb20772e0c9d240c75eb26b0e37abee".
// Verified against same-run gdb captures (37B version frame + 334B conf frame).
func TestWireFrameGCM(t *testing.T) {
	payload := make([]byte, 21)
	for i := range payload {
		payload[i] = byte('A' + i%26)
	}
	msg := encryptFrame(payload)
	// 21B payload -> frame = 12 nonce + 21 ct + 16 tag = 49B; wire = 4+49
	if len(msg) != 4+49 {
		t.Fatalf("wire len = %d, want 4+49=53 (4 hdr + 49 GCM frame)", len(msg))
	}
	hdr := binary.LittleEndian.Uint32(msg[:4])
	if int(hdr) != 49 {
		t.Fatalf("hdr len = %d, want 49", hdr)
	}
	// nonce is random, must differ between messages
	msg2 := encryptFrame(payload)
	if hex.EncodeToString(msg[4:16]) == hex.EncodeToString(msg2[4:16]) {
		t.Fatal("nonce reused across messages")
	}
	// round-trip decrypt
	pt, err := decryptFrame(msg[4:])
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != string(payload) {
		t.Fatalf("round-trip mismatch: %q", pt)
	}
}

// Verify the recovered AES-256-GCM key against the gdb-captured frames.
func TestGCMCapturedFrames(t *testing.T) {
	// 37B version frame (breakthrough): PT = "\x05\x00\x00\x004.9.3"
	versionFrame, _ := hex.DecodeString("74581e05c174c1c8c3a0184504e3d3060790f78ff38255b11eb2faa81c2a7241e4b7f77288")
	pt, err := decryptFrame(versionFrame)
	if err != nil {
		t.Fatalf("version frame: %v", err)
	}
	t.Logf("version PT = %q", pt)
	if string(pt) != "\x05\x00\x00\x004.9.3" {
		t.Fatalf("version PT mismatch: %q", pt)
	}
}
