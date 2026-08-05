package main

import (
	"encoding/hex"
	"testing"
)

// Full message decryption: message frame = [12B nonce][ct][16B tag],
// AES-256-GCM (key = "ceb20772e0c9d240c75eb26b0e37abee").
// Same-run captured frame (session 365) decrypts to the version message.
func TestMsgDecryptRegister(t *testing.T) {
	// 37B version frame (breakthrough same-run capture):
	//   nonce = 74581e05c174c1c8c3a0 (12B)
	//   ct    = 184504e3d3060790f78f (9B)   -> "\x05\x00\x00\x004.9.3"
	//   tag   = f38255b11eb2faa81c2a7241e4b7f77288 (16B)
	frame, _ := hex.DecodeString("74581e05c174c1c8c3a0184504e3d3060790f78ff38255b11eb2faa81c2a7241e4b7f77288")
	if len(frame) != 37 {
		t.Fatalf("frame len %d, want 37", len(frame))
	}
	pt, err := decryptFrame(frame)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	t.Logf("PT = %q (version message)", pt)
	if string(pt) != "\x05\x00\x00\x004.9.3" {
		t.Fatalf("PT mismatch: %q", pt)
	}
}
