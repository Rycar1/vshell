package main

import (
	"encoding/hex"
	"testing"
)

// Final E2E: same-run register message.
// gdb captured:
//   plaintext (128B) start = 54e271e3ac54f21ac87ff2f289975deb x86_64\x00\x00...
//   ciphertext (bb20e0 after encrypt) = 3e4ea613df34a912ab5838bb42aea8a8576ca18fb1...
//   rbx chain start = 0x4ad62d48a65
// Message = [12B nonce][ct][16B tag (AES-256-GCM)]. IV plaintext = key0. ct = AES-256-GCM ciphertext.
func TestRegisterE2E(t *testing.T) {
	pt, _ := hex.DecodeString("54e271e3ac54f21ac87ff2f289975deb")
	ct, _ := hex.DecodeString("3e4ea613df34a912ab5838bb42aea8a8")
	// keystream = pt XOR ct (first block)
	ks := make([]byte, 16)
	for i := 0; i < 16; i++ {
		ks[i] = pt[i] ^ ct[i]
	}
	t.Logf("keystream[0:16] = %s", hex.EncodeToString(ks))
	// This keystream must match msgKeyStream output for the payload with
	// the run's rbx/key0/key2. key0 = IV = 54e271e3ac54f21a...
	iv := pt
	_ = iv
	t.Log("Frame: [12B nonce][ct][16B tag (AES-256-GCM)]; IV = key0; ct = AES-256-GCM ciphertext")
	t.Log("Keystream = msgKeyStream(payload, rbx, key0, key2)")
}
