package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"testing"
)

// TestMsgKeyDerivation ties the message-frame key to md5 and pins the exact
// constant recovered from the binary.
//
// Evidence (see message_wire.go header for the full provenance split):
//   - HARD: a gdb breakpoint captured the key register RDX as a 32-byte ASCII
//     buffer "ceb20772e0c9d240c75eb26b0e37abee" (stable across runs).
//   - That ASCII text appears nowhere in v_windows_amd64.exe (raw or masked),
//     so it is a runtime-derived value, not a compiled constant.
//   - hex(md5("salt")) = ceb20772e0c9d240c75eb26b0e37abee, and "salt" is the
//     only printable string of length <= 4 with that digest (exhaustive
//     search over all 95 printable ASCII chars), matching the listener field
//     the panel labels "流量加密盐" (encrypt salt).
//   - The address 0x56f480 from the gdb log could NOT be confirmed as a
//     crypto/aes.NewCipher call site in Ghidra; the static side is unlocated.
//   - 32 ASCII key bytes as key material -> AES-256 (tag verifies; AES-128
//     with the 16 raw digest bytes fails authentication).
func TestMsgKeyDerivation(t *testing.T) {
	const want = "ceb20772e0c9d240c75eb26b0e37abee"

	sum := md5.Sum([]byte("salt"))
	wantHex := hex.EncodeToString(sum[:])
	if wantHex != want {
		t.Fatalf("md5(\"salt\") hex = %s, want %s", wantHex, want)
	}

	k := deriveFrameKey("salt")
	if string(k) != want {
		t.Fatalf("deriveFrameKey(\"salt\") = %q, want %q", k, want)
	}
	if len(k) != 32 {
		t.Fatalf("frame key len = %d, want 32 (AES-256)", len(k))
	}
	// The key buffer is the hex TEXT, not the 16 raw digest bytes.
	if hex.EncodeToString(k) == want {
		t.Fatal("key is raw md5 bytes; must be the hex text of the digest")
	}
	// Package var is wired to the recovered deployment salt.
	if string(msgFrameKey) != want || msgFrameKeyText() != want {
		t.Fatalf("msgFrameKey = %q", msgFrameKey)
	}
	// A different salt must not collide onto the recovered key.
	if string(deriveFrameKey("default")) == want {
		t.Fatal("deriveFrameKey collided for an unrelated salt")
	}
}

// TestMsgKeyBothInterpretationsInScope closes the two readings that a
// 32-char hex string invites: the raw 16-byte digest (legal AES-128 material)
// and a zero-padded digest (legal AES-256 material). Neither authenticates
// the captured frame; the hex TEXT does.
func TestMsgKeyBothInterpretationsInScope(t *testing.T) {
	frame, _ := hex.DecodeString(
		"74581e05c174c1c8c3a0184504e3d3060790f78ff38255b11eb2faa81c2a7241e4b7f77288")

	pt, err := decryptFrameWith(deriveFrameKey("salt"), frame)
	if err != nil {
		t.Fatalf("hex-text key (AES-256): %v", err)
	}
	if string(pt) != "\x05\x00\x00\x004.9.3" {
		t.Fatalf("hex-text key PT = %q", pt)
	}

	// Raw 16 digest bytes: legal AES-128 key, but wrong for this frame.
	raw := md5.Sum([]byte("salt"))
	if _, err := decryptFrameWith(raw[:], frame); err == nil {
		t.Fatal("raw md5 digest must NOT authenticate the captured frame")
	}

	// Zero-padded digest: the other natural AES-256 reading, also wrong.
	padded := make([]byte, 32)
	copy(padded, raw[:])
	if _, err := decryptFrameWith(padded, frame); err == nil {
		t.Fatal("zero-padded md5 digest must NOT authenticate the captured frame")
	}
}

// TestGCMFrameShape pins the AEAD shape the tag match proves: cipher.NewGCM
// defaults, no AAD, nonce prepended to the wire (Seal(nil, nonce, …)), with
// the plaintext NOT included in the sealed buffer (frames carry ciphertext
// only — the "gcm.Seal(nonce, nonce, pt, nil)" in-place idiom would leave the
// plaintext in the frame).
//
// The assertion is a full split search: exactly one (nonce offset, nonce size,
// AAD) configuration authenticates the captured frame, and it is 12-byte
// nonce at offset 0 with no AAD. A 16-byte nonce (NewGCMWithNonceSize) can
// only be tried as Open(nonce=frame[:16], ct=frame[16:]) = 21 bytes, which
// cannot contain a 16-byte tag, so that constructor is excluded by the byte
// count alone.
func TestGCMFrameShape(t *testing.T) {
	frame, _ := hex.DecodeString(
		"74581e05c174c1c8c3a0184504e3d3060790f78ff38255b11eb2faa81c2a7241e4b7f77288")
	const want = "\x05\x00\x00\x004.9.3"

	var hits [][3]int // {nonceSize, offset, aadIsNonce}
	for _, nonceSize := range []int{8, 10, 12, 14, 16, 18, 20} {
		for offset := 0; offset <= 4; offset++ {
			if offset+nonceSize >= len(frame) {
				continue
			}
			nonce := frame[offset : offset+nonceSize]
			sealed := frame[offset+nonceSize:]
			for _, aad := range [][]byte{nil, nonce} {
				gcm := newGCMWithNonceSize(t, nonceSize)
				pt, err := gcm.Open(nil, nonce, sealed, aad)
				if err != nil {
					continue
				}
				if string(pt) != want {
					t.Fatalf("nonceSize=%d offset=%d: opened to %q, want %q",
						nonceSize, offset, pt, want)
				}
				aadFlag := 0
				if aad != nil {
					aadFlag = 1
				}
				hits = append(hits, [3]int{nonceSize, offset, aadFlag})
			}
		}
	}
	if len(hits) != 1 {
		t.Fatalf("authenticating shapes = %v, want exactly one", hits)
	}
	if hits[0] != [3]int{12, 0, 0} {
		t.Fatalf("authenticating shape = nonceSize %d offset %d aadNonce %d, want 12/0/0",
			hits[0][0], hits[0][1], hits[0][2])
	}
	// Default constructor agrees with the recovered shape.
	if newGCM().NonceSize() != 12 || newGCM().Overhead() != 16 {
		t.Fatalf("newGCM = nonce %d tag %d, want 12/16",
			newGCM().NonceSize(), newGCM().Overhead())
	}
}

// newGCMWithNonceSize builds an explicit-nonce-size AEAD for the shape search.
func newGCMWithNonceSize(t *testing.T, n int) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(msgFrameKey)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	if n == 12 {
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("cipher.NewGCM: %v", err)
		}
		return gcm
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, n)
	if err != nil {
		t.Fatalf("NewGCMWithNonceSize(%d): %v", n, err)
	}
	return gcm
}

// decryptFrameWith opens a frame with an explicit key (newGCM is bound to
// msgFrameKey; this mirrors it for key-comparison tests).
func decryptFrameWith(key, frame []byte) ([]byte, error) {
	gcm, err := gcmFor(key)
	if err != nil {
		return nil, err
	}
	if len(frame) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errShortFrame
	}
	return gcm.Open(nil, frame[:gcm.NonceSize()], frame[gcm.NonceSize():], nil)
}
