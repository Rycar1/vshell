package main

// messageWire implements the agent wire frame format recovered from the
// binary (sessions 532-537, gdb verified against same-run captures):
//
//	wire   = <u32 LE len><frame>            (4-byte little-endian length header)
//	frame  = [12B nonce][ct][16B tag]      (AES-256-GCM)
//	key    = "ceb20772e0c9d240c75eb26b0e37abee"  (32B constant, recovered
//	         from gdb breakpoint on the AES NewCipher call site 0x56f480)
//
// Verified frames (gdb same-run captures, decrypted with Go crypto/aes GCM):
//   - 37B version frame: nonce=74581e05c174c1c8c3a0, ct=9B, tag=16B
//     -> PT = "\x05\x00\x00\x004.9.3"
//   - 334B conf frame: nonce=070b5daf22e9c403e0c216f2, ct=306B, tag=16B
//     -> PT = "conf*\x01\x00\x00{\"Id\":0,\"IsConnect\":false,...}"
//
// This replaces the earlier (incorrect) 0x458f00 keystream model: 0x458f00
// is garble string/field-name decryption (rdx=0x8e2240 selects the string
// table), not message encryption.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

var (
	errShortFrame  = errors.New("frame too short")
	errLenMismatch = errors.New("wire length mismatch")
)

// msgFrameKey is the AES-256 key for message frames, recovered from the
// gdb breakpoint on 0x56f480 (AES NewCipher): 32 ASCII bytes.
var msgFrameKey = []byte("ceb20772e0c9d240c75eb26b0e37abee")

// newGCM returns the AES-256-GCM AEAD for message frames.
func newGCM() cipher.AEAD {
	block, err := aes.NewCipher(msgFrameKey)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm
}

// encryptFrame builds a wire message: <u32 LE len><AES-256-GCM frame>.
// Frame = [12B random nonce][ciphertext][16B tag]; ciphertext = payload.
func encryptFrame(payload []byte) []byte {
	gcm := newGCM()
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	sealed := gcm.Seal(nil, nonce, payload, nil)
	frame := append(nonce, sealed...)
	out := make([]byte, 4+len(frame))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(frame)))
	copy(out[4:], frame)
	return out
}

// decryptFrame opens an AES-256-GCM frame (without the 4-byte length header).
// Returns the plaintext payload.
func decryptFrame(frame []byte) ([]byte, error) {
	gcm := newGCM()
	if len(frame) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errShortFrame
	}
	nonce := frame[:gcm.NonceSize()]
	sealed := frame[gcm.NonceSize():]
	return gcm.Open(nil, nonce, sealed, nil)
}

// parseWire splits a full wire message into length and frame.
func parseWire(wire []byte) ([]byte, error) {
	if len(wire) < 4 {
		return nil, errShortFrame
	}
	n := binary.LittleEndian.Uint32(wire[:4])
	if int(n) != len(wire)-4 {
		return nil, errLenMismatch
	}
	return wire[4:], nil
}
