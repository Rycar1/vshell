package main

import "testing"

// The earlier "[16B IV][21B ct]" keystream model is disproven (see
// message_wire.go): frames are AES-GCM, [12B nonce][ct][16B tag], with no
// 21-byte block chunking. This test pins that structural fact: any payload
// length produces a frame of exactly nonce+len(payload)+tag, and a
// 21-byte-multiple payload is not split into 21-byte blocks.
func TestFrameNotChunkedInto21ByteBlocks(t *testing.T) {
	gcm := newGCM()
	overhead := gcm.NonceSize() + gcm.Overhead()
	for _, n := range []int{0, 1, 9, 21, 42, 306} {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(i)
		}
		wire := encryptFrame(payload)
		if len(wire) != 4+overhead+n {
			t.Fatalf("payload %d: wire len %d, want %d (4 hdr + %d frame)",
				n, len(wire), 4+overhead+n, overhead+n)
		}
		pt, err := decryptFrame(wire[4:])
		if err != nil {
			t.Fatalf("payload %d: decrypt: %v", n, err)
		}
		if len(pt) != n {
			t.Fatalf("payload %d: PT len %d", n, len(pt))
		}
	}
}

// The conf frame's plaintext header is "conf\x2a\x01\x00\x00" followed by the
// register JSON (gdb same-run capture, session 537). The captured frame body
// was 334 bytes with a 306-byte plaintext, i.e. 12 + 306 + 16 — the exact
// AES-GCM shape.
func TestConfFrameShape(t *testing.T) {
	pt := append([]byte("conf\x2a\x01\x00\x00"), []byte(`{"Id":0,"IsConnect":false,"VerifyKey":""}`)...)
	wire := encryptFrame(pt)
	if len(wire[4:]) != 12+len(pt)+16 {
		t.Fatalf("conf frame len %d, want %d", len(wire[4:]), 12+len(pt)+16)
	}
	got, err := decryptFrame(wire[4:])
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(pt) {
		t.Fatalf("conf PT mismatch: %q", got)
	}
}

// The "register" message body is plain JSON framed as AES-GCM; the same-run
// capture showed it beginning {"VerifyKey":"0l... — the earlier 21-byte
// keystream cipher model is disproven (see message_wire.go).
func TestRegisterMsgShape(t *testing.T) {
	const prefix = `{"VerifyKey":"0l`
	body := []byte(`{"VerifyKey":"0ldZAz4ckNLrxULk","Tp":"tcp","Addr":"127.0.0.1:443"}`)
	if string(body[:len(prefix)]) != prefix {
		t.Fatalf("register prefix mismatch: %q", body[:len(prefix)])
	}
	wire := encryptFrame(body)
	pt, err := decryptFrame(wire[4:])
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != string(body) {
		t.Fatalf("register round trip mismatch: %q", pt)
	}
}
