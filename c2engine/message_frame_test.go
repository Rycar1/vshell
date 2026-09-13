package c2engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestFrameSaltKeyDerivation pins the message-frame key derivation recovered
// from the binary.
//
// 证据分级：
//   - 硬证据：gdb 断点抓到 AES 密钥寄存器 RDX = 32 字节 ASCII 缓冲
//     "ceb20772e0c9d240c75eb26b0e37abee"（多次运行一致）。
//   - 该文本在原二进制 v_windows_amd64.exe 中不存在（raw/掩码搜索均为空）
//     → 运行期派生量，不是编译常量。
//   - hex(md5("salt")) = ceb20772e0c9d240c75eb26b0e37abee；"salt" 是长度 ≤ 4
//     的全部 95 个可打印 ASCII 字符组合中唯一具有该摘要的原像，对应监听器
//     字段「流量加密盐」listeners.EncryptSalt。
//   - gdb 日志中的 0x56f480 未能在 Ghidra 中确认为 crypto/aes.NewCipher
//     调用点（该处无函数、无 xref），静态侧未定位。
//   - 该 32 字符十六进制文本按原样作为密钥字节（→ AES-256）；16 字节原始摘要
//     与零填充摘要都过不了 tag 校验（见 agent 侧
//     TestMsgKeyBothInterpretationsInScope）。
func TestFrameSaltKeyDerivation(t *testing.T) {
	const want = "ceb20772e0c9d240c75eb26b0e37abee"

	sum := md5.Sum([]byte("salt"))
	if hex.EncodeToString(sum[:]) != want {
		t.Fatalf("md5(\"salt\") = %s, want %s", hex.EncodeToString(sum[:]), want)
	}

	key := FrameSaltKey("salt")
	if string(key) != want {
		t.Fatalf("FrameSaltKey(\"salt\") = %q, want %q", key, want)
	}
	if len(key) != 32 {
		t.Fatalf("FrameSaltKey len = %d, want 32 (AES-256)", len(key))
	}

	// The hex TEXT is the key; the 16 raw digest bytes are legal AES-128 key
	// material but do not authenticate the captured frame (agent-side test
	// TestMsgKeyBothInterpretationsInScope proves the negative).
	if hex.EncodeToString(key) == want {
		t.Fatal("key is raw md5 bytes; must be the hex text of the digest")
	}
	if _, err := aes.NewCipher(sum[:]); err != nil {
		t.Fatalf("raw digest should still be legal AES-128 key material: %v", err)
	}
	if _, err := aes.NewCipher(key); err != nil {
		t.Fatalf("hex-text key must be legal AES-256 material: %v", err)
	}

	// Distinct salts must not collide.
	if string(FrameSaltKey("other")) == want {
		t.Fatal("FrameSaltKey collided for an unrelated salt")
	}
}

// TestFrameCapturedShape pins the AEAD shape the tag match proves:
// cipher.NewGCM defaults — 12-byte nonce, 16-byte tag, no AAD — with the
// nonce prepended on the wire and the plaintext NOT included in the sealed
// buffer. Exactly one (nonce size, offset) configuration authenticates the
// captured frame.
func TestFrameCapturedShape(t *testing.T) {
	frame, _ := hex.DecodeString(
		"74581e05c174c1c8c3a0184504e3d3060790f78ff38255b11eb2faa81c2a7241e4b7f77288")
	const want = "\x05\x00\x00\x004.9.3"

	block, err := aes.NewCipher(FrameSaltKey("salt"))
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	type shape struct{ nonceSize, offset int }
	var hits []shape
	for _, nonceSize := range []int{8, 10, 12, 14, 16, 18, 20} {
		for offset := 0; offset <= 4; offset++ {
			if offset+nonceSize >= len(frame) {
				continue
			}
			var gcm cipher.AEAD
			if nonceSize == 12 {
				gcm, err = cipher.NewGCM(block)
			} else {
				gcm, err = cipher.NewGCMWithNonceSize(block, nonceSize)
			}
			if err != nil {
				continue
			}
			pt, oerr := gcm.Open(nil, frame[offset:offset+nonceSize], frame[offset+nonceSize:], nil)
			if oerr != nil {
				continue
			}
			if string(pt) != want {
				t.Fatalf("nonceSize=%d offset=%d opened to %q, want %q", nonceSize, offset, pt, want)
			}
			hits = append(hits, shape{nonceSize, offset})
		}
	}
	if len(hits) != 1 {
		t.Fatalf("authenticating shapes = %v, want exactly one", hits)
	}
	if hits[0] != (shape{12, 0}) {
		t.Fatalf("authenticating shape = nonce %d offset %d, want nonce 12 offset 0",
			hits[0].nonceSize, hits[0].offset)
	}
	// The default constructor agrees (12-byte nonce, 16-byte tag), and a
	// 16-byte nonce constructor is excluded by the byte count alone: 37-16
	// leaves 21 bytes, which cannot hold a 16-byte tag plus ciphertext.
	if g, err := newFrameGCM("salt"); err != nil {
		t.Fatalf("newFrameGCM: %v", err)
	} else if g.NonceSize() != 12 || g.Overhead() != 16 {
		t.Fatalf("newFrameGCM = nonce %d tag %d, want 12/16", g.NonceSize(), g.Overhead())
	}
}

// TestFrameDecryptCapturedVersionFrame opens the gdb-captured 37B version
// frame (session 537) with the salt-derived key.
func TestFrameDecryptCapturedVersionFrame(t *testing.T) {
	frame, _ := hex.DecodeString(
		"74581e05c174c1c8c3a0184504e3d3060790f78ff38255b11eb2faa81c2a7241e4b7f77288")
	if len(frame) != 37 {
		t.Fatalf("captured frame len %d, want 37 (12 nonce + 9 ct + 16 tag)", len(frame))
	}

	// Frame body form.
	pt, err := Unframe(frame, "salt")
	if err != nil {
		t.Fatalf("Unframe: %v", err)
	}
	if string(pt) != "\x05\x00\x00\x004.9.3" {
		t.Fatalf("version PT = %q", pt)
	}

	// Full wire form (4-byte LE length header).
	wire := make([]byte, 4+len(frame))
	binary.LittleEndian.PutUint32(wire[:4], uint32(len(frame)))
	copy(wire[4:], frame)
	pt2, err := FrameDecrypt(wire, "salt")
	if err != nil {
		t.Fatalf("FrameDecrypt: %v", err)
	}
	if string(pt2) != string(pt) {
		t.Fatalf("wire/frame forms disagree: %q vs %q", pt2, pt)
	}

	// A wrong salt must fail authentication.
	if _, err := FrameDecrypt(wire, "wrong-salt"); err == nil {
		t.Fatal("FrameDecrypt accepted a frame under the wrong salt")
	}
}

// TestFrameRoundTrip verifies the frame format end to end:
// wire = <u32 LE len><[12B nonce][ct][16B tag]>, AES-256-GCM.
func TestFrameRoundTrip(t *testing.T) {
	payload := []byte(`{"VerifyKey":"0ldZAz4ckNLrxULk","Tp":"tcp","Addr":"127.0.0.1:443"}`)

	wire, err := FrameEncrypt(payload, "salt")
	if err != nil {
		t.Fatalf("FrameEncrypt: %v", err)
	}
	if len(wire) != 4+12+len(payload)+16 {
		t.Fatalf("wire len %d, want %d", len(wire), 4+12+len(payload)+16)
	}
	if got := int(binary.LittleEndian.Uint32(wire[:4])); got != len(wire)-4 {
		t.Fatalf("length header %d, body %d", got, len(wire)-4)
	}

	pt, err := FrameDecrypt(wire, "salt")
	if err != nil {
		t.Fatalf("FrameDecrypt: %v", err)
	}
	if string(pt) != string(payload) {
		t.Fatalf("round trip mismatch: %q", pt)
	}

	// Nonce is per-message: two encryptions of the same payload differ.
	wire2, _ := FrameEncrypt(payload, "salt")
	if hex.EncodeToString(wire[4:16]) == hex.EncodeToString(wire2[4:16]) {
		t.Fatal("nonce reused across frames")
	}

	// A corrupted length header is rejected before decryption.
	bad := make([]byte, len(wire))
	copy(bad, wire)
	binary.LittleEndian.PutUint32(bad[:4], uint32(len(wire)))
	if _, err := FrameDecrypt(bad, "salt"); err == nil {
		t.Fatal("FrameDecrypt accepted a mismatched length header")
	}

	// A truncated frame is rejected.
	if _, err := Unframe(wire[4:len(wire)-1], "salt"); err == nil {
		t.Fatal("Unframe accepted a truncated frame")
	}
}
