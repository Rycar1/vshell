package main

// messageWire implements the agent message frame recovered from the binary.
//
//	wire   = <u32 LE len><frame>            (4-byte little-endian length header)
//	frame  = [12B nonce][ct][16B tag]       (AES-256-GCM)
//
// PROVENANCE — what is hard evidence and what is not.
//
// HARD: a gdb breakpoint (session 537) captured the AES key register RDX as a
// 32-byte ASCII buffer "ceb20772e0c9d240c75eb26b0e37abee", stable across runs.
//
// NOT READ FROM THE BINARY — 0x56f480: this address comes from a gdb log whose
// Ghidra correspondence was never established, and it could NOT be confirmed
// as a call site of anything in Ghidra. There is no function at 0x0056f480, no
// xref to it, and the bytes there (0x56f440-0x56f49f) are a table-compare loop
// (`CMP RBX,R8 / JNC`, table 0x019e8700), not a call. Note also that during
// most of this session Ghidra had EXITED (MCP calls were failing with
// connection/WinError 10061, not timing out), so the function/xref absences
// for this address were partly observed against a dead server and were not
// re-confirmed afterwards. Treat 0x56f480 as unresolved: it may not be the
// real key-setup site at all. The static side is open work.
//
// NOT READ FROM THE BINARY — the GCM construction site: garble strips Go
// SYMBOL names but keeps package paths, type metadata and renderer-visible
// method names, so crypto/aes, crypto/cipher and "NewGCM" are all present as
// strings (roughly 176 / 264 / 129 occurrences). What is missing is the link
// from a name to code: compiler-generated method names are rendered as
// "pkg.(*type).Method", e.g. the cipher GCM type appears as
// Ip3jZB1cm.(*bq0m8kYa).NewGCM / .NonceSize / .Overhead / .Seal / .Open in a
// name blob at file 0x6c04e5c (VA 0x06c0585c). That blob is funcnametab data:
// Ghidra reports the whole table as one string with NO xrefs, and
// search_functions finds no function for "NewGCM" or "Ip3jZB1cm". The
// name→PC link lives in pclntab, which Ghidra does not parse. So the
// construction site is not reachable through names; the AEAD parameters below
// are established by EXHAUSTIVE SEARCH AGAINST THE CAPTURED FRAME. Do not
// write "the decompiled code shows cipher.NewGCM" anywhere: it does not and
// cannot. Anyone changing these parameters must re-verify against a capture.
// (An earlier revision of this comment claimed there was no crypto/aes
// metadata at all; that was wrong and is corrected here.)
//
// KEY RECOVERY (session 537 + this session): that 32-char buffer is NOT a
// compiled constant — the ASCII bytes never appear in v_windows_amd64.exe
// (raw or masked), and agent/agent.exe only contains it because that build
// was made after the constant had already been guessed into the source. The
// value is md5("salt"):
//
//	crypto/md5    md5("salt") = ceb20772e0c9d240c75eb26b0e37abee  (16B)
//	encoding/hex  hex.EncodeToString(...) = the 32 lowercase hex chars
//
// md5 and encoding/hex are both linked into the binary: encoding/hex by its
// "encoding/hex: odd length hex string" message and "0123456789abcdef" table;
// crypto/md5 by its IV in rodata — at 0x0a62e380 the bytes are
// 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10, i.e. A/B/C/D =
// 0x67452301 / 0xefcdab89 / 0x98badcfe / 0x10325476 stored little-endian.
// "salt" is the unique printable string up to 4 bytes with this digest (all
// 95^1+95^2+95^3+95^4 candidates searched), so the preimage is not ambiguous.
// The digest is then hex-encoded to 32 lowercase chars and THAT ASCII TEXT is
// the key material verbatim (32 bytes → AES-256) — not the 16 raw digest
// bytes. Confirmed by Open() on the captured frame: only the 32-byte form
// verifies the tag (TestMsgKeyBothInterpretationsInScope; AES-128 with the raw
// digest, and zero-padded digest, both fail).
//
// AEAD SHAPE — ESTABLISHED BY EXHAUSTIVE SEARCH AGAINST THE CAPTURED FRAME,
// NOT READ FROM THE BINARY (see the provenance note above; the construction
// site is unreachable statically). A successful tag check is the whole
// evidence, and it is strong precisely because the alternatives were actually
// tested rather than dismissed: of every candidate — nonce size 8–20, nonce
// offset 0–4, AAD ∈ {none, nonce}, tag size 8–20 (via NewGCMWithNonceSize and
// NewGCMWithTagSize) — EXACTLY ONE authenticates the 37-byte capture:
// nonce 12 at offset 0, AAD absent, tag 16. That is cipher.NewGCM's default
// shape, with the nonce prepended and the plaintext not included in the
// sealed buffer. NewGCMWithNonceSize(…,16) is additionally excluded by byte
// count alone (37−16 = 21 bytes cannot hold ct + a 16-byte tag). See
// TestGCMFrameShape, which fails if the assumption ever changes.
//
// Caveat to keep in mind: this fixes the parameters FOR THIS FRAME. If any
// original call site passed non-nil AAD, the capture alone cannot reveal it
// (a no-AAD frame still opens only under no-AAD parameters, so the two ends
// agree here) — but a future frame sealed with AAD would not open. The
// server side (c2engine FrameEncrypt/FrameDecrypt) uses the same no-AAD
// defaults; if a divergence ever appears, re-derive from a capture with AAD
// rather than guessing.
//
// 反编译排除项（0x016f1b20，与同批 8 个函数共用的一字节常量表 0x019e7b40）：
// 该函数在运行时把两个 16B 常量块逐字节相加（`for i < 0x1e: buf[i]=a[i]+b[i]`），
//   0x712df8289676aa14 0xc3abf46688ea980b 0xb2937bb6b4b2c3ab 0xbe888dbee8fdb54d
//   + 0xf31c7c46cff3c24f 0xb0c478fd987a8d15 0xb2d1e66a78b3b0c4 0xb59d937c8b76b025
// 得到 30 字节 ASCII "clientId %d close...address: "（已按小端字节序复算），
// 再经 FUN_0044ac40(0, buf, 0x1e) 与 FUN_00a28780(DAT_019e8540, ..., 2, 2) →
// 0x00a286e0 使用。那 30 字节是明文串，不是本文件的 32 字节十六进制密钥文本，
// 因此 0x016f1b20 与本消息帧密钥无关（它是另一条链路的常量使用点）。
//
// Wire shape (gdb same-run captures):
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
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

var (
	errShortFrame  = errors.New("frame too short")
	errLenMismatch = errors.New("wire length mismatch")
)

// msgFrameSalt is the per-deployment encryption salt (agent main.EncryptSalt,
// injected via ldflags; the server stores the same value per listener as
// EncryptSalt and the panel labels it "流量加密盐"). The recovered deployment's
// value was the literal "salt".
var msgFrameSalt = "salt"

// deriveFrameKey returns the message-frame AES key for a salt: the lowercase
// hex text of md5(salt), used verbatim as key bytes (32 ASCII chars → AES-256).
//
// 派生证据（见文件头 provenance 说明）：md5("salt") =
// ceb20772e0c9d240c75eb26b0e37abee，其 32 字符十六进制文本按原样即密钥字节
// （→ AES-256）。该文本对应 gdb 捕获的 RDX 密钥缓冲；文本本身不出现在
// v_windows_amd64.exe 中（raw/掩码都无），所以它是运行期由盐派生出来的，
// 不是编译常量。注意 0x56f480 在 Ghidra 中并非 NewCipher 调用点（无函数、无
// xref），静态侧未定位——只有 gdb 抓到的 RDX 值是硬证据。
func deriveFrameKey(salt string) []byte {
	sum := md5.Sum([]byte(salt))
	out := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(out, sum[:])
	return out
}

// msgFrameKey is the AES-256 key for the recovered deployment's message
// frames: the 32 ASCII hex chars of md5("salt").
var msgFrameKey = deriveFrameKey(msgFrameSalt)

// msgFrameKeyText is the same key as a string (the spelling the gdb capture
// saw in RDX at the key-setup site).
func msgFrameKeyText() string { return string(msgFrameKey) }

// newGCM returns the AES-GCM AEAD for message frames.
func newGCM() cipher.AEAD {
	gcm, err := gcmFor(msgFrameKey)
	if err != nil {
		panic(err)
	}
	return gcm
}

// gcmFor builds an AES-GCM AEAD from an explicit key (used by capture tests
// that compare key interpretations).
func gcmFor(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// encryptFrame builds a wire message: <u32 LE len><AES-GCM frame>.
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

// decryptFrame opens an AES-GCM frame (without the 4-byte length header).
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
