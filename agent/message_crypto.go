package main

// messageCrypto implements the VShell message-block cipher recovered from
// the agent binary 0x458f00 (verified byte-exact against gdb captures):
//
//	counter = [rbx u64 LE][len 0x0010 x4 broadcast]
//	state   = AESRound(counter XOR key)          // 1 self-keyed round
//	xmm1    = input XOR state
//	xmm1    = AESRound(xmm1, xmm1) x3            // self-keyed
//	out     = low 8 bytes of xmm1
//
// Message frame: [16B IV][21B ct]; keystream = CBC chain of block outputs.
// Self-keyed AESRound means the round key equals the current state, which is
// NOT standard AES key expansion — it is a custom construction.

// aesRound performs one AES round: SubBytes, ShiftRows, MixColumns, AddRoundKey.
// State is column-major (byte i = col i/4, row i%4), matching AES-NI.
var sbox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

func xtime(a byte) byte {
	if a&0x80 != 0 {
		return (a << 1) ^ 0x1b
	}
	return a << 1
}

func gmul(a, b byte) byte {
	var r byte
	for b != 0 {
		if b&1 != 0 {
			r ^= a
		}
		b >>= 1
		a = xtime(a)
	}
	return r
}

// aesRound: one AES round, self-keyed (round key = state) or with explicit rk.
func aesRound(state, rk [16]byte) [16]byte {
	var out [16]byte
	// SubBytes + ShiftRows (row r shifted LEFT by r; column-major)
	// byte at (col c, row r) comes from (col (c+r)%4, row r) after left-shift
	for c := 0; c < 4; c++ {
		for r := 0; r < 4; r++ {
			out[c*4+r] = sbox[state[((c+r)%4)*4+r]]
		}
	}
	// MixColumns
	for c := 0; c < 4; c++ {
		a0, a1, a2, a3 := out[c*4], out[c*4+1], out[c*4+2], out[c*4+3]
		out[c*4] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3
		out[c*4+1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3
		out[c*4+2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3)
		out[c*4+3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2)
	}
	// AddRoundKey
	for i := 0; i < 16; i++ {
		out[i] ^= rk[i]
	}
	return out
}

// msgBlockEncrypt implements 0x458f00 for len==16.
func msgBlockEncrypt(input []byte, rbx uint64, key []byte) [8]byte {
	// counter = [rbx LE][0x0010 x4]
	var ctr [16]byte
	for i := 0; i < 8; i++ {
		ctr[i] = byte(rbx >> (8 * i))
	}
	for i := 0; i < 4; i++ {
		ctr[8+2*i] = 0x10
		ctr[9+2*i] = 0x00
	}
	var k [16]byte
	copy(k[:], key)
	// state = aesenc(counter XOR key) — 1 self round
	var x0 [16]byte
	for i := 0; i < 16; i++ {
		x0[i] = ctr[i] ^ k[i]
	}
	state := aesRound(x0, x0)
	// xmm1 = input XOR state
	var x1 [16]byte
	copy(x1[:], input[:16])
	for i := 0; i < 16; i++ {
		x1[i] ^= state[i]
	}
	// 3x aesenc self-keyed
	x1 = aesRound(x1, x1)
	x1 = aesRound(x1, x1)
	x1 = aesRound(x1, x1)
	var out [8]byte
	copy(out[:], x1[:8])
	return out
}

// msgDualBlockEncrypt implements the 0x458fb7 dual-block path (0x10 < len <= 0x20):
//
//	state0 = aesenc(counter XOR key0)        (entry, key@0xbb20e0)
//	state2 = aesenc(counter XOR key2)        (this path, key2@0xbb20f0)
//	xmm2   = input[0:16]  XOR state0
//	xmm3   = input[len-16:len] XOR state2
//	both 3x aesenc self-keyed, then xmm2 ^= xmm3
//	out    = low 8 bytes
func msgDualBlockEncrypt(input []byte, rbx uint64, len_ uint16, key0, key2 []byte) [8]byte {
	// counter = [rbx LE][len x4]
	var ctr [16]byte
	for i := 0; i < 8; i++ {
		ctr[i] = byte(rbx >> (8 * i))
	}
	for i := 0; i < 4; i++ {
		ctr[8+2*i] = byte(len_ & 0xff)
		ctr[9+2*i] = byte((len_ >> 8) & 0xff)
	}
	var k0, k2 [16]byte
	copy(k0[:], key0)
	copy(k2[:], key2)
	// state0 = aesenc(counter XOR key0)
	var x0 [16]byte
	for i := 0; i < 16; i++ {
		x0[i] = ctr[i] ^ k0[i]
	}
	state0 := aesRound(x0, x0)
	// state2 = aesenc(counter XOR key2)
	var x1 [16]byte
	for i := 0; i < 16; i++ {
		x1[i] = ctr[i] ^ k2[i]
	}
	state2 := aesRound(x1, x1)
	// xmm2 = input[0:16] XOR state0
	var x2 [16]byte
	copy(x2[:], input[:16])
	for i := 0; i < 16; i++ {
		x2[i] ^= state0[i]
	}
	// xmm3 = input[len-16:len] XOR state2
	var x3 [16]byte
	copy(x3[:], input[len_-16:len_])
	for i := 0; i < 16; i++ {
		x3[i] ^= state2[i]
	}
	x2 = aesRound(x2, x2)
	x2 = aesRound(x2, x2)
	x2 = aesRound(x2, x2)
	x3 = aesRound(x3, x3)
	x3 = aesRound(x3, x3)
	x3 = aesRound(x3, x3)
	for i := 0; i < 16; i++ {
		x2[i] ^= x3[i]
	}
	var out [8]byte
	copy(out[:], x2[:8])
	return out
}
