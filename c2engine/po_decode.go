package c2engine

// ============================================================================
// po 字符串置换链（garble 的每包 decFunc，家族 A）
// The po string-permutation chain (garble's per-package decFunc, family A)
// ============================================================================
//
// 反编译证据（v_windows_amd64.exe）：
//
//	FUN_01912ac0（0x1912ac0）与 FUN_01912bc0（0x1912bc0）形态相同：
//
//	  数据区（密文）：[RSP+0x2c] 起 20 字节（3 个 MOV imm64，彼此重叠 4 字节）
//	  索引表：        [RSP+0x18] 起 20 字节（同样 3 个 MOV imm64，重叠 4 字节）
//	  循环：RAX 从 0 每次 +2，条件 RAX < 0x14（FUN_01912bc0 为 0x14，收尾取 0x11）
//	      RDX = key[RAX] ; RSI = key[RAX+1]
//	      k   = (RAX + (key[RAX] ^ key[RAX+1]) + C) & 0xff      ; C 由函数给出
//	      R8D = data[RDX] OP k                                   ; OP 见下
//	      data[RDX] = R8B
//	      data[RSI] = 原值 ^ k（XOR 型）/ 原值 + k（ADD 型）
//
//	收尾 FUN_0044ac40(0, data, N) 产出 N 字节 Go 字符串。
//
// 两个函数的差别只在**步运算**与加法常数：
//
//	FUN_01912ac0  异或型，add = +0x1e   → "stageless/ebpf_%s_%s"
//	FUN_01912bc0  加法型，add = -0x40   → "windows_amd64.exe"
//
// 两条都已逐字节验证（PoVectors + po_decode_test.go），无需任何未知字节。
//
// 关于"步运算"的诚实说明：x86 反汇编里两步写回都用同一个寄存器（R8/R9），
// 因此"两次都 XOR k" 与"一次 XOR k、一次 + 原值"在反编译文本上不可区分。
// 这里用两条向量的明文把两种运算类各自解出：穷举 op∈{xor,add} × add∈[0,256)，
// 每条向量都**恰好只有一个**解，并且与反汇编里的常数一致
// （FUN_01912ac0 的 MOV EDI,0x1e 与 FUN_01912bc0 的 LEA EDX,[RDX-0x40]）。
// 即：运算类不是猜的，是被唯一确定的；但它是通过明文反解得到的，
// 而不是从反汇编直接读出的，这一点如实记录在此。
//
// The exact step operation is not directly readable from the disassembly (both
// write-backs reuse one register), so it was solved from the plaintext: over
// op∈{xor,add} × add∈[0,256) each vector has exactly ONE solution, and it
// matches the constant in the listing. Unique, but derived from the plaintext —
// recorded here rather than presented as read-off-the-binary.
//
// The two decFuncs differ only in the step operation (XOR vs ADD) and the
// additive constant; both vectors decode byte-exactly.
//
// 家族 B（FUN_01913320 / FUN_01913640）用 while+switch 状态机写常数，
// 以 bVar2 = 步号*步序 ^ bVar2 递推变换字节；其调度尚未完全解出，
// 见 string_decrypt.go 的说明，不做猜测性还原。

// PoOp 是家族 A 的步运算类型。
type PoOp byte

const (
	// PoOpXOR：data[a] = data[b] ^ k; data[b] = old_a ^ k（FUN_01912ac0）。
	PoOpXOR PoOp = iota
	// PoOpAdd：data[a] = data[b] + k; data[b] = old_a + k（FUN_01912bc0）。
	PoOpAdd
)

// PoSwapAdd 是 FUN_01912ac0 的加法常数（+0x1e）。
const PoSwapAdd = 0x1e

// PoSwapAddBC0 是 FUN_01912bc0 的加法常数（-0x40，即 +0xc0 mod 256）。
const PoSwapAddBC0 = 0xc0

// poStep 对单个字节对施加一步变换。
func poStep(x, y, k byte, op PoOp) (byte, byte) {
	switch op {
	case PoOpAdd:
		return y + k, x + k
	default:
		return y ^ k, x ^ k
	}
}

// poStepInv 是 poStep 的逆。
func poStepInv(x, y, k byte, op PoOp) (byte, byte) {
	switch op {
	case PoOpAdd:
		return y - k, x - k
	default:
		return y ^ k, x ^ k
	}
}

// PoDecodeChain 解码家族 A 的置换链：data 为常数区（密文），key 为索引表，
// k = (key[i]^key[i+1]) + i + add（下标越界时该步跳过）。
//
// PoDecodeChain decodes a family-A chain: each key pair (a,b) swaps data[a] and
// data[b] with k = (a^b) + i + add and the function's step operation.
func PoDecodeChain(data, key []byte, add byte, op PoOp) []byte {
	out := append([]byte{}, data...)
	for i := 0; i+1 < len(key); i += 2 {
		a, b := int(key[i]), int(key[i+1])
		if a >= len(out) || b >= len(out) {
			continue
		}
		k := byte(a^b) + byte(i) + add
		out[a], out[b] = poStep(out[a], out[b], k, op)
	}
	return out
}

// PoEncodeChain 是 PoDecodeChain 的逆：按相反顺序施加逆步。
// PoDecodeChain(PoEncodeChain(p, k, add, op), k, add, op) == p。
func PoEncodeChain(plain, key []byte, add byte, op PoOp) []byte {
	out := append([]byte{}, plain...)
	var steps []int
	for i := 0; i+1 < len(key); i += 2 {
		steps = append(steps, i)
	}
	for s := len(steps) - 1; s >= 0; s-- {
		i := steps[s]
		a, b := int(key[i]), int(key[i+1])
		if a >= len(out) || b >= len(out) {
			continue
		}
		k := byte(a^b) + byte(i) + add
		out[a], out[b] = poStepInv(out[a], out[b], k, op)
	}
	return out
}

// PoArgs 返回家族 A 的 argv 编码参数：索引表长度 = 明文长度（每步 2 字节）。
func PoArgs(plainLen int, seed byte) ([]byte, byte) {
	return PoKey(seed, plainLen), seed
}

// PoKey 由种子生成家族 A 的索引表（每字节都是合法下标，落在 [0,n) 内）。
func PoKey(seed byte, n int) []byte {
	key := make([]byte, n)
	if n == 0 {
		return key
	}
	for i := range key {
		key[i] = byte((i*7 + int(seed)*13) % n)
	}
	return key
}

// PoArgvOp 是 argv 密文所用步运算。原版 argv 由 FUN_018dca00 逐条追加，
// 密文来自该包自己的 decFunc；这里固定用异或型（与 FUN_01912ac0 同族）。
const PoArgvOp = PoOpXOR

// EncodePoArg 把明文参数编码成家族 A 的置换链密文（载荷调试参数 argv 用）。
// 编码是确定性的：同一个 seed 得到同一密文，agent 侧用同样的 key 还原。
func EncodePoArg(plain string, seed byte) []byte {
	b := []byte(plain)
	key, add := PoArgs(len(b), seed)
	return PoEncodeChain(b, key, add, PoArgvOp)
}

// DecodePoArg 还原 EncodePoArg 的明文。
func DecodePoArg(cipher []byte, seed byte) string {
	key, add := PoArgs(len(cipher), seed)
	return string(PoDecodeChain(cipher, key, add, PoArgvOp))
}

// ---------------------------------------------------------------------------
// 家族 A 回归向量（直接取自反编译的常数区与索引表）
// Family-A regression vectors, taken verbatim from the decompiled constants.
// ---------------------------------------------------------------------------

// PoVector 是一条家族 A 的回归向量。
type PoVector struct {
	Name   string
	Values []byte // 常数区（密文）
	Key    []byte // 索引表（每两字节一次置换）
	Add    byte   // 加法常数
	Op     PoOp   // 步运算
	Want   string
}

// PoDecodeVector 按向量参数还原明文。
func PoDecodeVector(v PoVector) string {
	return string(PoDecodeChain(v.Values, v.Key, v.Add, v.Op))
}

// PoVectors 是从原版二进制反编译常数直接抄录的回归向量。
// 两条都必须逐字节匹配（PoVectorsSolved）。
var PoVectors = []PoVector{
	{
		// FUN_01912ac0（0x1912ac0）：异或型。
		Name: "stageless/ebpf_%s_%s",
		Values: []byte{
			0x61, 0x74, 0x73, 0x09, 0x65, 0x0b, 0x7e, 0x16, 0x73, 0x2f,
			0x65, 0x62, 0x18, 0x55, 0x6f, 0x25, 0x73, 0x50, 0x25, 0x50,
		},
		Key: []byte{
			0x06, 0x11, 0x02, 0x00, 0x07, 0x11, 0x03, 0x0d, 0x05, 0x13,
			0x0c, 0x13, 0x0d, 0x13, 0x11, 0x0d, 0x00, 0x02, 0x0e, 0x0e,
		},
		Add:  PoSwapAdd,
		Op:   PoOpXOR,
		Want: "stageless/ebpf_%s_%s",
	},
	{
		// FUN_01912bc0（0x1912bc0）：加法型，常数 -0x40。
		Name: "windows_amd64.exe",
		Values: []byte{
			0x77, 0xc1, 0x6e, 0x9b, 0x05, 0xea, 0x73, 0x5c, 0x61, 0x84,
			0x88, 0x85, 0x9c, 0x2e, 0xf5, 0x78, 0x8c,
		},
		Key: []byte{
			0x04, 0x04, 0x05, 0x0a, 0x04, 0x0a, 0x0e, 0x01, 0x09, 0x10,
			0x0e, 0x0a, 0x03, 0x01, 0x0b, 0x07, 0x04, 0x03, 0x05, 0x0c,
		},
		Add:  PoSwapAddBC0,
		Op:   PoOpAdd,
		Want: "windows_amd64.exe",
	},
}

// PoVectorsSolved 报告全部回归向量是否已逐字节还原。
func PoVectorsSolved() bool {
	for _, v := range PoVectors {
		if PoDecodeVector(v) != v.Want {
			return false
		}
	}
	return true
}
