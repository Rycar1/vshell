package c2engine

// ============================================================================
// 原版字符串解密链：家族 B（garble 的 po 类型 / 每包 decFunc）
// Original string-decryption chain, family B (garble's po type / decFunc)
// ============================================================================
//
// 反编译证据（v_windows_amd64.exe）：
//
//	FUN_019146e0（0x19146e0，家族 B 的写字节闭包，逐条指令已核对）：
//
//	    R8  = closure[0x10]   ; 指向捕获的种子（*uint8）
//	    RDX = closure[0x8]    ; 指向捕获的缓冲区描述符
//	    R9  = closure[0x18]   ; 指向捕获的输出切片
//	    cVar1 = *R8                  ; 当前种子值
//	    ... 若容量不足则 FUN_004476e0 扩容 ...
//	    buf[len-1] = param_1 - cVar1 ; 写入：值 - 当前种子
//	    *R8 = *R8 + param_1          ; 种子自增：seed += 值
//
//	也就是说：闭包每被调用一次，就把调用参数减去"当前种子"写出一字节，
//	并把种子按该参数推进。于是第 i 次调用写出的字节为
//
//	    seed_{i+1} = seed_i + v_i          （v_i 为闭包参数，即反编译的
//	    out_i      = v_i - seed_i          常数块字节）
//
//	构造器（FUN_01914a40 / FUN_01914b40 / FUN_01914c40 / FUN_01913320 /
//	FUN_01913640）以“计数器写法”调用该闭包：控制流是一个 while+switch
//	状态机，
//
//	    bVar2 = 步号 * 步序 ^ bVar2          （FUN_01913320/01913640 的种子递推）
//	    ...
//	    local_2f[uVar4] = local_2f[uVar5] ^ bVar2  /  -= / +=   （参数置换）
//
//	收尾 FUN_0044ac40(0, buf, n) 产出 n 字节 Go 字符串。
//
// 已验证的部分：
//   - 写字节语义 out_i = v_i - seed_i, seed_{i+1} = seed_i + v_i（逐指令核对）；
//   - 家族 A 的置换链（见 po_decode.go，两条向量已逐字节还原）。
//
// 未解决（不猜测）：
//   家族 B 中"步号/步序/k"如何在无外层循环计数器的构造器里推进，
//   以及 while+switch 状态机的步进调度（Ghidra 无法直接反编译该 switch），
//   尚未完全确定；因此本文件不产出任何家族 B 的具体字符串，
//   控制器对这类字符串（如 shellcode 分支的魔数）不做伪造还原。
//
// Family B's per-write semantics are confirmed instruction-by-instruction
// (out_i = v_i - seed_i, seed advances by v_i); the step/key scheduling of the
// constructor state machines is still unrecovered, so no family-B string is
// synthesised here.

// PoEmit 按家族 B 的写字节语义把常数块 vals 展开为闭包输出：
// out_i = v_i - seed_i，seed_{i+1} = seed_i + v_i。
//
// PoEmit applies family B's write semantics to a constant block: each byte is
// `v - seed`, and the running seed advances by `v`.
func PoEmit(seed byte, vals ...byte) []byte {
	out := make([]byte, 0, len(vals))
	s := seed
	for _, v := range vals {
		out = append(out, v-s)
		s += v
	}
	return out
}

// PoEmitVector 是家族 B 写字节语义的回归向量。
// PoEmitVector pins family B's write semantics against the decompilation.
type PoEmitVector struct {
	Name string
	Seed byte
	Vals []byte
	Want []byte
}

// PoEmitVectors 取自 FUN_019146e0 的语义（out = v - seed，seed += v）。
// 这些向量不依赖任何未解出的调度，可直接对拍实现。
var PoEmitVectors = []PoEmitVector{
	{
		Name: "first byte is v minus the initial seed",
		Seed: 0x01,
		Vals: []byte{0x01, 0x02, 0x03},
		// 1-1=0；seed=2 → 2-2=0；seed=4 → 3-4=0xff
		Want: []byte{0x00, 0x00, 0xff},
	},
	{
		Name: "seed advances by each value",
		Seed: 0x10,
		Vals: []byte{0x20, 0x05, 0xff},
		// 0x20-0x10=0x10；seed=0x30 → 0x05-0x30=0xd5；seed=0x35 → 0xff-0x35=0xca
		Want: []byte{0x10, 0xd5, 0xca},
	},
}
