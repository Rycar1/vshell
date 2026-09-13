package c2engine

import (
	"testing"
)

// PoVectors 的每一条都直接取自原版二进制反编译出的常数区与索引表，
// 必须逐字节还原（这是与二进制行为一致性的直接证据）。
func TestPoDecodeVectors(t *testing.T) {
	for _, v := range PoVectors {
		got := PoDecodeVector(v)
		if got != v.Want {
			t.Errorf("%s: decoded %q, want %q", v.Name, got, v.Want)
		}
	}
	if !PoVectorsSolved() {
		t.Error("PoVectorsSolved() = false, want true")
	}
}

// 家族 A 的置换链必须可逆（PoEncodeChain 是 PoDecodeChain 的逆），
// 两种步运算都要成立。
func TestPoChainRoundTrip(t *testing.T) {
	for _, op := range []PoOp{PoOpXOR, PoOpAdd} {
		for _, plain := range []string{"", "a", "tcp", "windows_amd64.exe", "127.0.0.1:49319 tcp qwe123qwe"} {
			for seed := 0; seed < 8; seed++ {
				key, add := PoArgs(len(plain), byte(seed))
				ct := PoEncodeChain([]byte(plain), key, add, op)
				if got := string(PoDecodeChain(ct, key, add, op)); got != plain {
					t.Errorf("op %d seed %d: round trip %q -> %q -> %q", op, seed, plain, ct, got)
				}
			}
		}
	}
}

// EncodePoArg/DecodePoArg 也必须成对（载荷里 argv 的实际编码路径）。
func TestPoArgRoundTrip(t *testing.T) {
	for _, plain := range []string{"", "10.1.2.3:55555 tcp vk-secret salt-secret", "socks5://127.0.0.1:1080"} {
		for seed := 0; seed < 4; seed++ {
			ct := EncodePoArg(plain, byte(seed))
			if got := DecodePoArg(ct, byte(seed)); got != plain {
				t.Errorf("seed %d: %q -> %q -> %q", seed, plain, ct, got)
			}
		}
	}
}

// 家族 B 的写字节语义：out_i = v_i - seed_i，seed_{i+1} = seed_i + v_i
// （逐指令核对 FUN_019146e0）。
func TestPoEmitSemantics(t *testing.T) {
	for _, v := range PoEmitVectors {
		got := PoEmit(v.Seed, v.Vals...)
		if string(got) != string(v.Want) {
			t.Errorf("%s: PoEmit = % x, want % x", v.Name, got, v.Want)
		}
	}
}

// 索引表长度由调用方给定，解码器不得越界（任意长度/种子下都安全）。
func TestPoDecodeChainNoOutOfRange(t *testing.T) {
	for n := 1; n < 64; n++ {
		for seed := 0; seed < 256; seed += 37 {
			data := make([]byte, n)
			for i := range data {
				data[i] = byte(i)
			}
			key, add := PoArgs(n, byte(seed))
			_ = PoDecodeChain(data, key, add, PoOpXOR)
			_ = PoDecodeChain(data, key, add, PoOpAdd)
		}
	}
}

// 已还原的两条文件名模板必须与反编译一致。
func TestPoFilenameTemplates(t *testing.T) {
	if PoTplStagelessEBPF != "stageless/ebpf_%s_%s" {
		t.Errorf("stageless template = %q", PoTplStagelessEBPF)
	}
	if PoDefaultArchSuffix != "windows_amd64.exe" {
		t.Errorf("default arch suffix = %q", PoDefaultArchSuffix)
	}
}
