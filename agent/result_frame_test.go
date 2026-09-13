//go:build !server
// +build !server

package main

import (
	"encoding/binary"
	"testing"
)

// 结果帧编码测试。依据：FUN_0100d160 / FUN_0100d440 / FUN_0100d5e0 /
// FUN_01094a20 / FUN_01094ba0 的反编译（见 agent/main.go 的结果帧一节）。

// captureFrames 在测试期间接管结果帧，返回收集到的帧。
func captureFrames(t *testing.T) *[]resultFrame {
	t.Helper()
	prev := resultFrameSink
	var got []resultFrame
	resultFrameSink = func(frames []resultFrame) { got = append(got, frames...) }
	t.Cleanup(func() { resultFrameSink = prev })
	return &got
}

// TestResultFrameBytes 钉住 FUN_0100d160 写入的 24 字节布局：
//
//	+0x00 kind u8 / +0x01 flags u8 / +0x02 u16 / +0x04 A / +0x08 B / +0x0c C
//	/ +0x10 u64
func TestResultFrameBytes(t *testing.T) {
	f := resultFrame{Kind: 0x54, Flags: 0, W: 0, A: 1, B: 2, C: 3, D: 0}
	b := f.bytes()
	if len(b) != 24 {
		t.Fatalf("记录长度 = %d, want 24", len(b))
	}
	if b[0] != 0x54 {
		t.Errorf("+0x00 = 0x%02x, want 0x54", b[0])
	}
	if binary.LittleEndian.Uint16(b[2:]) != 0 {
		t.Errorf("+0x02 = %d, want 0", binary.LittleEndian.Uint16(b[2:]))
	}
	if binary.LittleEndian.Uint32(b[4:]) != 1 {
		t.Errorf("+0x04 = %d, want 1", binary.LittleEndian.Uint32(b[4:]))
	}
	if binary.LittleEndian.Uint32(b[8:]) != 2 {
		t.Errorf("+0x08 = %d, want 2", binary.LittleEndian.Uint32(b[8:]))
	}
	if binary.LittleEndian.Uint32(b[12:]) != 3 {
		t.Errorf("+0x0c = %d, want 3", binary.LittleEndian.Uint32(b[12:]))
	}
	if binary.LittleEndian.Uint64(b[16:]) != 0 {
		t.Errorf("+0x10 = %d, want 0", binary.LittleEndian.Uint64(b[16:]))
	}
}

// TestEmitScalar 覆盖 FUN_01094a20：0x48 记录（A=0, B=1, C=0）带负载值，
// 随后 0x54(A=1, B=1, C=0) 终止。
func TestEmitScalar(t *testing.T) {
	frames := emitScalar(42)
	if len(frames) != 2 {
		t.Fatalf("帧数 = %d, want 2", len(frames))
	}
	if frames[0].Kind != frameKindScalar || frames[0].A != 0 || frames[0].B != 1 || frames[0].C != 0 {
		t.Fatalf("首帧 = %+v", frames[0])
	}
	if !frames[0].HasLoad || frames[0].Load != 42 {
		t.Fatalf("负载 = %+v, want 42", frames[0])
	}
	if frames[1].Kind != frameKindListEnd || frames[1].A != 1 || frames[1].B != 1 || frames[1].C != 0 {
		t.Fatalf("终止帧 = %+v", frames[1])
	}
}

// TestEmitString 覆盖 FUN_01094ba0：空串不发任何记录。
func TestEmitString(t *testing.T) {
	if frames := emitString(""); frames != nil {
		t.Fatalf("空串应不发记录，得到 %v", frames)
	}
	frames := emitString("work-1")
	if len(frames) != 2 {
		t.Fatalf("帧数 = %d, want 2", len(frames))
	}
	if frames[0].Kind != frameKindDetail || frames[0].B != 1 {
		t.Fatalf("0x75 帧 = %+v（B 应为 1，来自 FUN_01094ba0 的 FUN_0100d5e0(0x75,0,1,0)）", frames[0])
	}
	if frames[1].Kind != frameKindListEnd {
		t.Fatalf("终止帧 = %+v", frames[1])
	}
}

// TestEmitFormat 覆盖 FUN_0100d440 的格式串编码：
//
//	's' → 非空 0x75 / 空 0x4b，B = base + 序号
//	'i' → 0x47，A = 值，B = base + 序号
//	收尾 → 0x54，A = base，B = 格式串长度
func TestEmitFormat(t *testing.T) {
	// "ssi"：两个字符串 + 一个整数，base = 0。
	frames := emitFormat(0, "ssi", 1, 0, 7)
	if len(frames) != 4 {
		t.Fatalf("帧数 = %d, want 4", len(frames))
	}
	if frames[0].Kind != frameKindDetail || frames[0].B != 0 {
		t.Errorf("第 0 项 = %+v, want 0x75 @0", frames[0])
	}
	if frames[1].Kind != frameKindStrNil || frames[1].B != 1 {
		t.Errorf("第 1 项 = %+v, want 0x4b @1（空串）", frames[1])
	}
	if frames[2].Kind != frameKindInt || frames[2].A != 7 || frames[2].B != 2 {
		t.Errorf("第 2 项 = %+v, want 0x47 A=7 @2", frames[2])
	}
	end := frames[3]
	if end.Kind != frameKindListEnd || end.A != 0 || end.B != 3 {
		t.Errorf("终止帧 = %+v, want 0x54 A=base B=3", end)
	}

	// base != 0 时 B 要加上 base（原版传的是「记录缓冲区 + 偏移」）。
	frames = emitFormat(10, "i", 5)
	if frames[0].B != 10 {
		t.Errorf("base=10 时 B = %d, want 10", frames[0].B)
	}
	if frames[1].A != 10 || frames[1].B != 1 {
		t.Errorf("终止帧 = %+v, want A=10 B=1", frames[1])
	}
}

// TestEmitFormatArgsExhausted 确认格式串多于参数时按 0 处理（原版从缓冲区
// 按指针步进取值，参数不足即读到 0），不 panic。
func TestEmitFormatArgsExhausted(t *testing.T) {
	frames := emitFormat(0, "si", 0)
	if len(frames) != 3 {
		t.Fatalf("帧数 = %d, want 3", len(frames))
	}
	if frames[0].Kind != frameKindStrNil {
		t.Errorf("缺参数的 's' 应为 0x4b，得到 %+v", frames[0])
	}
	if frames[1].Kind != frameKindInt || frames[1].A != 0 {
		t.Errorf("缺参数的 'i' 应为 0x47 A=0，得到 %+v", frames[1])
	}
}

// TestDispatchEmitsFrames 确认已实现的操作码真的产生对应形状的结果帧。
func TestDispatchEmitsFrames(t *testing.T) {
	tests := []struct {
		name    string
		op      byte
		in      []byte
		wantKnd []uint8 // 期望的帧码序列
	}{
		{"interval get", opCmdInterval, []byte{opCmdInterval}, []uint8{frameKindScalar, frameKindListEnd}},
		{"sleep set", opCmdSleepMode, []byte(nativeBlock(opCmdSleepMode, 2)), []uint8{frameKindScalar, frameKindListEnd}},
		{"debug log set", opCmdDebugLog, []byte(nativeBlock(opCmdDebugLog, 1)), []uint8{frameKindAck}},
		{"default keepalive", opCmdDefKeepAlvA, []byte{opCmdDefKeepAlvA}, []uint8{frameKindScalar, frameKindListEnd}},
		{"send state", opCmdNetCheck, []byte{opCmdNetCheck}, []uint8{frameKindScalar, frameKindListEnd}},
		{"tunnel log", opCmdTunnelLog, []byte{opCmdTunnelLog}, []uint8{frameKindScalar, frameKindListEnd}},
		{"tunnel dump off", opCmdTunnelDump, []byte{opCmdTunnelDump}, nil},
		{"send delay无参数", opCmdSetSendDly, []byte{opCmdSetSendDly}, []uint8{9}},
		{"send delay有参数", opCmdSetSendDly, []byte(nativeBlock(opCmdSetSendDly, 50)), []uint8{100}},
		{"work mode get", opCmdSetWorkMode, []byte{opCmdSetWorkMode}, []uint8{frameKindDetail, frameKindListEnd}},
		{"ping interval", opCmdPingIntv, []byte{opCmdPingIntv}, []uint8{frameKindScalar, frameKindListEnd}},
		{"ping interval 2", opCmdPingIntv2, []byte{opCmdPingIntv2}, []uint8{frameKindScalar, frameKindListEnd}},
		{"upload speed", opCmdUploadSpeed, []byte{opCmdUploadSpeed}, []uint8{frameKindScalar, frameKindListEnd}},
		{"client limit get", opCmdClientLimit, []byte{opCmdClientLimit}, []uint8{frameKindScalar, frameKindListEnd}},
		{"destroy scheduled", opCmdDestroy, []byte(nativeBlock(opCmdDestroy, 5)), []uint8{frameKindScalar, frameKindListEnd}},
		{"keepalive", opCmdKeepAlive, []byte{opCmdKeepAlive}, []uint8{frameKindScalar, frameKindListEnd}},
		{"thread count", opCmdThreadCount, []byte{opCmdThreadCount}, []uint8{frameKindScalar, frameKindListEnd}},
		{"sysinfo", opCmdSysInfo, []byte{opCmdSysInfo}, []uint8{frameKindScalar, frameKindListEnd}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := captureFrames(t)
			if _, errMsg := dispatchNativeCommand(1, tc.op, tc.in, 5); errMsg != "" {
				t.Fatalf("unexpected error: %s", errMsg)
			}
			if len(*got) != len(tc.wantKnd) {
				t.Fatalf("帧数 = %d (%v), want %d (%v)", len(*got), kinds(*got), len(tc.wantKnd), tc.wantKnd)
			}
			for i, k := range tc.wantKnd {
				if (*got)[i].Kind != k {
					t.Fatalf("第 %d 帧码 = 0x%02x, want 0x%02x（全部：%v）", i, (*got)[i].Kind, k, kinds(*got))
				}
			}
		})
	}
}

func kinds(frames []resultFrame) []uint8 {
	out := make([]uint8, len(frames))
	for i, f := range frames {
		out[i] = f.Kind
	}
	return out
}
