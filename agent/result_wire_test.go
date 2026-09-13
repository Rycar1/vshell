//go:build !server
// +build !server

package main

import (
	"encoding/binary"
	"testing"
)

// recordBlockForTest 按契约形态拼出记录块（与服务器端解析对称）。
// 仅供测试：生产代码不构造这个形态，因为它在原版里没有依据。
func recordBlockForTest(text string) []byte {
	frames := emitString(text)
	if len(frames) == 0 {
		return nil
	}
	b := resultRecordBytes(frames)
	binary.LittleEndian.PutUint64(b[16:], uint64(len(text)))
	return append(b, []byte(text)...)
}

// 记录块编码测试（buffer-block).
//
// 重要：这些测试钉住的是**缓冲内布局**（FUN_0100d160 的 24 字节记录）与
// 复刻端的契约形态，而**不是**已恢复的线上格式 —— 记录→线缆那一步在静态侧
// 没有实现者（见 agent/main.go 的「Result frames on the wire」一节）。
// 这些字节目前没有生产调用者：SendResult 仍发 ResultRequest JSON。

// TestRecordBlockLayout 钉住缓冲内的字节排布：
//
//	[0..24)   0x75 记录，A=0, B=1, C=0, +0x10 = len(load)
//	[24..48)  0x54 记录，A=1, B=1, C=0, +0x10 = 0
//	[48..)    load 本体（契约形态，非原版事实）
func TestRecordBlockLayout(t *testing.T) {
	text := "whoami output"
	b := recordBlockForTest(text)
	if len(b) != 48+len(text) {
		t.Fatalf("块长 = %d, want %d", len(b), 48+len(text))
	}
	if b[0] != frameKindDetail {
		t.Errorf("记录 0 帧码 = 0x%02x, want 0x75", b[0])
	}
	if binary.LittleEndian.Uint32(b[4:]) != 0 || binary.LittleEndian.Uint32(b[8:]) != 1 ||
		binary.LittleEndian.Uint32(b[12:]) != 0 {
		t.Errorf("记录 0 字段 = A%d B%d C%d, want A0 B1 C0",
			binary.LittleEndian.Uint32(b[4:]), binary.LittleEndian.Uint32(b[8:]),
			binary.LittleEndian.Uint32(b[12:]))
	}
	if n := binary.LittleEndian.Uint64(b[16:]); n != uint64(len(text)) {
		t.Errorf("记录 0 的 +0x10 = %d, want %d", n, len(text))
	}
	if b[24] != frameKindListEnd {
		t.Errorf("记录 1 帧码 = 0x%02x, want 0x54", b[24])
	}
	if binary.LittleEndian.Uint32(b[24+4:]) != 1 || binary.LittleEndian.Uint32(b[24+8:]) != 1 {
		t.Errorf("记录 1 字段 = A%d B%d, want A1 B1",
			binary.LittleEndian.Uint32(b[24+4:]), binary.LittleEndian.Uint32(b[24+8:]))
	}
	if got := string(b[48:]); got != text {
		t.Errorf("负载 = %q, want %q", got, text)
	}
}

// TestEmitStringRecordSequence 复刻 FUN_01094ba0 的记录序：0x75 + 0x54，
// 空串则一条都不发（这部分是实锤，与线路形态无关）。
func TestEmitStringRecordSequence(t *testing.T) {
	if frames := emitString(""); frames != nil {
		t.Fatalf("空串应不发记录，得到 %v", frames)
	}
	frames := emitString("x")
	if len(frames) != 2 || frames[0].Kind != frameKindDetail || frames[1].Kind != frameKindListEnd {
		t.Fatalf("记录序 = %+v, want 0x75 后接 0x54", frames)
	}
}
