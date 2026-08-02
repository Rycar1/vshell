package c2engine

import (
	"encoding/binary"
	"testing"
)

// 线协议对齐验证：FUN_011b6ba0（构建）与 FUN_011b7020（解析）的帧格式
// [0] type u8 + [1..5] id u32 小端 + [5..] 载荷，容量 0xff5。

func TestBuildChannelFrameLayout(t *testing.T) {
	f := BuildChannelFrame(ChannelData, 0x12345678, []byte("payload"))
	if len(f) != ChannelHeaderLen+7 {
		t.Fatalf("len = %d, want %d", len(f), ChannelHeaderLen+7)
	}
	if f[0] != byte(ChannelData) {
		t.Errorf("type byte = %#x, want %#x", f[0], ChannelData)
	}
	if got := binary.LittleEndian.Uint32(f[1:5]); got != 0x12345678 {
		t.Errorf("id = %#x, want %#x", got, 0x12345678)
	}
	if string(f[5:]) != "payload" {
		t.Errorf("data = %q", f[5:])
	}
}

func TestParseChannelFrameRoundTrip(t *testing.T) {
	frame := BuildChannelFrame(ChannelSessCmd, 42, []byte("cmd-data"))
	parsed, n := ParseChannelFrame(frame)
	if n != len(frame) {
		t.Errorf("n = %d, want %d", n, len(frame))
	}
	if parsed.Type != ChannelSessCmd || parsed.ID != 42 || string(parsed.Data) != "cmd-data" {
		t.Errorf("parsed = %+v", parsed)
	}
}

func TestParseChannelFrameSessionDataField(t *testing.T) {
	// type 5 帧：8 字节数据字段位于 [5..13]，载荷其余部分不并入 Data。
	frame := BuildChannelFrame(ChannelSess, 7, []byte("12345678rest"))
	parsed, _ := ParseChannelFrame(frame)
	if parsed.Type != ChannelSess {
		t.Fatalf("type = %#x", parsed.Type)
	}
	if string(parsed.Data) != "12345678" {
		t.Errorf("session data = %q, want 8-byte field", parsed.Data)
	}
}

func TestBuildChannelFrameRejectsUnsendable(t *testing.T) {
	for _, ty := range []ChannelType{ChannelSessData, ChannelSessData2, ChannelAck, ChannelClose} {
		if f := BuildChannelFrame(ty, 1, []byte("x")); f != nil {
			t.Errorf("type %#x: built %v, want nil (原版直接返回路径)", ty, f)
		}
	}
}

func TestChannelFrameMaxSize(t *testing.T) {
	big := make([]byte, ChannelMaxFrame*2)
	f := BuildChannelFrame(ChannelData, 0, big)
	if len(f) > ChannelMaxFrame {
		t.Fatalf("frame len %d > 0xff5", len(f))
	}
	if len(f) != ChannelMaxFrame {
		t.Errorf("frame len = %d, want 0xff5（截断到容量）", len(f))
	}
	// 解析截断帧仍满足头部校验
	p, n := ParseChannelFrame(f)
	if n != len(f) || p.Type != ChannelData {
		t.Errorf("parse truncated: n=%d type=%#x", n, p.Type)
	}
}

func TestParseChannelFrameTooShort(t *testing.T) {
	if _, n := ParseChannelFrame([]byte{0x08, 0x01}); n != 0 {
		t.Errorf("short frame parsed with n=%d, want 0", n)
	}
}
