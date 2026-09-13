//go:build !server
// +build !server

package main

import (
	"encoding/binary"
	"strings"
	"testing"
)

// nativeBlock 构造一条原版形态的命令块：首字节 = 操作码，其后 4 字节大端参数，
// 其余补 NUL（原版 FUN_010952e0 的参数缓冲区即定长 0xEC 字节）。
func nativeBlock(op byte, arg int32) string {
	b := make([]byte, 8)
	b[0] = op
	binary.BigEndian.PutUint32(b[1:5], uint32(arg))
	return string(b)
}

// TestNativeCommandNameTableComplete 确认操作码表覆盖 FUN_010952e0 跳转表里
// 所有可达项（0x00–0x2a，缺 0x04/0x18 —— 这两项是跳转表槽位，与相邻项共享
// 同一个 .text 目标，Ghidra 将其标为不可达）。
func TestNativeCommandNameTableComplete(t *testing.T) {
	// 原版跳转表 DAT_1dc31ce0 必须存在的项（见 agent/main.go 顶部操作码表）。
	want := []byte{
		0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
		0x27, 0x28, 0x29, 0x2a,
	}
	if len(want) != 39 {
		t.Fatalf("table list = %d entries, want 39", len(want))
	}
	for _, op := range want {
		if nativeCommandNames[op] == "" {
			t.Errorf("opcode 0x%02x missing from nativeCommandNames", op)
		}
	}
	if len(nativeCommandNames) != len(want) {
		t.Errorf("nativeCommandNames has %d entries, want %d",
			len(nativeCommandNames), len(want))
	}
}

// TestDecodeNativeCommand 校验原生块与文本命令的判别（防止面板文本命令被
// 误判成操作码）。
func TestDecodeNativeCommand(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool // 是否识别为原生操作码块
	}{
		{"interval 无参数", string([]byte{opCmdInterval}), true},
		{"interval 带参数", nativeBlock(opCmdInterval, 30), true},
		{"sleep 带参数", nativeBlock(opCmdSleepMode, 2), true},
		{"ping", nativeBlock(opCmdPing, 12), true},
		{"destroy", nativeBlock(opCmdDestroy, 5), true},
		{"gateway 文本参数", string([]byte{opCmdSetGateway}) + "example.com", true},
		{"domain 仅操作码字节", string([]byte{opCmdSetDomain}), true},
		{"domain 带参数（可打印参数，判为文本）", string([]byte{opCmdSetDomain}) + "example.com", false},
		{"空白首字节 = interval get", " ", true},
		{"文本 dir（D=0x44 非操作码）", "dir", false},
		{"文本 shell 命令", "whoami /all", false},
		{"文本 terminal_start", "terminal_start type=bash", false},
		{"以空格开头的文本命令", " whoami", false},
		{"以 # 开头的文本命令", "#comment", false},
		{"以 ( 开头的文本命令", "(echo hi)", false},
		{"空命令", "", false},
		{"未知首字节", "\x99abc", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, ok := decodeNativeCommand(tc.in)
			if ok != tc.want {
				t.Fatalf("decodeNativeCommand(%q) = %v, want %v", tc.in, ok, tc.want)
			}
		})
	}
}

// TestDecodeCommandInt 校验 4 字节大端参数解码（原版 FUN_00fc1620 的整数形态）。
func TestDecodeCommandInt(t *testing.T) {
	tests := []struct {
		arg  int32
		want int
	}{
		{0, 0},
		{1, 1},
		{30, 30},
		{0x7fffffff, 0x7fffffff},
		{-1, -1},
		{-0x80000000, -0x80000000},
	}
	for _, tc := range tests {
		got := decodeCommandInt([]byte(nativeBlock(opCmdInterval, tc.arg)))
		if got != tc.want {
			t.Errorf("decodeCommandInt(arg=%d) = %d, want %d", tc.arg, got, tc.want)
		}
	}
	// 参数不足 5 字节 → 0
	if got := decodeCommandInt([]byte{opCmdInterval, 0, 0}); got != 0 {
		t.Errorf("short arg = %d, want 0", got)
	}
}

// TestDispatchNativeCommandImplemented 表驱动覆盖已对齐的操作码分支。
func TestDispatchNativeCommandImplemented(t *testing.T) {
	tests := []struct {
		name      string
		op        byte
		arg       int32
		hasArg    bool
		wantIn    string // 结果应包含
		wantError bool
	}{
		{"interval get", opCmdInterval, 0, false, "interval", false},
		{"interval set", opCmdInterval, 30, true, "interval 30", false},
		{"sleep mode get", opCmdSleepMode, 0, false, "sleep mode", false},
		{"debug log set", opCmdDebugLog, 0, false, "debug mask", false},
		{"work mode set", opCmdSetWorkMode, 2, true, "work mode 2", false},
		{"ping interval set", opCmdPingIntv, 15, true, "ping interval 15", false},
		{"ping arg", opCmdPing, 12, true, "pong 12", false},
		{"send delay negative abs", opCmdSetSendDly, -25, true, "send delay 25", false},
		{"upload speed set", opCmdUploadSpeed, 4096, true, "upload speed 4096", false},
		{"client limit get", opCmdClientLimit, 0, false, "client limit", false},
		{"client limit set", opCmdClientLimit, 99, true, "client limit 99", false},
		{"relicense", opCmdRelicense, 0, false, "license reloaded", false},
		{"destroy scheduled", opCmdDestroy, 5, true, "destroy scheduled 5", false},
		{"keepalive set", opCmdKeepAlive, 60, true, "keepalive 60", false},
		{"fwd port", opCmdFwdPort, 0, false, "fwd port", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := []byte{byte(tc.op)}
			if tc.hasArg {
				in = []byte(nativeBlock(tc.op, tc.arg))
			}
			got, errMsg := dispatchNativeCommand(1, tc.op, in, 5)
			if tc.wantError && errMsg == "" {
				t.Fatalf("errMsg empty, want error")
			}
			if !tc.wantError && errMsg != "" {
				t.Fatalf("unexpected error: %s", errMsg)
			}
			if tc.wantIn != "" && !strings.Contains(got, tc.wantIn) {
				t.Fatalf("result = %q, want containing %q", got, tc.wantIn)
			}
		})
	}
}

// TestDispatchNativeCommandUnimplemented 确认尚未对齐的操作码如实返回未实现，
// 而不是伪造成功（项目规则：不能臆造实现）。
func TestDispatchNativeCommandUnimplemented(t *testing.T) {
	pending := []byte{
		opCmdScreenshot, opCmdTunnelLog, opCmdNetCheck, opCmdTunnelDump,
		opCmdPortMapDump, opCmdConnDump, opCmdPipeDump, opCmdTcpPing,
		opCmdIfList, opCmdIfDetail, opCmdSysList, opCmdNetRoute, opCmdMtu,
		opCmdSysTime, opCmdReconnect, opCmdProxyList, opCmdHostScan,
		opCmdFileList, opCmdProcList, opCmdSvcList, opCmdSysInfo,
		opCmdSetDomain, opCmdThreadCount,
	}
	for _, op := range pending {
		got, errMsg := dispatchNativeCommand(1, op, []byte(nativeBlock(op, 1)), 5)
		if errMsg == "" {
			t.Errorf("opcode 0x%02x returned %q with no error; unimplemented opcodes must report failure", op, got)
			continue
		}
		if !strings.Contains(errMsg, "not implemented") {
			t.Errorf("opcode 0x%02x error = %q, want 'not implemented'", op, errMsg)
		}
	}
}

// TestExecuteCommandNativeAndRelayPaths 确认 executeCommand 的分派优先级：
// terminal_*/screen_capture* 文本中继 > 原生操作码块 > JSON/shell。
func TestExecuteCommandNativeAndRelayPaths(t *testing.T) {
	// 原生操作码块走原生分支（interval set 会更新 sleepTime）。
	prev := sleepTime
	defer func() { sleepTime = prev }()
	if out, errMsg := executeCommand(1, nativeBlock(opIntervalAlias, 42), 5); errMsg != "" {
		t.Fatalf("native interval: %s", errMsg)
	} else if !strings.Contains(out, "interval 42") {
		t.Fatalf("native interval result = %q", out)
	}
	if sleepTime != 42 {
		t.Fatalf("sleepTime = %d, want 42", sleepTime)
	}

	// 文本中继命令优先级最高：terminal_close 是安全分支（无会话 → 仍返回关闭串）。
	if out, errMsg := executeCommand(1, "terminal_close", 5); errMsg != "" {
		t.Fatalf("terminal_close: %s", errMsg)
	} else if !strings.Contains(out, "terminal closed") {
		t.Fatalf("terminal_close result = %q", out)
	}
	// screen_capture_stop 同理。
	if out, errMsg := executeCommand(1, "screen_capture_stop", 5); errMsg != "" {
		t.Fatalf("screen_capture_stop: %s", errMsg)
	} else if !strings.Contains(out, "screen capture stopped") {
		t.Fatalf("screen_capture_stop result = %q", out)
	}

	// 未对齐的原生操作码经 executeCommand 也必须报错，而不是落进 shell。
	if _, errMsg := executeCommand(1, nativeBlock(opCmdSysList, 1), 5); !strings.Contains(errMsg, "not implemented") {
		t.Fatalf("syslist errMsg = %q", errMsg)
	}
}

// opIntervalAlias 是 interval 操作码的测试别名，避免测试里出现裸字节。
const opIntervalAlias = opCmdInterval
