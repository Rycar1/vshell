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

// TestNativeCommandOpcodesMatchJumpTable 把操作码常量钉死在原版跳转表的槽位上。
// 这是防「整体偏移一位」复发的关键测试。
//
// 依据（FUN_010952e0 反汇编）：
//
//	01095828: MOVZX R9D,byte ptr [RDX + 0x8]   ; 记录 +8 的字节 = 操作码
//	01095830: DEC R9                           ; 索引 = 操作码 - 1
//	01095833: CMP R9,0x2a
//	0109583d: LEA RAX,[0x1dc31e40]             ; 跳转表
//	01095844: JMP qword ptr [RAX + R9*0x8]
//
// 表共 43 槽（索引 0..0x2a），槽位 i 承载操作码 i+1，因此操作码是连续的
// 0x01..0x2b —— 没有空洞，0x19 也是合法操作码。43 槽中恰有 2 槽指向 default
// 分支 0x109774f：槽 4 → 操作码 0x05，槽 0x18 → 操作码 0x19；其余 41 槽各有
// 真实处理块。
//
// 这张表逐槽来自 0x1dc31e40 的实际内容（每个目标地址都已用 Ghidra 的 xref
// `From 1dc31eXX [DATA]` 反查核对过）。
func TestNativeCommandOpcodesMatchJumpTable(t *testing.T) {
	const defaultTarget = 0x109774f
	// 槽位索引 -> 该槽的目标地址。
	slots := []uint32{
		0x1095848, 0x10958f2, 0x1095a5c, 0x1095ba5, defaultTarget, 0x1095d13,
		0x1095d90, 0x1095ea0, 0x1095ee5, 0x1095f17, 0x1095f36, 0x1096110,
		0x1096126, 0x1096277, 0x10962fc, 0x1096380, 0x1096445, 0x1096488,
		0x109654c, 0x10966c7, 0x1096800, 0x109688d, 0x10969f5, 0x1096a2d,
		defaultTarget, 0x1096af0, 0x1096b51, 0x1096cd2, 0x1096d65, 0x1096d8c,
		0x1096e2c, 0x1096edd, 0x1096ee5, 0x1096f8c, 0x1096fba, 0x1097054,
		0x1097165, 0x1097230, 0x1097269, 0x10972be, 0x10974d2, 0x109759a,
		0x1097625,
	}
	// CMP R9,0x2a 的越界上界 → 索引 0..0x2a 共 43 槽。
	if len(slots) != 43 {
		t.Fatalf("槽位数 = %d, want 43", len(slots))
	}
	// 不变量 1：槽位 i 承载操作码 i+1，且 0x01..0x2b 全部存在（无空洞）。
	for i := range slots {
		op := byte(i + 1)
		if nativeCommandNames[op] == "" {
			t.Errorf("槽位 %d 承载操作码 0x%02x，但 nativeCommandNames 里没有", i, op)
		}
	}
	if len(nativeCommandNames) != 43 {
		t.Errorf("nativeCommandNames 有 %d 项, want 43（操作码 0x01..0x2b 连续无空洞）",
			len(nativeCommandNames))
	}
	// 不变量 2：恰有 2 槽指向 default 分支，且就是 0x05 与 0x19。
	var defOps []byte
	for i, target := range slots {
		if target == defaultTarget {
			defOps = append(defOps, byte(i+1))
		}
	}
	if len(defOps) != 2 || defOps[0] != 0x05 || defOps[1] != 0x19 {
		t.Errorf("default 分支槽位对应操作码 %v, want [0x05 0x19]", defOps)
	}
	// 不变量 3：其余 41 槽各有真实处理块（用几个已逐指令核对的锚点固定）。
	anchors := map[byte]uint32{
		opCmdSetWorkMode: 0x1096277, // dec case 0xd：读 local_280+0x2c 的 bit6
		opCmdKeepAlive:   0x10974d2, // dec case 0x28：写 local_398+0x298
		opCmdTunnelCount: 0x1097054, // dec case 0x23：+2 字节 tunnel 计数
		opCmdPing:        0x1096b51, // dec case 0x1a：local_398+0x210 ping 往返
		opCmdSysTime:     0x1096af0, // dec case 0x19：FUN_01094280 系统时间
		opCmdFwdPort:     0x1097625, // dec case 0x2a：三个候选串 → 1/2/3
	}
	for op, want := range anchors {
		if got := slots[op-1]; got != want {
			t.Errorf("操作码 0x%02x 的目标 = 0x%08x, want 0x%08x", op, got, want)
		}
	}
	// 早前版本的错误锚点：0x1a 曾被当成 ping（实为 sysTime），0x1b 曾被当成
	// default（实为 ping）。这两条断言防止它复发。
	if opCmdSysTime != 0x1a {
		t.Errorf("sysTime 操作码 = 0x%02x, want 0x1a（表项 0x1dc31f08 → 0x1096af0）", opCmdSysTime)
	}
	if opCmdPing != 0x1b {
		t.Errorf("ping 操作码 = 0x%02x, want 0x1b（表项 0x1dc31f10 → 0x1096b51）", opCmdPing)
	}
	if opCmdDefKeepAlvA != 0x05 || opCmdDefKeepAlvB != 0x19 {
		t.Errorf("default 分支操作码 = 0x%02x/0x%02x, want 0x05/0x19",
			opCmdDefKeepAlvA, opCmdDefKeepAlvB)
	}
}

// TestNativeCommandNameTableComplete 确认助记名表覆盖跳转表的全部 43 槽。
func TestNativeCommandNameTableComplete(t *testing.T) {
	// 操作码 = 槽位 + 1，槽位 0..0x2a → 0x01..0x2b，连续无空洞。
	want := make([]byte, 0, 43)
	for op := 1; op <= 0x2b; op++ {
		want = append(want, byte(op))
	}
	if len(want) != 43 {
		t.Fatalf("table list = %d entries, want 43", len(want))
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
		{"systime", nativeBlock(opCmdSysTime, 12), true},
		{"ping", nativeBlock(opCmdPing, 12), true},
		{"destroy", nativeBlock(opCmdDestroy, 5), true},
		{"gateway 文本参数", string([]byte{opCmdSetGateway}) + "example.com", true},
		{"domain 仅操作码字节", string([]byte{opCmdSetDomain}), true},
		{"domain 带参数（可打印参数，判为文本）", string([]byte{opCmdSetDomain}) + "example.com", false},
		{"空白首字节 = filelist get", " ", true},
		{"文本 dir（D=0x44 非操作码）", "dir", false},
		{"文本 shell 命令", "whoami /all", false},
		{"文本 terminal_start", "terminal_start type=bash", false},
		{"以空格开头的文本命令", " whoami", false},
		{"以 # 开头的文本命令", "#comment", false},
		{"以 ( 开头的文本命令", "(echo hi)", false},
		{"空命令", "", false},
		{"未知首字节", "\x99abc", false},
		{"fwd port 仅操作码字节（0x2b）", string([]byte{opCmdFwdPort}), true},
		{"fwd port 带可打印参数（判为文本）", string([]byte{opCmdFwdPort}) + "port1", false},
		{"以 + 开头的文本命令", "+1 2", false},
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
		{"send delay negative abs", opCmdSetSendDly, -25, true, "send delay 25", false},
		{"upload speed set", opCmdUploadSpeed, 4096, true, "upload speed 4096", false},
		{"client limit get", opCmdClientLimit, 0, false, "client limit", false},
		{"client limit set", opCmdClientLimit, 99, true, "client limit 99", false},
		{"relicense", opCmdRelicense, 0, false, "license reloaded", false},
		{"destroy scheduled", opCmdDestroy, 5, true, "destroy scheduled 5", false},
		{"keepalive set", opCmdKeepAlive, 60, true, "keepalive 60", false},
		{"mtu set", opCmdMtu, 1400, true, "mtu 1400", false},
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
		opCmdScreenshot, opCmdConnStat, opCmdSysList,
		opCmdPortMapDump, opCmdConnDump, opCmdPipeDump, opCmdTcpPing,
		opCmdIfList, opCmdIfDetail, opCmdProxyList, opCmdSysList2,
		opCmdNetRoute, opCmdPing, opCmdHostScan, opCmdFileList,
		opCmdProcList, opCmdSvcList,
		opCmdFwdPort,
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

// TestDispatchDefaultBranchKeepAlive 覆盖跳转表 default 分支的两个操作码
// （0x05 与 0x19 的表项都指向 0x109774f，见 FUN_010952e0 dec default）：
// FUN_00fc1620 解析 → FUN_010fdec0 只在 n >= 1 时写 +0x304 → FUN_01094a20 下发。
func TestDispatchDefaultBranchKeepAlive(t *testing.T) {
	prev := agentKeepAlive
	defer func() { agentKeepAlive = prev }()

	for _, op := range []byte{opCmdDefKeepAlvA, opCmdDefKeepAlvB} {
		agentKeepAlive = 0
		if got, errMsg := dispatchNativeCommand(1, op, []byte(nativeBlock(op, 45)), 5); errMsg != "" {
			t.Fatalf("opcode 0x%02x: %s", op, errMsg)
		} else if got != "keepalive 45" {
			t.Fatalf("opcode 0x%02x result = %q, want \"keepalive 45\"", op, got)
		}
		// n < 1 时 FUN_010fdec0 不写 +0x304（反编译：if (param_3 < 1) 走无参分支）。
		if got, _ := dispatchNativeCommand(1, op, []byte(nativeBlock(op, 0)), 5); got != "keepalive 45" {
			t.Fatalf("opcode 0x%02x n=0 改写了 +0x304：%q", op, got)
		}
		// 无参数：仍下发当前值（反编译 default 分支末尾的 FUN_01094a20）。
		if got, _ := dispatchNativeCommand(1, op, []byte{op}, 5); got != "keepalive 45" {
			t.Fatalf("opcode 0x%02x 无参数 result = %q", op, got)
		}
	}
}

// TestDispatchSendState 覆盖 dec case 0x5（操作码 0x06）：读写
// [local_2a0[3]+0x74] 后 FUN_00fee040 应用。
func TestDispatchSendState(t *testing.T) {
	prev := agentSendField
	defer func() { agentSendField = prev }()

	if got, errMsg := dispatchNativeCommand(1, opCmdNetCheck, []byte(nativeBlock(opCmdNetCheck, 7)), 5); errMsg != "" {
		t.Fatalf("set: %s", errMsg)
	} else if got != "send state 7" {
		t.Fatalf("set result = %q", got)
	}
	if got, _ := dispatchNativeCommand(1, opCmdNetCheck, []byte{opCmdNetCheck}, 5); got != "send state 7" {
		t.Fatalf("get result = %q", got)
	}
}

// TestDispatchTunnelLog 覆盖 dec case 0x6（操作码 0x07）：数值写入 +0x224，
// 并按真/假置位或清位 local_280[6] 的 bit5（0x20）。
func TestDispatchTunnelLog(t *testing.T) {
	prevLog, prevMask := agentTunnelLogLevel, agentDebugMask
	defer func() { agentTunnelLogLevel, agentDebugMask = prevLog, prevMask }()

	agentDebugMask = 0
	if got, errMsg := dispatchNativeCommand(1, opCmdTunnelLog, []byte(nativeBlock(opCmdTunnelLog, 3)), 5); errMsg != "" {
		t.Fatalf("set: %s", errMsg)
	} else if got != "tunnel log 3" {
		t.Fatalf("set result = %q", got)
	}
	if agentDebugMask&0x20 == 0 {
		t.Fatalf("debug mask = 0x%x, want bit5 置位", agentDebugMask)
	}
	if _, _ = dispatchNativeCommand(1, opCmdTunnelLog, []byte(nativeBlock(opCmdTunnelLog, 0)), 5); agentDebugMask&0x20 != 0 {
		t.Fatalf("debug mask = 0x%x, want bit5 清零", agentDebugMask)
	}
}

// TestDispatchTunnelDump 覆盖 dec case 0x7（操作码 0x08）：只处理有参数的情形
// （FUN_01094220 解析布尔 → FUN_010836e0），无参数不回包。
func TestDispatchTunnelDump(t *testing.T) {
	prev := agentTunnelDumpState
	defer func() { agentTunnelDumpState = prev }()

	got, errMsg := dispatchNativeCommand(1, opCmdTunnelDump, []byte(nativeBlock(opCmdTunnelDump, 1)), 5)
	if errMsg != "" || got != "tunnel dump 1" {
		t.Fatalf("set on = (%q, %q)", got, errMsg)
	}
	// FUN_01094220 的布尔解析：首字节 '0' 为假，其余为真（非 NUL 即真）。
	got, errMsg = dispatchNativeCommand(1, opCmdTunnelDump, []byte{nativeBlock(opCmdTunnelDump, 0)[0], '0'}, 5)
	if errMsg != "" || got != "tunnel dump 0" {
		t.Fatalf("set off = (%q, %q)", got, errMsg)
	}
	got, errMsg = dispatchNativeCommand(1, opCmdTunnelDump, []byte{opCmdTunnelDump}, 5)
	if errMsg != "" || got != "" {
		t.Fatalf("无参数应无回包，得到 (%q, %q)", got, errMsg)
	}
}

// TestDispatchMtu 覆盖 dec case 0x17（操作码 0x18）：每次调用先写 local_398+0x218
// 初值 -2，有参数时写入前先做 `if (*local_228 < -1) *local_228 = -1`，再经
// FUN_00fdfbe0 写回并读回该字段。
//
// 夹取发生在 FUN_00fdfbe0 之前，所以 n ≤ -2 一律变成 -1；FUN_00fdfbe0 里
// `-2 < param_3` 的守卫在这个操作码下永远为真（不可达分支），复刻端如实照搬。
func TestDispatchMtu(t *testing.T) {
	if got, _ := dispatchNativeCommand(1, opCmdMtu, []byte{opCmdMtu}, 5); got != "mtu -2" {
		t.Fatalf("无参数 result = %q, want \"mtu -2\"", got)
	}
	if got, _ := dispatchNativeCommand(1, opCmdMtu, []byte(nativeBlock(opCmdMtu, 1400)), 5); got != "mtu 1400" {
		t.Fatalf("set result = %q", got)
	}
	// *local_228 < -1 → 夹到 -1（-100 与 -2 都落在这一支）
	for _, n := range []int32{-100, -2} {
		if got, _ := dispatchNativeCommand(1, opCmdMtu, []byte(nativeBlock(opCmdMtu, n)), 5); got != "mtu -1" {
			t.Fatalf("n=%d result = %q, want \"mtu -1\"", n, got)
		}
	}
	// -1 不夹取，写入并读回 -1
	if got, _ := dispatchNativeCommand(1, opCmdMtu, []byte(nativeBlock(opCmdMtu, -1)), 5); got != "mtu -1" {
		t.Fatalf("n=-1 result = %q, want \"mtu -1\"", got)
	}
}

// TestDispatchReconnect 覆盖 dec case 0x1b（操作码 0x1c）：有参数且非负时写入
// local_398+0x228（负数回落全局默认，复刻端无该默认表，故不写）。
func TestDispatchReconnect(t *testing.T) {
	prev := agentReconnect
	defer func() { agentReconnect = prev }()

	if got, errMsg := dispatchNativeCommand(1, opCmdReconnect, []byte(nativeBlock(opCmdReconnect, 30)), 5); errMsg != "" {
		t.Fatalf("set: %s", errMsg)
	} else if got != "reconnect 30" {
		t.Fatalf("set result = %q", got)
	}
	// 负数：原版取全局默认 DAT_1e2f2b48，复刻端无该表 → 保持原值
	if got, _ := dispatchNativeCommand(1, opCmdReconnect, []byte(nativeBlock(opCmdReconnect, -5)), 5); got != "reconnect 30" {
		t.Fatalf("negative arg result = %q", got)
	}
	if got, _ := dispatchNativeCommand(1, opCmdReconnect, []byte{opCmdReconnect}, 5); got != "reconnect 30" {
		t.Fatalf("无参数 result = %q", got)
	}
}

// TestDispatchPingIntv2 覆盖 dec case 0x1e（操作码 0x1f）：无参数时下发
// [local_2a0[1]+8]+0x34，连接池为空回 0。
func TestDispatchPingIntv2(t *testing.T) {
	prev := agentPingInterval
	defer func() { agentPingInterval = prev }()

	agentPingInterval = 20
	if got, errMsg := dispatchNativeCommand(1, opCmdPingIntv2, []byte{opCmdPingIntv2}, 5); errMsg != "" {
		t.Fatalf("get: %s", errMsg)
	} else if got != "ping interval 20" {
		t.Fatalf("get result = %q", got)
	}
}

// TestDispatchSysInfoMode 覆盖 dec case 0x26（操作码 0x27）的解析器
// FUN_01094600：首字节 '0'/'1'/'2' 直接返回该数字。
func TestDispatchSysInfoMode(t *testing.T) {
	prev := agentSysInfoMode
	defer func() { agentSysInfoMode = prev }()

	for in, want := range map[byte]int{'0': 0, '1': 1, '2': 2, '9': 0, 'x': 0} {
		if got, errMsg := dispatchNativeCommand(1, opCmdSysInfo, []byte{opCmdSysInfo, in}, 5); errMsg != "" {
			t.Fatalf("in=%q: %s", in, errMsg)
		} else if got != "sysinfo "+string(rune('0'+want)) {
			t.Fatalf("in=%q result = %q, want sysinfo %d", in, got, want)
		}
	}
	// 无参数：下发当前值
	agentSysInfoMode = 2
	if got, _ := dispatchNativeCommand(1, opCmdSysInfo, []byte{opCmdSysInfo}, 5); got != "sysinfo 2" {
		t.Fatalf("无参数 result = %q", got)
	}
}

// TestDispatchThreadCount 覆盖 dec case 0x29（操作码 0x2a）：FUN_010ff7e0
// 只在 n >= 1 时写 +0x300。
func TestDispatchThreadCount(t *testing.T) {
	prev := agentThreadCount
	defer func() { agentThreadCount = prev }()

	if got, errMsg := dispatchNativeCommand(1, opCmdThreadCount, []byte(nativeBlock(opCmdThreadCount, 4)), 5); errMsg != "" {
		t.Fatalf("set: %s", errMsg)
	} else if got != "thread count 4" {
		t.Fatalf("set result = %q", got)
	}
	if got, _ := dispatchNativeCommand(1, opCmdThreadCount, []byte(nativeBlock(opCmdThreadCount, 0)), 5); got != "thread count 4" {
		t.Fatalf("n=0 改写了 +0x300：%q", got)
	}
	if got, _ := dispatchNativeCommand(1, opCmdThreadCount, []byte{opCmdThreadCount}, 5); got != "thread count 4" {
		t.Fatalf("无参数 result = %q", got)
	}
}

// TestParseSysInfoMode 直接覆盖 FUN_01094600 的复刻实现。
func TestParseSysInfoMode(t *testing.T) {
	tests := []struct {
		in   []byte
		want int
	}{
		{[]byte{opCmdSysInfo, '0'}, 0},
		{[]byte{opCmdSysInfo, '1'}, 1},
		{[]byte{opCmdSysInfo, '2'}, 2},
		{[]byte{opCmdSysInfo, '3'}, 0}, // 只有 0x30–0x32 走数字分支
		{[]byte{opCmdSysInfo, 'z'}, 0}, // 文本形态需运行期字符串表，静态不可读 → 不匹配
		{[]byte{opCmdSysInfo}, 0},
	}
	for _, tc := range tests {
		if got := parseSysInfoMode(tc.in); got != tc.want {
			t.Errorf("parseSysInfoMode(%q) = %d, want %d", tc.in, got, tc.want)
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

// 0x1a (sysTime) moved from the unimplemented set to the implemented set: the
// query side (no arg → report whether the system time has been set) and the set
// side (arg → apply) are both backed by the decompiled branch behaviour, and the
// only unrecovered part — the exact reply string the original sends — is
// documented as a divergence rather than left as `not implemented`.
func TestSysTimeIsImplemented(t *testing.T) {
	out, err := dispatchNativeCommand(1, opCmdSysTime, nil, 5)
	if err != "" {
		t.Fatalf("sysTime query returned error %q, want a report", err)
	}
	if out == "" {
		t.Fatal("sysTime query returned empty output")
	}
}

// 0x24 (tunnelCount) implemented: both branches are fully described by the
// decompilation and neither depends on a runtime-built string. No arg reports
// (count-1); with an arg the count rotates via (n+1)&7 with 0 treated as 1.
func TestTunnelCountIsImplemented(t *testing.T) {
	if _, err := dispatchNativeCommand(1, opCmdTunnelCount, nil, 5); err != "" {
		t.Fatalf("tunnelCount query returned error %q", err)
	}
	if _, err := dispatchNativeCommand(1, opCmdTunnelCount, []byte(nativeBlock(opCmdTunnelCount, 3)), 5); err != "" {
		t.Fatalf("tunnelCount set returned error %q", err)
	}
}

// 0x28 (setDomain) implemented: the branch's behaviour depends on set/clear/read-
// back, not on the string's content, so it is implementable even though the
// original's global holds a runtime-written value. The argument is TEXT (a
// domain/SNI name), not a 4-byte int block, so it is taken from the raw remainder.
func TestSetDomainIsImplemented(t *testing.T) {
	in := append([]byte{opCmdSetDomain}, []byte("example.com")...)
	if _, err := dispatchNativeCommand(1, opCmdSetDomain, in, 5); err != "" {
		t.Fatalf("setDomain(set) returned error %q", err)
	}
	if _, err := dispatchNativeCommand(1, opCmdSetDomain, []byte{opCmdSetDomain}, 5); err != "" {
		t.Fatalf("setDomain(query) returned error %q", err)
	}
}

// 0x0b (setGateway) implemented. Same shape as 0x28: the branch's behaviour is
// set/clear/read-back of a global, so it is implementable even though the
// original's global holds a runtime-written string. The global itself
// (DAT_1e490968) is a real .data object, not a missing equivalent.
func TestSetGatewayIsImplemented(t *testing.T) {
	in := append([]byte{opCmdSetGateway}, []byte("10.0.0.1:443")...)
	if _, err := dispatchNativeCommand(1, opCmdSetGateway, in, 5); err != "" {
		t.Fatalf("setGateway(set) returned error %q", err)
	}
	if _, err := dispatchNativeCommand(1, opCmdSetGateway, []byte{opCmdSetGateway}, 5); err != "" {
		t.Fatalf("setGateway(query) returned error %q", err)
	}
}
