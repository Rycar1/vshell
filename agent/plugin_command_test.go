//go:build !server
// +build !server

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 插件（runplugin）命令的解析与「绝不落进 shell」测试。
//
// 依据：原版 FUN_01152dc0 / FUN_01153100 / FUN_011541e0（见 agent/main.go 的
// 「Plugin / runner」一节）。命令文本 = `runplugin <hex> <procArg> <true|false>`，
// 形状来自控制器侧 RunPlugin 的拼装。

func TestParsePluginCommandShape(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantOK  bool
		wantHex string
		wantArg string
		wantNet bool
	}{
		{
			name:    "普通插件",
			in:      "runplugin deadbeef 1.2.3.4 false",
			wantOK:  true,
			wantHex: "deadbeef",
			wantArg: "1.2.3.4",
			wantNet: false,
		},
		{
			name:    ".net 插件（末位 true）",
			in:      "runplugin 00ff10 --pipe true",
			wantOK:  true,
			wantHex: "00ff10",
			wantArg: "--pipe",
			wantNet: true,
		},
		{
			name:    "procArg 含空格（原版不加引号，原样拼接）",
			in:      "runplugin ab a b c false",
			wantOK:  true,
			wantHex: "ab",
			wantArg: "a b c",
			wantNet: false,
		},
		{
			name:    "大写十六进制也可（原版只生成小写，但解析不挑）",
			in:      "runplugin DEADBEEF arg false",
			wantOK:  true,
			wantHex: "DEADBEEF",
			wantArg: "arg",
		},
		{name: "缺布尔位", in: "runplugin deadbeef 1.2.3.4"},
		{name: "布尔位非法", in: "runplugin deadbeef 1.2.3.4 1"},
		{name: "缺 procArg", in: "runplugin deadbeef false"},
		{name: "空载荷", in: "runplugin  1.2.3.4 false"},
		{name: "奇数长度十六进制", in: "runplugin abc 1.2.3.4 false"},
		{name: "非十六进制", in: "runplugin zz 1.2.3.4 false"},
		{name: "命令字前缀相似但不同", in: "runplugins deadbeef a false"},
		{name: "不是本命令", in: "whoami"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, reason := parsePluginCommand(tc.in)
			if !tc.wantOK {
				if cmd != nil {
					t.Fatalf("应拒绝，得到 %+v", cmd)
				}
				if reason == "" {
					t.Fatal("拒绝时必须给出原因")
				}
				return
			}
			if cmd == nil {
				t.Fatalf("应接受，原因 = %q", reason)
			}
			if cmd.Hex != tc.wantHex || cmd.ProcArg != tc.wantArg || cmd.IsNet != tc.wantNet {
				t.Fatalf("解析 = %+v, want hex=%q arg=%q net=%v",
					cmd, tc.wantHex, tc.wantArg, tc.wantNet)
			}
		})
	}
}

// TestDispatchPluginCommandRefuses 确认形状合法时也是「明确拒绝」，而不是
// 伪造成功或走别的路径。
func TestDispatchPluginCommandRefuses(t *testing.T) {
	out, errMsg := dispatchPluginCommand("runplugin deadbeef 1.2.3.4 false")
	if errMsg == "" {
		t.Fatal("插件执行未恢复，必须返回错误而不是成功")
	}
	if !strings.Contains(errMsg, "not implemented") {
		t.Fatalf("错误信息应说明未实现，得到 %q", errMsg)
	}
	if !strings.Contains(errMsg, "4 bytes") {
		t.Fatalf("错误信息应报出解析到的载荷长度（4 字节），得到 %q", errMsg)
	}
	if out != "" {
		t.Fatalf("拒绝时不应有输出，得到 %q", out)
	}
}

// TestRunpluginNeverReachesShell 是本任务的核心断言：runplugin 命令绝不能落进
// runCommand（/bin/sh -c 或 cmd.exe /C）。
//
// 手法：在命令尾部附加 shell 重定向 `> <marker>`，并让插件解析器因此拒绝它。
// 如果这段文本被交给 shell，重定向会在命令查找之前执行，marker 文件必然被创建
// （POSIX sh 与 cmd.exe 皆然）；新路径下 marker 不会出现。
func TestRunpluginNeverReachesShell(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "shell_ran_marker")

	cmdStr := "runplugin deadbeef 1.2.3.4 false > " + marker
	_, errMsg := executeCommand(1, cmdStr, 5)

	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("runplugin 命令被交给了 shell（marker 已创建）：%s", marker)
	}
	if !strings.Contains(errMsg, "runplugin") {
		t.Fatalf("错误信息应来自插件解析器，得到 %q", errMsg)
	}
}

// TestUnknownCommandTypeDoesNotReachShell 覆盖 JSON 信封：未知 type 必须明确
// 失败，而不是把整个命令串丢给 shell。
func TestUnknownCommandTypeDoesNotReachShell(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "unknown_marker")

	// 未知 type：即使 payload 里带有 shell 片段，也不能被执行。
	// 用 json.Marshal 生成信封，避免 Windows 路径的反斜杠破坏 JSON 转义。
	envelope, err := json.Marshal(map[string]string{
		"type":    "definitely_not_a_command",
		"command": "touch " + marker,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, errMsg := executeCommand(1, string(envelope), 5)
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("未知命令类型被交给了 shell（marker 已创建）：%s", marker)
	}
	if !strings.Contains(errMsg, "unknown command type") {
		t.Fatalf("错误信息应为未知命令类型，得到 %q", errMsg)
	}
}

// TestRunpluginInsideShellEnvelopeStillRefused 确认服务器把插件命令包进
// {"type":"shell","command":"…"} 时同样不会被执行。
func TestRunpluginInsideShellEnvelopeStillRefused(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "envelope_marker")

	cmd := "runplugin deadbeef 1.2.3.4 false > " + marker
	envelope, err := json.Marshal(map[string]string{"type": "shell", "command": cmd})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, errMsg := executeCommand(1, string(envelope), 5)
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("shell 信封里的 runplugin 被交给了 shell：%s", marker)
	}
	if !strings.Contains(errMsg, "runplugin") {
		t.Fatalf("错误信息应来自插件解析器，得到 %q", errMsg)
	}
}

// TestPlainShellCommandStillRuns 确认修复没有误伤：显式 {"type":"shell"} 与
// 自由文本仍然照常执行（终端/屏幕中继与既有面板命令依赖这条路径）。
func TestPlainShellCommandStillRuns(t *testing.T) {
	envelope, err := json.Marshal(map[string]string{"type": "shell", "command": "echo vshell-ok"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, errMsg := executeCommand(1, string(envelope), 10)
	if errMsg != "" {
		t.Fatalf("普通 shell 命令不应失败：%q", errMsg)
	}
	if !strings.Contains(out, "vshell-ok") {
		t.Fatalf("普通 shell 命令输出异常：%q", out)
	}
}
