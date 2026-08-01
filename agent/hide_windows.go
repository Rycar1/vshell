//go:build windows

// hide_windows.go：Windows 平台下隐藏子进程窗口（通过 SysProcAttr.HideWindow）。
// hide_windows.go: hides subprocess windows on Windows via SysProcAttr.HideWindow.
package main

import (
	"os/exec"
	"syscall"
)

// hideCmdWindow 在 Windows 上隐藏子进程的命令行窗口。
// hideCmdWindow hides the subprocess command window on Windows.
func hideCmdWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
}
