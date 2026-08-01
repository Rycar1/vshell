//go:build !windows

// hide_other.go：非 Windows 平台下的隐藏窗口占位实现。
// hide_other.go: no-op implementation for hiding windows on non-Windows platforms.
package main

import "os/exec"

// hideCmdWindow 在非 Windows 平台为空操作。
// hideCmdWindow is a no-op on non-Windows platforms.
func hideCmdWindow(cmd *exec.Cmd) {
	// No-op on non-Windows platforms
}
