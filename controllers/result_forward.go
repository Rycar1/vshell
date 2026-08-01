package controllers

import (
	"encoding/base64"
	"strings"

	"vshell/c2engine"
)

func init() {
	// The listener's result handler cannot import controllers (import cycle),
	// so it delegates streaming results here via a hook registered at init.
	c2engine.SetResultForwardHook(forwardStreamingResultToViewers)
}

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
