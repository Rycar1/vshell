//go:build !server
// +build !server

package main

import (
	"encoding/base64"
	"testing"
	"time"
)

// TestTerminalSessionReuse verifies a terminal session can be started, closed,
// and started again. Regression for the waitOnce-lifetime bug where every
// session after the first was dead on arrival (the stale exit goroutine set
// active=false immediately after the new session started).
func TestTerminalSessionReuse(t *testing.T) {
	if _, errMsg := startTerminal("cmd", 24, 80, 1); errMsg != "" {
		t.Fatalf("first start: %s", errMsg)
	}
	terminalClose()

	if _, errMsg := startTerminal("cmd", 24, 80, 2); errMsg != "" {
		t.Fatalf("second start: %s", errMsg)
	}
	// The old bug: the first session's exit goroutine no-oped its consumed
	// sync.Once and immediately set active=false, killing the new session.
	time.Sleep(300 * time.Millisecond)
	termSess.mu.Lock()
	active := termSess.active
	termSess.mu.Unlock()
	if !active {
		t.Fatal("second terminal session is not active after start")
	}

	// Input must be accepted on the second session.
	if out, errMsg := terminalInput(base64.StdEncoding.EncodeToString([]byte("echo ok\r\n"))); errMsg != "" {
		t.Fatalf("second session input: %s", errMsg)
	} else if out != "ok" {
		t.Fatalf("second session input out = %q", out)
	}

	// Close and start a third time to confirm reuse is not one-time.
	terminalClose()
	if _, errMsg := startTerminal("cmd", 24, 80, 3); errMsg != "" {
		t.Fatalf("third start: %s", errMsg)
	}
	terminalClose()
}
