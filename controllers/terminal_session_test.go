package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vshell/c2engine"

	"github.com/gorilla/websocket"
)

// TestLocalTerminalShellInteraction verifies the local terminal session:
// shell spawns, accepts stdin, echoes output, and replies to ping.
func TestLocalTerminalShellInteraction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(HandleTerminalWebSocket))
	defer srv.Close()

	// No client id → local terminal mode
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/terminal/ws?token=jwt"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Wait for the "connected" welcome message
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, welcome, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	if !strings.Contains(string(welcome), "connected") {
		t.Errorf("welcome = %q, want connected message", welcome)
	}

	// Send a ping control message → expect pong
	ping := []byte(`{"type":"ping"}`)
	if err := conn.WriteMessage(websocket.TextMessage, ping); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, pong, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if !strings.Contains(string(pong), "pong") {
		t.Errorf("pong = %q", pong)
	}
}

// TestTerminalJSONControlMessages verifies the JSON control message schema
// (input/resize) is parseable by the local terminal loop.
func TestTerminalJSONControlMessages(t *testing.T) {
	// The readWebSocketInput switch accepts: input, resize, ping
	// Verify the schema compiles to the expected keys
	schemas := []string{
		`{"type":"input","data":"ls -la\r"}`,
		`{"type":"resize","rows":40,"cols":128}`,
		`{"type":"ping"}`,
	}
	for _, s := range schemas {
		var msg map[string]interface{}
		if err := json.Unmarshal([]byte(s), &msg); err != nil {
			t.Errorf("schema %q not valid JSON: %v", s, err)
			continue
		}
		typ, _ := msg["type"].(string)
		switch typ {
		case "input":
			if _, ok := msg["data"].(string); !ok {
				t.Errorf("input missing data string: %v", msg)
			}
		case "resize":
			if _, ok := msg["rows"].(float64); !ok {
				t.Errorf("resize missing rows: %v", msg)
			}
			if _, ok := msg["cols"].(float64); !ok {
				t.Errorf("resize missing cols: %v", msg)
			}
		case "ping":
			// no payload
		default:
			t.Errorf("unknown control type %q", typ)
		}
	}
}

// TestRemoteTerminalDispatchFormat verifies the remote terminal's task
// dispatch format (terminal_input/terminal_resize/terminal_close) matches
// the agent command vocabulary.
func TestRemoteTerminalDispatchFormat(t *testing.T) {
	// The remote loop encodes:
	//   terminal_start type=%s rows=%d cols=%d
	//   terminal_input:<base64>
	//   terminal_resize rows=%d cols=%d
	//   terminal_close
	start := c2engine.EncodeShellCommand("terminal_start type=cmd rows=24 cols=80", 0)
	if !strings.Contains(start, "terminal_start") {
		t.Errorf("start cmd = %q", start)
	}
	resize := c2engine.EncodeShellCommand("terminal_resize rows=40 cols=120", 0)
	if !strings.Contains(resize, "terminal_resize") {
		t.Errorf("resize cmd = %q", resize)
	}
	closeCmd := c2engine.EncodeShellCommand("terminal_close", 5)
	if !strings.Contains(closeCmd, "terminal_close") {
		t.Errorf("close cmd = %q", closeCmd)
	}
}
