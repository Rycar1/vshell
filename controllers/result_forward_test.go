package controllers

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestForwardStreamingScreenFrame verifies that a "screen_frame:…" result from
// an agent reaches the registered screen viewer as a raw binary frame.
func TestForwardStreamingScreenFrame(t *testing.T) {
	serverConn, clientConn, closeFn := testWSServer(t)
	defer closeFn()

	sv := StartScreenStream(60, serverConn, 50, 10)
	defer StopScreenStream(60, sv)

	// Build a screen_frame result payload.
	frame := []byte{0xff, 0xd8, 0xff, 0xe0, 0x01, 0xff, 0xd9}
	payload := "screen_frame:jpeg:1:" + base64.StdEncoding.EncodeToString(frame)

	forwardStreamingResultToViewers(60, payload)

	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	mt, got, err := clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if mt != websocket.BinaryMessage {
		t.Fatalf("message type = %d, want BinaryMessage", mt)
	}
	if len(got) != len(frame) || got[0] != 0xff || got[1] != 0xd8 {
		t.Errorf("frame = % x, want raw JPEG", got)
	}
}

// TestForwardStreamingTerminalOutput verifies that a "terminal_output:…"
// result reaches the remote-terminal WebSocket session for that client as a
// base64 "output" message.
func TestForwardStreamingTerminalOutput(t *testing.T) {
	serverConn, clientConn, closeFn := testWSServer(t)
	defer closeFn()

	ts := &WSTerminalSession{
		ID:       "wsterm_61_1",
		ClientID: 61,
		conn:     serverConn,
		done:     make(chan struct{}),
	}
	wsTermMu.Lock()
	wsTermSessions[ts.ID] = ts
	wsTermMu.Unlock()
	defer func() {
		wsTermMu.Lock()
		delete(wsTermSessions, ts.ID)
		wsTermMu.Unlock()
	}()

	payload := "terminal_output:" + base64.StdEncoding.EncodeToString([]byte("kali@host:~$ "))

	forwardStreamingResultToViewers(61, payload)

	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, msg, err := clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("read message: %v", err)
	}
	var out struct {
		Type string `json:"type"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(msg, &out); err != nil {
		t.Fatalf("non-JSON terminal message %q: %v", msg, err)
	}
	if out.Type != "output" {
		t.Fatalf("type = %q, want output", out.Type)
	}
	dec, err := base64.StdEncoding.DecodeString(out.Data)
	if err != nil {
		t.Fatalf("bad base64 data: %v", err)
	}
	if string(dec) != "kali@host:~$ " {
		t.Fatalf("decoded = %q, want %q", dec, "kali@host:~$ ")
	}
}
