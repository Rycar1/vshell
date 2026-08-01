package controllers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestTerminalWSHandlerAcceptsOriginalURLFormat verifies the actual
// HandleTerminalWebSocket accepts the original frontend URL format
// /api/terminal/ws?id=42&token=jwt123.
func TestTerminalWSHandlerAcceptsOriginalURLFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(HandleTerminalWebSocket))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/terminal/ws?id=42&token=jwt123"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		if resp != nil {
			t.Fatalf("dial failed (HTTP %d): %v", resp.StatusCode, err)
		}
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	// Handler upgrades and (client 42 not online) runs local terminal.
	// Send a raw keystroke frame; the handler must stay connected (the local
	// shell may exit immediately on some platforms, which is also fine — the
	// point is that the WebSocket upgraded successfully).
	if err := conn.WriteMessage(websocket.TextMessage, []byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = conn.ReadMessage()
	if err == nil {
		// data received (local shell output) — fine
	} else if strings.Contains(err.Error(), "timeout") {
		// no output within deadline — fine
	} else if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
		// A connection reset after the local shell exits is acceptable on
		// platforms where the shell closes stdin immediately (e.g. Windows).
		if !strings.Contains(err.Error(), "reset") && !strings.Contains(err.Error(), "close") {
			t.Fatalf("unexpected read err: %v", err)
		}
	}
}

// TestScreenWSHandlerAcceptsOriginalURLFormat verifies HandleScreenWebSocket
// accepts /api/screen/ws?id=7&quality=50&token=jwt.
func TestScreenWSHandlerAcceptsOriginalURLFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(HandleScreenWebSocket))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/screen/ws?id=7&quality=50&token=jwt"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		if resp != nil {
			t.Fatalf("dial failed (HTTP %d): %v", resp.StatusCode, err)
		}
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	// Original frontend control messages must not kill the connection
	for _, ctrl := range []string{`{"type":"3","keyCode":65}`, `{"type":"4"}`, `{"type":"10"}`} {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(ctrl)); err != nil {
			t.Fatalf("write %s: %v", ctrl, err)
		}
	}
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, _, err = conn.ReadMessage()
	if err != nil && !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "close") {
		t.Fatalf("unexpected read err: %v", err)
	}
}
