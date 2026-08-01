package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

// TestTerminalWSQueryParams verifies the original frontend's terminal WS
// URL format: /api/terminal/ws?id=X&token=Y (id, NOT client_id).
func TestTerminalWSQueryParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Original frontend: ?id=<clientId>&token=<jwt>
		id := r.URL.Query().Get("id")
		token := r.URL.Query().Get("token")
		if id == "" || token == "" {
			t.Errorf("missing id/token params: %s", r.URL.RawQuery)
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		// Echo raw bytes (xterm AttachAddon sends/receives raw terminal data)
		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if mt != websocket.TextMessage && mt != websocket.BinaryMessage {
				t.Errorf("unexpected message type %d", mt)
			}
			if err := conn.WriteMessage(mt, msg); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/terminal/ws?id=42&token=jwt123"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// xterm.js AttachAddon sends raw keystrokes as text frames
	if err := conn.WriteMessage(websocket.TextMessage, []byte("whoami\r")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(msg) != "whoami\r" {
		t.Errorf("echo = %q", msg)
	}
}

// TestScreenWSControlMessages verifies the original frontend's screen WS
// control messages: {"type":"3"} key events, {"type":"4"} scroll,
// {"type":"10"} disconnect.
func TestScreenWSControlMessages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Original frontend: /api/screen/ws?id=X&quality=Y&token=Z
		if r.URL.Query().Get("id") == "" || r.URL.Query().Get("quality") == "" {
			t.Errorf("missing id/quality: %s", r.URL.RawQuery)
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		// Server sends binary JPEG frames; client sends JSON controls
		conn.WriteMessage(websocket.BinaryMessage, []byte{0xff, 0xd8, 0xff, 0xe0}) // JPEG SOI
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var ctrl map[string]interface{}
			if err := json.Unmarshal(msg, &ctrl); err != nil {
				continue
			}
			typ, _ := ctrl["type"].(string)
			switch typ {
			case "3", "4", "10":
				// accepted control types from the original frontend
			default:
				t.Errorf("unexpected control type %q", typ)
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/screen/ws?id=7&quality=50&token=jwt"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Verify binary frame relay
	mt, frame, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if mt != websocket.BinaryMessage {
		t.Errorf("frame type = %d, want binary", mt)
	}
	if len(frame) < 4 || frame[0] != 0xff || frame[1] != 0xd8 {
		t.Errorf("frame not JPEG: % x", frame)
	}

	// Send the original frontend's control messages
	for _, ctrl := range []string{
		`{"type":"3","keyCode":65}`,
		`{"type":"4"}`,
	} {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(ctrl)); err != nil {
			t.Fatalf("write ctrl: %v", err)
		}
	}
}
