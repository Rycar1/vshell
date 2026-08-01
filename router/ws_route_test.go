package router

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"

	"vshell/utils"
)

// TestAPITerminalScreenWSRoutesUpgrade verifies that the SPA's WebSocket paths
// (/api/terminal/ws and /api/screen/ws) are served by the real WebSocket
// handlers (upgrade to 101), not the JSON-returning controller actions.
// Regression: the SPA dials /api/terminal/ws?id=X&token=Y as a WebSocket, but
// it was routed to TerminalController.WS()/ScreenController.Ws() which return a
// plain 200 JSON body — breaking the terminal and screen viewers.
func TestAPITerminalScreenWSRoutesUpgrade(t *testing.T) {
	mux := InitRouter()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tok, err := utils.GenerateToken("admin")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	wsBase := "ws" + strings.TrimPrefix(srv.URL, "http")
	cases := []struct {
		path string
	}{
		{"/api/terminal/ws?id=42&token=" + tok},
		{"/api/screen/ws?id=42&quality=50&token=" + tok},
	}

	for _, tc := range cases {
		conn, resp, err := websocket.DefaultDialer.Dial(wsBase+tc.path, nil)
		if err != nil {
			if resp != nil {
				t.Fatalf("%s dial failed (HTTP %d): %v", tc.path, resp.StatusCode, err)
			}
			t.Fatalf("%s dial failed: %v", tc.path, err)
		}
		conn.Close()
	}
}
