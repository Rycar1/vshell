package controllers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// testWSServer sets up a WebSocket pair and returns the SERVER-side conn
// (the one StartScreenStream should be given — writes to it flow to the
// client side) plus the CLIENT-side conn used for assertions.
func testWSServer(t *testing.T) (serverConn *websocket.Conn, clientConn *websocket.Conn, closeFn func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverCh <- conn
		// Keep the server connection open (does not consume frames).
		select {}
	}))

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	client, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		srv.Close()
		t.Fatalf("dial: %v", err)
	}
	server := <-serverCh
	return server, client, func() {
		client.Close()
		server.Close()
		srv.Close()
	}
}

// serverCh hands the upgraded server-side conn to the test.
var serverCh = make(chan *websocket.Conn, 1)

// TestRelayScreenFrameBinaryFormat verifies screen frames reach the viewer
// as RAW BINARY JPEG — the format the original frontend consumes
// (binaryType="arraybuffer", Blob type image/jpeg).
func TestRelayScreenFrameBinaryFormat(t *testing.T) {
	serverConn, clientConn, closeFn := testWSServer(t)
	defer closeFn()

	// Register the viewer deterministically with the SERVER-side conn.
	sv := StartScreenStream(55, serverConn, 50, 10)
	defer StopScreenStream(55, sv)
	if sv == nil {
		t.Fatal("StartScreenStream returned nil")
	}

	// Relay a JPEG frame (SOI FFD8 ... EOI FFD9)
	jpeg := []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0xff, 0xd9}
	RelayScreenFrame(55, jpeg, "jpeg", 1)

	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	mt, frame, err := clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if mt != websocket.BinaryMessage {
		t.Fatalf("message type = %d, want BinaryMessage (2)", mt)
	}
	if len(frame) != len(jpeg) || frame[0] != 0xff || frame[1] != 0xd8 {
		t.Errorf("frame = % x, want raw JPEG", frame)
	}
}

// TestRelayScreenFrameUnknownClient verifies frames to unknown clients are
// dropped without panic.
func TestRelayScreenFrameUnknownClient(t *testing.T) {
	RelayScreenFrame(99999, []byte{0xff, 0xd8}, "jpeg", 1)
	StopScreenStream(99999, nil)
}

// TestScreenStreamViewerLifecycle verifies StopScreenStream closes the
// viewer connection and subsequent relays are dropped.
func TestScreenStreamViewerLifecycle(t *testing.T) {
	serverConn, clientConn, closeFn := testWSServer(t)
	defer closeFn()

	sv := StartScreenStream(56, serverConn, 30, 10)
	StopScreenStream(56, sv)

	// After stop, frames are dropped silently
	RelayScreenFrame(56, []byte{0xff, 0xd8}, "jpeg", 2)

	// The connection should be closed by StopScreenStream
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err := clientConn.ReadMessage()
	if err == nil {
		t.Error("connection should be closed after StopScreenStream")
	}
}
