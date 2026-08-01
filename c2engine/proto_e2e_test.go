package c2engine

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestProtocolEncodeDecodeRoundTrip verifies the full message pipeline:
// JSON → AES-GCM encrypt → base64 → decode → decrypt → JSON, and the
// gzip compression round trip.
func TestProtocolEncodeDecodeRoundTrip(t *testing.T) {
	key := DeriveKey("testsalt", "testvkey")
	if len(key) != 32 {
		t.Fatalf("DeriveKey len = %d, want 32", len(key))
	}

	msg := CheckinRequest{
		VerifyKey:   "testvkey",
		HostName:    "host1",
		UserName:    "user1",
		OsName:      "windows",
		ProcessName: "agent.exe",
		LocalIP:     "10.0.0.1",
	}

	// Encrypt path
	enc, err := EncodeMessage(msg, key)
	if err != nil {
		t.Fatalf("EncodeMessage: %v", err)
	}
	// Must be base64 of AES-GCM (nonce + ciphertext)
	raw, err := base64.StdEncoding.DecodeString(string(enc))
	if err != nil {
		t.Fatalf("payload not base64: %v", err)
	}
	if len(raw) < 12+16 {
		t.Fatalf("ciphertext too short: %d", len(raw))
	}

	// Decrypt path
	var decoded CheckinRequest
	if err := DecodeMessage(enc, &decoded, key); err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if decoded.VerifyKey != "testvkey" || decoded.HostName != "host1" || decoded.OsName != "windows" {
		t.Errorf("decoded mismatch: %+v", decoded)
	}

	// Wrong key must fail
	var bad CheckinRequest
	if err := DecodeMessage(enc, &bad, DeriveKey("wrongsalt", "wrongvkey")); err == nil {
		t.Error("DecodeMessage with wrong key should fail")
	}
}

// TestProtocolCompressionRoundTrip verifies gzip compress/decompress.
func TestProtocolCompressionRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte("hello vshell "), 1000)
	compressed, err := CompressPayload(payload)
	if err != nil {
		t.Fatalf("CompressPayload: %v", err)
	}
	if len(compressed) >= len(payload) {
		t.Errorf("compressed (%d) not smaller than original (%d)", len(compressed), len(payload))
	}
	decompressed, err := DecompressPayload(compressed)
	if err != nil {
		t.Fatalf("DecompressPayload: %v", err)
	}
	if !bytes.Equal(decompressed, payload) {
		t.Error("decompressed payload mismatch")
	}
}

// TestProtocolXorObfuscation verifies XOR encode/decode symmetry.
func TestProtocolXorObfuscation(t *testing.T) {
	payload := []byte("agent binary payload 12345")
	key := byte(0xAA)
	encoded := XorEncode(payload, key)
	if bytes.Equal(encoded, payload) {
		t.Error("XorEncode should change the payload")
	}
	decoded := XorEncode(encoded, key)
	if !bytes.Equal(decoded, payload) {
		t.Error("XorEncode round trip failed")
	}

	multi := []byte("multi-key-42")
	enc2 := XorEncodeWithKey(payload, multi)
	dec2 := XorEncodeWithKey(enc2, multi)
	if !bytes.Equal(dec2, payload) {
		t.Error("XorEncodeWithKey round trip failed")
	}
}

// TestProtocolHTTPCheckinFlow verifies the full HTTP checkin → task poll →
// result flow against the open-source listener handlers.
func TestProtocolHTTPCheckinFlow(t *testing.T) {
	// Build a listener config with salt+vkey
	cfg := &Config{DBPath: "db/data.db"}
	e := GetEngine()
	e.Init(cfg)

	listener := &Listener{
		ID:          99,
		Status:      true,
		ListenAddr:  "127.0.0.1:0",
		Mode:        "http",
		VerifyKey:   "e2e-vkey",
		EncryptSalt: "e2e-salt",
	}
	// The checkin handler resolves the listener via the engine registry.
	e.listeners[99] = listener
	cl := NewC2Listener(listener)

	// 1. Encrypted checkin
	key := DeriveKey(listener.EncryptSalt, listener.VerifyKey)
	checkin := CheckinRequest{
		VerifyKey:   "e2e-vkey",
		HostName:    "e2e-host",
		UserName:    "e2e-user",
		OsName:      "linux",
		ProcessName: "agent",
		LocalIP:     "192.168.1.10",
	}
	body, _ := EncodeMessage(checkin, key)

	req := httptest.NewRequest(http.MethodPost, "/api/checkin", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.10:5555"
	w := httptest.NewRecorder()
	cl.handleCheckin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("checkin status = %d: %s", w.Code, w.Body.String())
	}
	var resp CheckinResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("checkin resp: %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("checkin status = %q: %s", resp.Status, w.Body.String())
	}
	if resp.ClientID == 0 {
		t.Fatal("checkin should assign a client id")
	}

	// 2. Poll tasks (verify key required since the listener has one set)
	req2 := httptest.NewRequest(http.MethodGet, "/api/tasks?client_id="+int64ToString(resp.ClientID)+"&verify_key=e2e-vkey", nil)
	w2 := httptest.NewRecorder()
	cl.handleGetTasks(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("tasks status = %d", w2.Code)
	}
	var taskResp TaskResponse
	if err := json.Unmarshal(w2.Body.Bytes(), &taskResp); err != nil {
		t.Fatalf("tasks resp: %v", err)
	}

	// 3. Submit a result (verify key required since the listener has one set)
	result := ResultRequest{
		ClientID:  resp.ClientID,
		CommandID: 1,
		Result:    "command output",
		Status:    "completed",
		VerifyKey: "e2e-vkey",
	}
	resultBody, _ := json.Marshal(result)
	req3 := httptest.NewRequest(http.MethodPost, "/api/result", bytes.NewReader(resultBody))
	w3 := httptest.NewRecorder()
	cl.handlePostResult(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("result status = %d", w3.Code)
	}
}

func int64ToString(v int64) string {
	return fmt.Sprintf("%d", v)
}
