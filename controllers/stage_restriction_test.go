package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"vshell/c2engine"
)

// TestStageRejectsNonTCPListener verifies the original binary's restriction:
// "Stage support TCP/WS only" (black-box captured from /api/download/stage).
func TestStageRejectsNonTCPListener(t *testing.T) {
	engine := c2engine.GetEngine()
	// Init storage so NewListener can persist
	engine.Init(&c2engine.Config{DBPath: t.TempDir() + "/data.db"})
	// Register an http-mode listener via the public API
	listener, err := engine.NewListener("127.0.0.1:9999", "", "http", "", "", "test-http")
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	_ = listener

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/download/stage?id=%d&arch=amd64", listener.ID), nil)
	w := httptest.NewRecorder()
	dc := &DownloadController{}
	dc.Init(&Context{Request: req, ResponseWriter: w})
	dc.Prepare()
	dc.Stage()

	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != -1 || resp.Message != "Stage support TCP/WS only" {
		t.Errorf("resp = %+v, want code:-1 Stage support TCP/WS only", resp)
	}
}

// TestStageAcceptsTCPListener verifies TCP-mode listeners pass the gate.
func TestStageAcceptsTCPListener(t *testing.T) {
	engine := c2engine.GetEngine()
	engine.Init(&c2engine.Config{DBPath: t.TempDir() + "/data.db"})
	listener, err := engine.NewListener("127.0.0.1:9998", "127.0.0.1:9998", "tcp", "", "", "test-tcp")
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	_ = listener

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/download/stage?id=%d&arch=amd64", listener.ID), nil)
	w := httptest.NewRecorder()
	dc := &DownloadController{}
	dc.Init(&Context{Request: req, ResponseWriter: w})
	dc.Prepare()
	dc.Stage()

	var resp struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Should NOT be the restriction error (template missing is fine)
	if resp.Code == -1 {
		var full struct {
			Message string `json:"message"`
		}
		json.Unmarshal(w.Body.Bytes(), &full)
		if full.Message == "Stage support TCP/WS only" {
			t.Errorf("tcp listener wrongly restricted: %s", w.Body.String())
		}
	}
}
