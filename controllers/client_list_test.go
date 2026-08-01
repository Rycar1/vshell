package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"vshell/c2engine"
	"vshell/models"
	"vshell/utils"
)

// TestClientListMergesEngineClients verifies that agents which checked in via a
// C2 listener (present in the engine but not yet persisted to the models DB)
// appear in /api/client/list. Regression: the client page silently missed every
// live-checked-in agent because ClientController.Get() only read the models DB.
func TestClientListMergesEngineClients(t *testing.T) {
	if err := models.InitDB(t.TempDir() + "/test.db"); err != nil {
		t.Fatalf("init db: %v", err)
	}
	defer models.GetDB().Close()

	// Seed an engine-only client (the models DB has no such record).
	engine := c2engine.GetEngine()
	// Init sets up the engine's JSON storage; without it NewClient would panic
	// on a nil storage.
	if err := engine.Init(&c2engine.Config{DBPath: t.TempDir() + "/engine.json"}); err != nil {
		t.Fatalf("engine.Init: %v", err)
	}
	if _, err := engine.NewClient(
		"merge-test-vkey", "http", "9.9.9.9:5555",
		"10.0.0.9", "merge-user", "merge-host", "linux", "merge-agent",
	); err != nil {
		t.Fatalf("engine.NewClient: %v", err)
	}

	tok, err := utils.GenerateToken("admin")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/client/list", nil)
	req.Header.Set("Token", tok)
	rec := httptest.NewRecorder()

	cc := &ClientController{}
	(&ActionHandler{Ctrl: cc, Action: "List"}).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("client list status = %d, body=%q", rec.Code, rec.Body.String())
	}
	var resp struct {
		Result struct {
			ClientCount int `json:"clientCount"`
			Items       []struct {
				ID       int64  `json:"Id"`
				HostName string `json:"HostName"`
			} `json:"items"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("non-JSON: %v", err)
	}

	found := false
	for _, it := range resp.Result.Items {
		if it.HostName == "merge-host" {
			found = true
		}
	}
	if !found {
		t.Fatalf("engine client 'merge-host' missing from /api/client/list; items=%v",
			resp.Result.Items)
	}
}
