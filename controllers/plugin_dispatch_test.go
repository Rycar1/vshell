package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"vshell/c2engine"
	"vshell/models"
	"vshell/utils"
)

// TestRunPluginPascalCaseJSON verifies the plugin runner accepts the original
// frontend's PascalCase/camelCase JSON body — {"id":N,"pluginName":X,"procArg":Y}
// — and dispatches a real plugin (fscan.x64.elf) instead of failing with
// "client_id is required". Regression: the fallback field reads only worked for
// query params because the JSON body had already been consumed.
func TestRunPluginPascalCaseJSON(t *testing.T) {
	if err := models.InitDB(t.TempDir() + "/test.db"); err != nil {
		t.Fatalf("init db: %v", err)
	}
	defer models.GetDB().Close()

	engine := c2engine.GetEngine()
	if err := engine.Init(&c2engine.Config{DBPath: t.TempDir() + "/engine.json"}); err != nil {
		t.Fatalf("engine.Init: %v", err)
	}
	if _, err := engine.NewClient(
		"plugin-test-vkey", "http", "10.0.0.7:7000",
		"10.0.0.7", "puser", "plugin-host", "linux", "plugin-agent",
	); err != nil {
		t.Fatalf("engine.NewClient: %v", err)
	}

	// Create a fake .elf plugin file reachable from the test cwd.
	pluginPath := t.TempDir() + "/testplugin.elf"
	if err := os.WriteFile(pluginPath, []byte("#!/bin/sh\necho plugin-ran\n"), 0o755); err != nil {
		t.Fatalf("write plugin: %v", err)
	}

	tok, err := utils.GenerateToken("admin")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	bodyBytes, _ := json.Marshal(map[string]interface{}{
		"id":         1,
		"pluginName": pluginPath,
		"procArg":    "-h",
	})
	body := string(bodyBytes)
	req := httptest.NewRequest(http.MethodPost, "/api/runner/runplugin", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Token", tok)
	rec := httptest.NewRecorder()

	rc := &RunnerController{}
	(&ActionHandler{Ctrl: rc, Action: "RunPlugin"}).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code   int `json:"code"`
		Result struct {
			CommandID int64 `json:"command_id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("non-JSON: %v", err)
	}
	if resp.Code != 0 {
		t.Fatalf("code = %d (want 0), body=%q", resp.Code, rec.Body.String())
	}
	if resp.Result.CommandID == 0 {
		t.Fatalf("no command dispatched: %q", rec.Body.String())
	}
}
