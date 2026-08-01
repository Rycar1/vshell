package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestRunnerListReturnsPluginDirectory verifies /api/runner/list returns the
// plugins directory listing as [{id,name}] — matching the original binary's
// response consumed by the original frontend's ApiSelect (resultField:"result",
// labelField:"name", valueField:"name").
func TestRunnerListReturnsPluginDirectory(t *testing.T) {
	// Isolate: create a temp working dir containing a plugins/ subdir with
	// known files, then chdir into it (the runner reads "plugins" relative to cwd).
	tmp := t.TempDir()
	pluginsDir := filepath.Join(tmp, "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"AddUser.dll", "fscan.x64.elf", "gost.x64.exe"} {
		if err := os.WriteFile(filepath.Join(pluginsDir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)

	req := httptest.NewRequest(http.MethodGet, "/api/runner/list", nil)
	w := httptest.NewRecorder()
	rc := &RunnerController{}
	rc.Init(&Context{Request: req, ResponseWriter: w})
	rc.Prepare()
	rc.List()

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp struct {
		Code   int                      `json:"code"`
		Result []map[string]interface{} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != 0 {
		t.Fatalf("code = %d, want 0: %s", resp.Code, w.Body.String())
	}
	if len(resp.Result) != 3 {
		t.Fatalf("result len = %d, want 3: %s", len(resp.Result), w.Body.String())
	}
	names := map[string]bool{}
	for _, item := range resp.Result {
		if _, ok := item["id"]; !ok {
			t.Errorf("item missing id: %v", item)
		}
		n, _ := item["name"].(string)
		names[n] = true
	}
	for _, want := range []string{"AddUser.dll", "fscan.x64.elf", "gost.x64.exe"} {
		if !names[want] {
			t.Errorf("missing plugin %q in result: %v", want, resp.Result)
		}
	}
}

// TestRunnerListEmptyPluginsDir verifies a missing plugins dir yields [] not an error.
func TestRunnerListEmptyPluginsDir(t *testing.T) {
	tmp := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)

	req := httptest.NewRequest(http.MethodGet, "/api/runner/list", nil)
	w := httptest.NewRecorder()
	rc := &RunnerController{}
	rc.Init(&Context{Request: req, ResponseWriter: w})
	rc.Prepare()
	rc.List()

	var resp struct {
		Code   int                      `json:"code"`
		Result []map[string]interface{} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != 0 {
		t.Fatalf("code = %d, want 0: %s", resp.Code, w.Body.String())
	}
	if len(resp.Result) != 0 {
		t.Fatalf("result len = %d, want 0: %s", len(resp.Result), w.Body.String())
	}
}
