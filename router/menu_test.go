package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"vshell/utils"
)

// TestGetMenuListPathsMatchSPARoutes verifies that every path returned by
// /api/getMenuList (including download children) corresponds to a route the
// compiled SPA actually registers. Regression test: the menu previously
// advertised /client/index, /listener/index, /file/index, /tunnel/index,
// /plugin/index, /host/index and /download/shellcode — none of which exist in
// the SPA's static route modules (real routes are /client/list, /listener/list,
// /filemanager/index, /tunnel/list, /pluginrunner/index, etc.).
func TestGetMenuListPathsMatchSPARoutes(t *testing.T) {
	// Routes the compiled SPA registers (extracted from the embedded bundle).
	validRoutes := map[string]bool{
		"/dashboard/index":   true,
		"/client/list":       true,
		"/listener/list":     true,
		"/terminal/index":    true,
		"/filemanager/index": true,
		"/tunnel/list":       true,
		"/download/index":    true,
		"/download/stage":    true,
		"/download/stageless": true,
		"/download/listen":   true,
		"/download/ebpf":     true,
		"/pluginrunner/index": true,
		"/screenshot/index":  true,
		"/setting/index":     true,
		"/about/index":       true,
	}

	mux := InitRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/getMenuList", nil)
	// /api/getMenuList is protected; the SPA calls it with the Token header.
	tok, err := utils.GenerateToken("admin")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	req.Header.Set("Token", tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/api/getMenuList status = %d, want %d; body=%q",
			rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp struct {
		Code   int                      `json:"code"`
		Result []map[string]interface{} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("/api/getMenuList non-JSON body %q: %v", rec.Body.String(), err)
	}
	if resp.Code != 0 {
		t.Fatalf("/api/getMenuList code = %d, want 0", resp.Code)
	}
	if len(resp.Result) == 0 {
		t.Fatal("/api/getMenuList returned empty result")
	}

	var checkItem func(map[string]interface{})
	checkItem = func(item map[string]interface{}) {
		path, _ := item["path"].(string)
		if path == "" {
			t.Errorf("menu item missing path: %v", item)
			return
		}
		if !validRoutes[path] {
			t.Errorf("menu path %q is not a registered SPA route", path)
		}
		if children, ok := item["children"].([]interface{}); ok {
			for _, c := range children {
				cm, _ := c.(map[string]interface{})
				checkItem(cm)
			}
		}
	}

	for _, item := range resp.Result {
		checkItem(item)
	}
}
