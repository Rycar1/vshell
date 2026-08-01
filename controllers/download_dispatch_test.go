package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"vshell/c2engine"
)

// TestDownloadActionsDispatch verifies that the DownloadController's agent
// generation actions (Stage/Stageless/Shellcode/Dll/Listen/ListenDll) are
// reached via the ActionHandler. Regression: these fell through to the default
// method-based dispatch (inherited no-op Post()), so POST /api/download/stageless
// returned an empty 200 body.
func TestDownloadActionsDispatch(t *testing.T) {
	dc := &DownloadController{}
	cases := []struct {
		action string
	}{
		{"Stageless"}, {"Dll"}, {"Listen"}, {"ListenDll"},
	}
	for _, tc := range cases {
		ah := &ActionHandler{Ctrl: dc, Action: tc.action}
		req := httptest.NewRequest(http.MethodPost, "/api/download/"+tc.action, nil)
		rec := httptest.NewRecorder()
		ah.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", tc.action, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Fatalf("%s returned an empty body", tc.action)
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s returned non-JSON body %q: %v", tc.action, rec.Body.String(), err)
		}
		if resp["code"] != float64(0) {
			t.Fatalf("%s code = %#v, want 0; body=%q", tc.action, resp["code"], rec.Body.String())
		}
	}
}

// TestDownloadStageModeRestriction verifies that Stage/Shellcode reject a
// non-TCP/WS listener with the documented "Stage support TCP/WS only" error.
func TestDownloadStageModeRestriction(t *testing.T) {
	dc := &DownloadController{}
	for _, action := range []string{"Stage", "Shellcode"} {
		ah := &ActionHandler{Ctrl: dc, Action: action}
		// listener id 0 => GetListener returns nil => mode check skipped;
		// use a real HTTP-mode listener registered in the engine to exercise
		// the restriction path.
		engine := c2engine.GetEngine()
		listener := engine.GetListener(2)
		if listener == nil || listener.Mode != "http" {
			t.Skip("test http listener (id 2) not present; skipping mode-restriction check")
		}
		req := httptest.NewRequest(http.MethodPost, "/api/download/"+action, nil)
		rec := httptest.NewRecorder()
		// Need a body with id=2 so the controller resolves the listener. Use
		// the query param path the controller also reads.
		req = httptest.NewRequest(http.MethodPost, "/api/download/"+action+"?id=2", nil)
		rec = httptest.NewRecorder()
		ah.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", action, rec.Code)
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s non-JSON: %q", action, rec.Body.String())
		}
		if resp["code"] != float64(-1) {
			t.Fatalf("%s code = %#v, want -1 (mode restriction)", action, resp["code"])
		}
	}
}
