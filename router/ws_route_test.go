package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"vshell/utils"
)

// TestAPITerminalScreenWSAuth verifies the SPA's WebSocket paths
// (/api/terminal/ws and /api/screen/ws) are gated by ApiBaseController.Prepare:
// no token → HTTP 401 (matching the original binary's auth flow); with a valid
// JWT token the request passes auth (the handler itself is the engine-phase
// WebSocket bridge, so no upgrade assertion is made here).
func TestAPITerminalScreenWSAuth(t *testing.T) {
	mux := InitRouter()

	for _, path := range []string{"/api/terminal/ws?id=42", "/api/screen/ws?id=42&quality=50"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without token = %d, want 401", path, rec.Code)
		}

		tok, err := utils.GenerateToken("admin")
		if err != nil {
			t.Fatalf("generate token: %v", err)
		}
		req2 := httptest.NewRequest(http.MethodGet, path+"&token="+tok, nil)
		rec2 := httptest.NewRecorder()
		mux.ServeHTTP(rec2, req2)
		if rec2.Code == http.StatusUnauthorized {
			t.Errorf("%s with valid token = 401, want non-401", path)
		}
	}
}
