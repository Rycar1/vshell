package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAPILogoutUnauthenticated verifies that GET /api/logout succeeds even
// WITHOUT a token. The SPA calls this on every page load (pre-login too) to
// clear any stale session, so it must NOT be gated by ApiBaseController's auth
// check. Regression test for the 401 error the SPA logged on each load.
func TestAPILogoutUnauthenticated(t *testing.T) {
	mux := InitRouter()

	req := httptest.NewRequest(http.MethodGet, "/api/logout", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/api/logout status = %d, want %d; body=%q",
			rec.Code, http.StatusOK, rec.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("/api/logout returned non-JSON body %q: %v", rec.Body.String(), err)
	}
	if body["code"] != float64(0) {
		t.Fatalf("/api/logout code = %#v, want 0", body["code"])
	}
	if body["type"] != "success" {
		t.Fatalf("/api/logout type = %#v, want success", body["type"])
	}
}

// TestAPILogoutMethods verifies the SPA's logout is reached as GET and that
// the handler tolerates POST as well (some frontends swap methods).
func TestAPILogoutMethods(t *testing.T) {
	mux := InitRouter()
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(method, "/api/logout", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s /api/logout status = %d, want %d; body=%q",
				method, rec.Code, http.StatusOK, rec.Body.String())
		}
	}
}
