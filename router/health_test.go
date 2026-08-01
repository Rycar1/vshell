package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthEndpointsReturnOK(t *testing.T) {
	mux := InitRouter()

	for _, path := range []string{"/health", "/api/health"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want %d; body=%q", path, rec.Code, http.StatusOK, rec.Body.String())
		}
		var body map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s returned non-JSON body %q: %v", path, rec.Body.String(), err)
		}
		if body["status"] != "ok" {
			t.Fatalf("%s status field = %#v, want ok", path, body["status"])
		}
		if _, ok := body["system"].(map[string]interface{}); !ok {
			t.Fatalf("%s missing system object: %#v", path, body)
		}
	}
}
