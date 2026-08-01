package controllers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDashboardInfoHTTP(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard/info", nil)
	w := httptest.NewRecorder()
	dc := &DashboardController{}
	dc.Init(&Context{Request: req, ResponseWriter: w})
	dc.Prepare()
	dc.Get()

	body, _ := io.ReadAll(w.Result().Body)
	t.Logf("status=%d body=%q", w.Code, string(body))
	if w.Code != http.StatusOK || len(body) == 0 {
		t.Fatalf("empty/error response: %d %q", w.Code, string(body))
	}
}
