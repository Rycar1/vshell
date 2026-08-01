package controllers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGetStringJSONPascalCase verifies JSON body parameters are read with
// both snake_case and PascalCase keys (original frontend submits Go field
// names as JSON keys: {"Mode":"tcp","ListenAddr":"...","Vkey":"..."}).
func TestGetStringJSONPascalCase(t *testing.T) {
	body := `{"Mode":"tcp","ListenAddr":"127.0.0.1:8001","Vkey":"secret","EncryptSalt":"salt1","DisconnectTimeout":120}`
	req := httptest.NewRequest(http.MethodPost, "/api/listener/add", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	c := &BaseController{}
	c.Init(&Context{Request: req, ResponseWriter: httptest.NewRecorder()})
	c.Prepare()

	if v := c.GetString("mode"); v != "tcp" {
		t.Errorf("mode = %q, want tcp", v)
	}
	if v := c.GetString("listen_addr"); v != "127.0.0.1:8001" {
		t.Errorf("listen_addr = %q, want 127.0.0.1:8001", v)
	}
	if v := c.GetString("vkey"); v != "secret" {
		t.Errorf("vkey = %q, want secret", v)
	}
	if v, _ := c.GetInt("disconnect_timeout"); v != 120 {
		t.Errorf("disconnect_timeout = %d, want 120", v)
	}
}

// TestGetStringJSONBodyReusable verifies parseJSONBody still works after
// GetString consumed the JSON body (body cache must stay readable).
func TestGetStringJSONBodyReusable(t *testing.T) {
	body := `{"id":42,"remark":"hello"}`
	req := httptest.NewRequest(http.MethodPost, "/api/listener/edit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	c := &BaseController{}
	c.Init(&Context{Request: req, ResponseWriter: httptest.NewRecorder()})
	c.Prepare()

	// consume via GetString first
	_ = c.GetString("remark")

	// then parseJSONBody must still see the payload
	var parsed map[string]interface{}
	if !parseJSONBody(req, &parsed) {
		t.Fatal("parseJSONBody returned false after GetString consumed body")
	}
	if parsed["id"].(float64) != 42 {
		t.Errorf("id = %v, want 42", parsed["id"])
	}
	if parsed["remark"] != "hello" {
		t.Errorf("remark = %v, want hello", parsed["remark"])
	}
}
