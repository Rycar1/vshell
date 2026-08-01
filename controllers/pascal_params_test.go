package controllers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestGetStringPascalCaseFallback verifies the original binary's PascalCase
// form parameter names are accepted alongside snake_case ones.
func TestGetStringPascalCaseFallback(t *testing.T) {
	form := url.Values{}
	form.Set("Mode", "tcp")
	form.Set("ListenAddr", "127.0.0.1:8001")
	form.Set("Vkey", "secret")
	form.Set("EncryptSalt", "salt1")
	form.Set("DisconnectTimeout", "120")
	req := httptest.NewRequest(http.MethodPost, "/api/listener/add", nil)
	req.PostForm = form
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	c := &BaseController{}
	c.Init(&Context{Request: req, ResponseWriter: httptest.NewRecorder()})
	c.Prepare()

	if v := c.GetString("mode"); v != "tcp" {
		t.Errorf("mode = %q, want tcp (PascalCase fallback)", v)
	}
	if v := c.GetString("listen_addr"); v != "127.0.0.1:8001" {
		t.Errorf("listen_addr = %q, want 127.0.0.1:8001", v)
	}
	if v := c.GetString("vkey"); v != "secret" {
		t.Errorf("vkey = %q, want secret", v)
	}
	if v := c.GetString("encrypt_salt"); v != "salt1" {
		t.Errorf("encrypt_salt = %q, want salt1", v)
	}
	if v, _ := c.GetInt("disconnect_timeout"); v != 120 {
		t.Errorf("disconnect_timeout = %d, want 120", v)
	}
	// snake_case still works
	if v := c.GetString("no_such_key", "default"); v != "default" {
		t.Errorf("default not applied: %q", v)
	}
}
