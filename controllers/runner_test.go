package controllers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Uploaded plugins must land in ./plugins under their own name, and the list
// endpoint must then report them.
func TestEngineSavePluginRoundTrip(t *testing.T) {
	// Run from a temp dir so the relative ./plugins path is isolated.
	wd, _ := os.Getwd()
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	if err := engineSavePlugin("payload.dll", strings.NewReader("MZ-plugin")); err != nil {
		t.Fatalf("save plugin: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(pluginsDir, "payload.dll"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != "MZ-plugin" {
		t.Fatalf("contents = %q", data)
	}

	list := engineListPlugins()
	if len(list) != 1 || list[0]["name"] != "payload.dll" {
		t.Fatalf("list = %+v, want one entry named payload.dll", list)
	}
}

// The uploaded filename comes from the HTTP request and must not be able to
// escape the plugin directory.
func TestEngineSavePluginRejectsTraversal(t *testing.T) {
	wd, _ := os.Getwd()
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	for _, name := range []string{"../escape.dll", `..\escape.dll`, "", "."} {
		if err := engineSavePlugin(name, strings.NewReader("x")); err == nil {
			// A traversal name that survives filepath.Base is contained under
			// plugins/, so reaching here is only acceptable if nothing escaped.
			if _, err := os.Stat(filepath.Join(dir, "escape.dll")); err == nil {
				t.Fatalf("name %q escaped the plugin directory", name)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "escape.dll")); err == nil {
		t.Fatal("a plugin was written outside ./plugins")
	}
}
