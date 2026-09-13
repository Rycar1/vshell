package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/beego/beego/v2/server/web/context"

	"vshell/c2engine"
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

// RunPlugin's platform selection matches the plugin name's extension
// (0x18edd80 compares the last 4 bytes against ".dll" / ".net" / ".exe"), and
// anything else falls through to the FUN_018fccc0 error branch.
func TestPluginKindByName(t *testing.T) {
	cases := []struct {
		name string
		kind pluginKind
		ok   bool
	}{
		{"payload.dll", pluginDll, true},
		{"PAYLOAD.DLL", pluginDll, true},
		{"Mimikatz.x64.exe", pluginExe, true},
		{"loader.net", pluginNet, true},
		{"loader.NET", pluginNet, true},
		{"libpayload.so", 0, false},
		{"payload.elf", 0, false},
		{"payload.dylib", 0, false},
		{"noextension", 0, false},
		{"", 0, false},
	}
	for _, tc := range cases {
		kind, ok := pluginKindByName(tc.name)
		if ok != tc.ok || (ok && kind != tc.kind) {
			t.Errorf("pluginKindByName(%q) = (%v, %v), want (%v, %v)",
				tc.name, kind, ok, tc.kind, tc.ok)
		}
	}

	// The selected kind maps back to the extension the original compares against
	// (0x1bd727d / 0x1bd7475 / 0x1bd72bd). This is metadata only — the dispatched
	// command carries plugin bytes, never the extension.
	if pluginDll.extension() != ".dll" || pluginNet.extension() != ".net" || pluginExe.extension() != ".exe" {
		t.Fatalf("extension mapping = %q/%q/%q",
			pluginDll.extension(), pluginNet.extension(), pluginExe.extension())
	}
}

// RunPlugin must not dispatch a command whose payload is not the plugin bytes.
// The original sends `runplugin <hex-of-plugin-bytes> <procArg> <true|false>`
// (FUN_018fd220 expands the selected file), and that byte source cannot be
// recovered controller-side, so the handler has to fail loudly instead of
// emitting a look-alike command (the project's "leave it unresolved" rule).
func TestRunPluginRefusesUnalignedPayload(t *testing.T) {
	initEngineStorage(t)
	engine := c2engine.GetEngine()
	client, err := engine.NewClient("runplugin-key", "http", "1.2.3.4:5", "", "u", "h", "windows", "agent", "amd64")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	client.Status = true
	t.Cleanup(func() { _ = engine.DelClient(client.ID) })

	body := `{"id":` + itoa(int(client.ID)) + `,"pluginName":"mimikatz.x64.exe","procArg":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/runner/runplugin", strings.NewReader(body))
	ctrl := &RunnerController{}
	rec := httptest.NewRecorder()
	ctrl.Controller.Ctx = context.NewContext()
	ctrl.Controller.Data = make(map[interface{}]interface{})
	ctrl.Controller.Ctx.Reset(rec, req)
	ctrl.Ctx.Input.RequestBody = []byte(body)

	ctrl.RunPlugin()

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("non-JSON response %q: %v", rec.Body.String(), err)
	}
	if resp["code"] != float64(-1) {
		t.Fatalf("RunPlugin = %#v, want a failure response (no unaligned dispatch)", resp)
	}
	// Whatever the failure is, it must not be a fabricated runplugin command:
	// no task may have been queued for this client.
	tasks := engine.GetAndMarkPendingTasks(client.ID)
	if len(tasks) != 0 {
		t.Fatalf("RunPlugin queued %d task(s) despite the unresolved payload: %+v", len(tasks), tasks)
	}
}

// The architecture comes off the client record; a client the engine does not
// know, or one with no arch recorded, must not select a platform plugin.
func TestEngineClientArch(t *testing.T) {
	if got := engineClientArch(nil); got != "" {
		t.Errorf("engineClientArch(nil) = %q, want empty", got)
	}
	if got := engineClientArch(&c2engine.Client{}); got != "" {
		t.Errorf("engineClientArch(no arch) = %q, want empty", got)
	}
	if got := engineClientArch(&c2engine.Client{Arch: "amd64"}); got != "amd64" {
		t.Errorf("engineClientArch = %q, want amd64", got)
	}
}
