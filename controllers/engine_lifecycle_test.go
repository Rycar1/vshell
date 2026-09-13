package controllers

import (
	"testing"

	"vshell/c2engine"
)

// initEngineStorage gives the engine singleton its storage handle — every
// writer path (NewListener / NewTunnel / CreateTask) persists, and a nil
// *Storage panics.
func initEngineStorage(t *testing.T) {
	t.Helper()
	if err := c2engine.GetEngine().Init(&c2engine.Config{DBPath: t.TempDir() + "/test.db"}); err != nil {
		t.Fatalf("engine init: %v", err)
	}
	t.Cleanup(func() { _ = c2engine.GetEngine().Close() })
}

// Add/Edit/Start/Stop must round-trip through the engine rather than being
// no-ops: the panel's listener page reads back Mode/Remark/Vkey after saving.
func TestEngineListenerLifecycle(t *testing.T) {
	initEngineStorage(t)

	if err := engineAddListener(EngineListener{
		Mode: "http", Vkey: "k1", Salt: "s1", Remark: "first",
	}); err != nil {
		t.Fatalf("add listener: %v", err)
	}
	list, _ := engineGetListenerList(0, 10, "", "", "", "", 0)
	if len(list) != 1 {
		t.Fatalf("listeners = %d, want 1", len(list))
	}
	id := list[0].ID

	if err := engineEditListener(EngineListener{ID: id, Mode: "https", Remark: "edited", Vkey: "k2"}); err != nil {
		t.Fatalf("edit listener: %v", err)
	}
	got := engineGetListener(id)
	if got == nil {
		t.Fatal("listener disappeared after edit")
	}
	if got.Mode != "https" || got.Remark != "edited" || got.Vkey != "k2" {
		t.Fatalf("after edit = %+v", got)
	}

	// Start/Stop flip the persisted status flag.
	engineStartListener(id)
	if l := c2engine.GetEngine().GetListener(id); l == nil || !l.Status {
		t.Fatalf("listener status after start = %+v", l)
	}
	engineStopListener(id)
	if l := c2engine.GetEngine().GetListener(id); l == nil || l.Status {
		t.Fatalf("listener status after stop = %+v", l)
	}

	engineDelListener(id)
	if l := engineGetListener(id); l != nil {
		t.Fatalf("listener still present after delete: %+v", l)
	}
}

// The tunnel editor must not silently drop edits, and port/target changes are
// only accepted while the tunnel is stopped.
func TestEngineTunnelEditRules(t *testing.T) {
	initEngineStorage(t)

	if err := engineAddTunnel(EngineTunnel{Port: 8080, Mode: "tcp", Target: "127.0.0.1:22", Remark: "r"}); err != nil {
		t.Fatalf("add tunnel: %v", err)
	}
	list, _ := engineGetTunnelList(0, 10, "", "", "", "")
	if len(list) != 1 {
		t.Fatalf("tunnels = %d, want 1", len(list))
	}
	id := list[0].ID

	if err := engineEditTunnel(EngineTunnel{ID: id, Remark: "renamed"}); err != nil {
		t.Fatalf("edit remark: %v", err)
	}
	if got := c2engine.GetEngine().GetTunnel(id); got.Remark != "renamed" {
		t.Fatalf("remark = %q, want renamed", got.Remark)
	}

	// Running tunnels keep their bound port/target.
	engineStartTunnel(id)
	if err := engineEditTunnel(EngineTunnel{ID: id, Port: 9090, Target: "10.0.0.1:80"}); err != nil {
		t.Fatalf("edit while running: %v", err)
	}
	if got := c2engine.GetEngine().GetTunnel(id); got.Port != 8080 || got.Target != "127.0.0.1:22" {
		t.Fatalf("running tunnel was rebound: %+v", got)
	}

	// Stopped tunnels accept the rebind.
	engineStopTunnel(id)
	if err := engineEditTunnel(EngineTunnel{ID: id, Port: 9090, Target: "10.0.0.1:80"}); err != nil {
		t.Fatalf("edit while stopped: %v", err)
	}
	if got := c2engine.GetEngine().GetTunnel(id); got.Port != 9090 || got.Target != "10.0.0.1:80" {
		t.Fatalf("stopped tunnel not rebound: %+v", got)
	}

	// Editing an unknown tunnel is an error, not a silent success.
	if err := engineEditTunnel(EngineTunnel{ID: id + 999, Remark: "x"}); err == nil {
		t.Fatal("editing an unknown tunnel returned nil")
	}
}

// Start/stop of an unknown listener must not panic (the panel can race a delete).
func TestEngineListenerUnknownIDIsSafe(t *testing.T) {
	initEngineStorage(t)
	engineStartListener(4242)
	engineStopListener(4242)
}

// Start must report a listener it cannot actually bring up, so the panel shows
// failures instead of a green "ok".
func TestEngineStartListenerReportsError(t *testing.T) {
	initEngineStorage(t)
	if err := engineStartListener(9999); err == nil {
		t.Fatal("starting an unknown listener returned nil")
	}
}
