package c2engine

import "testing"

// The agent reports its architecture at check-in (agent main.Checkin sets Arch
// from runtime.GOARCH). RunPlugin needs it to pick the platform plugin
// (FUN_0164bde0 classifies 0="386" / 1="amd64"), so losing it silently made
// client.Arch permanently empty and every plugin dispatch fail.
func TestCheckinCarriesClientArch(t *testing.T) {
	// NewClient persists through the engine's storage, so it must be a live
	// handle, not a nil *Storage (which panics on the first write).
	e := GetEngine()
	if err := e.Init(&Config{DBPath: t.TempDir() + "/test.db"}); err != nil {
		t.Fatalf("engine init: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })

	c, err := e.NewClient("vk", "http", "1.2.3.4:5", "", "u", "h", "linux", "agent", "amd64")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.Arch != "amd64" {
		t.Fatalf("Arch = %q, want amd64", c.Arch)
	}

	// A re-check-in that reports a different arch must refresh it (an agent can
	// be rebuilt for another platform), while a check-in that omits the field
	// (empty arch) must not wipe the known value.
	if _, err := e.NewClient("vk", "http", "1.2.3.4:5", "", "u", "h", "linux", "agent", "386"); err != nil {
		t.Fatalf("re-checkin: %v", err)
	}
	if c.Arch != "386" {
		t.Fatalf("Arch after re-checkin = %q, want 386", c.Arch)
	}
	if _, err := e.NewClient("vk", "http", "1.2.3.4:5", "", "u", "h", "linux", "agent", ""); err != nil {
		t.Fatalf("re-checkin without arch: %v", err)
	}
	if c.Arch != "386" {
		t.Fatalf("Arch after empty-arch checkin = %q, want 386 (must not be wiped)", c.Arch)
	}
}
