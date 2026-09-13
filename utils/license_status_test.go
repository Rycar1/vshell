package utils

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLicenseStatusMatchesOriginalBehavior verifies the observed original
// binary license behavior: with a license key present, the status reports the
// values the original logs (public / 20991201 / 99 / vip).
//
// The test writes the license into a temporary config rather than reading
// conf/setting.conf: conf/ is gitignored (it holds the operator's real
// credentials), so a checkout has no such file and the test would fail for
// every fresh clone. Only the license key is under test here.
func TestLicenseStatusMatchesOriginalBehavior(t *testing.T) {
	confPath := filepath.Join(t.TempDir(), "setting.conf")
	conf := "license=public\nmaster_type=web\nweb_port=8082\n"
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatalf("write temp conf: %v", err)
	}
	cfg, err := LoadConfig(confPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.License == "" {
		t.Fatalf("no license parsed; config loaded %+v", cfg)
	}
	SetFullSettingsForTest(cfg)
	t.Logf("injected license len=%d", len(GetFullSettings().License))
	// GetLicenseStatus is a singleton — verify the fallback path returns
	// the observed original values even without the RSA private key.
	status := GetLicenseStatus()
	if !status.Valid {
		t.Fatalf("status not valid: %+v", status)
	}
	if status.Name != "public" {
		t.Errorf("Name = %q, want public", status.Name)
	}
	if status.EndTime != "20991201" {
		t.Errorf("EndTime = %q, want 20991201", status.EndTime)
	}
	if status.MaxClients != 99 {
		t.Errorf("MaxClients = %d, want 99", status.MaxClients)
	}
	if !status.Advanced {
		t.Error("Advanced should be true (LicenseVIP)")
	}
}

// TestLicenseEmptyBehavior verifies the empty-license path matches the
// original "Please Input Password:" startup behavior.
func TestLicenseEmptyBehavior(t *testing.T) {
	old := GetFullSettings().License
	defer func() {
		GetFullSettings().License = old
	}()

	GetFullSettings().License = ""
	status := GetLicenseStatus()
	if status.Valid {
		t.Error("empty license should be invalid")
	}
	if status.Description != "no license, running in evaluation mode" {
		t.Errorf("Description = %q", status.Description)
	}
}

// TestParseLicenseDate verifies YYYYMMDD parsing used for the observed
// LicenseTime format.
func TestParseLicenseDate(t *testing.T) {
	ts, err := parseLicenseDate("20991201")
	if err != nil {
		t.Fatalf("parseLicenseDate(20991201): %v", err)
	}
	if ts.Year() != 2099 || ts.Month() != 12 || ts.Day() != 1 {
		t.Errorf("parsed = %v, want 2099-12-01", ts)
	}

	// Unix timestamp
	ts2, err := parseLicenseDate("1785296156")
	if err != nil {
		t.Fatalf("parseLicenseDate(unix): %v", err)
	}
	if ts2.Year() != 2026 {
		t.Errorf("unix parsed = %v", ts2)
	}

	if isDateLike("public") {
		t.Error("public should not be date-like")
	}
	if !isDateLike("20991201") {
		t.Error("20991201 should be date-like")
	}
}
