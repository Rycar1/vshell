package utils

import (
	"os"
	"testing"
)

func TestParseConfigFile(t *testing.T) {
	// Simulate the original setting.conf content
	content := `# License授权
license=TEST_LICENSE_BASE64_STRING
# 控制端模式
master_type=web
# web
web_title=管理平台
web_port=8082
web_ip=0.0.0.0
web_basic_auth=true
web_jwt_secret=
web_username=admin
web_password=test-password-123
# web ssl
web_open_ssl=false
web_cert_file=conf/server.pem
web_key_file=conf/server.key
# dingding robot
dingding_access_token=
dingding_key_word=
# wechat robot
wx_key=
# log
log_level=7
log_path=
# pprof
#pprof_ip=0.0.0.0
#pprof_port=9999
`

	// Write to a temp file
	tmpFile := "test_setting.conf"
	os.WriteFile(tmpFile, []byte(content), 0644)
	defer os.Remove(tmpFile)

	cfg, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Verify key fields
	if cfg.License != "TEST_LICENSE_BASE64_STRING" {
		t.Errorf("License: got %q, want %q", cfg.License, "TEST_LICENSE_BASE64_STRING")
	}
	if cfg.MasterType != "web" {
		t.Errorf("MasterType: got %q, want web", cfg.MasterType)
	}
	if cfg.WebPort != 8082 {
		t.Errorf("WebPort: got %d, want 8082", cfg.WebPort)
	}
	if cfg.WebIP != "0.0.0.0" {
		t.Errorf("WebIP: got %q, want 0.0.0.0", cfg.WebIP)
	}
	if cfg.WebUsername != "admin" {
		t.Errorf("WebUsername: got %q, want admin", cfg.WebUsername)
	}
	if cfg.WebPassword != "test-password-123" {
		t.Errorf("WebPassword: got %q, want test-password-123", cfg.WebPassword)
	}
	if cfg.WebBasicAuth != true {
		t.Errorf("WebBasicAuth: got %v, want true", cfg.WebBasicAuth)
	}
	if cfg.WebOpenSSL != false {
		t.Errorf("WebOpenSSL: got %v, want false", cfg.WebOpenSSL)
	}
	if cfg.LogLevel != 7 {
		t.Errorf("LogLevel: got %d, want 7", cfg.LogLevel)
	}
	if cfg.WebTitle != "管理平台" {
		t.Errorf("WebTitle: got %q, want 管理平台", cfg.WebTitle)
	}
	if cfg.WebCertFile != "conf/server.pem" {
		t.Errorf("WebCertFile: got %q, want conf/server.pem", cfg.WebCertFile)
	}
	if cfg.WebKeyFile != "conf/server.key" {
		t.Errorf("WebKeyFile: got %q, want conf/server.key", cfg.WebKeyFile)
	}

	// Commented-out lines should NOT be parsed
	if cfg.PprofIP != "" {
		t.Errorf("PprofIP: got %q, want empty (commented out)", cfg.PprofIP)
	}
	if cfg.PprofPort != 0 {
		t.Errorf("PprofPort: got %d, want 0 (commented out)", cfg.PprofPort)
	}

	// Empty fields should stay empty
	if cfg.DingdingAccessToken != "" {
		t.Errorf("DingdingAccessToken: got %q, want empty", cfg.DingdingAccessToken)
	}
	if cfg.WxKey != "" {
		t.Errorf("WxKey: got %q, want empty", cfg.WxKey)
	}
}

func TestParseBool(t *testing.T) {
	tests := []struct {
		input string
		def   bool
		want  bool
	}{
		{"true", false, true},
		{"false", true, false},
		{"1", false, true},
		{"0", true, false},
		{"yes", false, true},
		{"no", true, false},
		{"on", false, true},
		{"off", true, false},
		{"", true, false},
		{"", false, false},
		{"garbage", true, true},  // returns default
		{"garbage", false, false},
	}

	for _, tt := range tests {
		got := parseBool(tt.input, tt.def)
		if got != tt.want {
			t.Errorf("parseBool(%q, %v) = %v, want %v", tt.input, tt.def, got, tt.want)
		}
	}
}

func TestConfigMissingFile(t *testing.T) {
	cfg, err := LoadConfig("nonexistent_file.conf")
	if err != nil {
		t.Errorf("LoadConfig should not error on missing file: %v", err)
	}
	// Should return defaults
	if cfg.WebPort != 8082 {
		t.Errorf("Default WebPort: got %d, want 8082", cfg.WebPort)
	}
	if cfg.MasterType != "web" {
		t.Errorf("Default MasterType: got %q, want web", cfg.MasterType)
	}
}

func TestSyncSettingsFromConfig(t *testing.T) {
	content := `web_port=9999
web_username=testuser
web_password=testpass
web_jwt_secret=mysecret
`
	tmpFile := "test_sync.conf"
	os.WriteFile(tmpFile, []byte(content), 0644)
	defer os.Remove(tmpFile)

	// Load config directly (bypass singleton)
	cfg, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// Verify parsed values
	if cfg.WebPort != 9999 {
		t.Errorf("WebPort: got %d, want 9999", cfg.WebPort)
	}
	if cfg.WebUsername != "testuser" {
		t.Errorf("WebUsername: got %q, want testuser", cfg.WebUsername)
	}
	if cfg.WebPassword != "testpass" {
		t.Errorf("WebPassword: got %q, want testpass", cfg.WebPassword)
	}
	if cfg.WebJWTSecret != "mysecret" {
		t.Errorf("WebJWTSecret: got %q, want mysecret", cfg.WebJWTSecret)
	}
}

func TestEdgeCases(t *testing.T) {
	content := `
# only comments and blanks

  web_port  =  1234  
# mid-file comment
web_basic_auth=0
`
	tmpFile := "test_edges.conf"
	os.WriteFile(tmpFile, []byte(content), 0644)
	defer os.Remove(tmpFile)

	cfg, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// Whitespace handling
	if cfg.WebPort != 1234 {
		t.Errorf("WebPort with whitespace: got %d, want 1234", cfg.WebPort)
	}
	// "0" for bool should be false
	if cfg.WebBasicAuth != false {
		t.Errorf("WebBasicAuth=0: got %v, want false", cfg.WebBasicAuth)
	}
}

func TestSaveConfig(t *testing.T) {
	tmpFile := "test_save.conf"
	defer os.Remove(tmpFile)

	cfg := defaultFullSettings()
	cfg.WebPort = 9999
	cfg.WebUsername = "testadmin"

	if err := SaveConfig(cfg, tmpFile); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	loaded, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadConfig after save: %v", err)
	}

	if loaded.WebPort != 9999 {
		t.Errorf("WebPort: got %d, want 9999", loaded.WebPort)
	}
	if loaded.WebUsername != "testadmin" {
		t.Errorf("WebUsername: got %q, want testadmin", loaded.WebUsername)
	}
}

func TestUpdateConfig(t *testing.T) {
	tmpFile := "test_update.conf"
	defer os.Remove(tmpFile)

	if err := SaveConfig(defaultFullSettings(), tmpFile); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	if err := UpdateConfig(map[string]interface{}{
		"web_port":     7777,
		"web_username": "newadmin",
	}, tmpFile); err != nil {
		t.Fatalf("UpdateConfig: %v", err)
	}

	loaded, _ := LoadConfig(tmpFile)
	if loaded.WebPort != 7777 {
		t.Errorf("WebPort: got %d, want 7777", loaded.WebPort)
	}
	if loaded.WebUsername != "newadmin" {
		t.Errorf("WebUsername: got %q, want newadmin", loaded.WebUsername)
	}
}
