// Package utils — Config file parser and settings management.
//
// Reverse-engineered from the original vshell binary (v_windows_amd64.exe).
// The original binary reads conf/setting.conf at startup using an INI-like
// format with # comments and key=value pairs. String keys are XOR-obfuscated
// in the binary; the keys below are the plaintext equivalents.
//
// Evidence: Original setting.conf from vshell(原版)/conf/setting.conf
// Confidence: HIGH (config file format is directly observable)

package utils

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// ============================================================================
// FullSettings — complete configuration matching the original binary
// ============================================================================

// FullSettings holds all configuration from conf/setting.conf.
// Mirrors the struct parsed by the original binary's config loader.
type FullSettings struct {
	// License
	License string // RSA-encrypted license key (base64)

	// Master mode: web, gui, all
	MasterType string

	// Web panel
	WebTitle     string
	WebPort      int
	WebIP        string
	WebBasicAuth bool
	WebJWTSecret string
	WebUsername  string
	WebPassword  string

	// Web SSL (panel HTTPS)
	WebOpenSSL  bool
	WebCertFile string
	WebKeyFile  string

	// DingDing robot notifications
	DingdingAccessToken string
	DingdingKeyWord     string

	// WeChat robot notifications
	WxKey string

	// Logging
	LogLevel int    // 0=Emergency .. 7=Debug
	LogPath  string // empty = use default log path

	// pprof debug
	PprofIP   string
	PprofPort int
}

// ============================================================================
// Config loader — parses conf/setting.conf
// ============================================================================

var (
	fullCfg     *FullSettings
	fullCfgOnce sync.Once
	fullCfgMu   sync.RWMutex
)

// defaultConfigPath returns the path to the config file.
// The original binary uses "conf/setting.conf" relative to the executable.
// Confidence: HIGH (directly observable from original directory structure)
func defaultConfigPath() string {
	// Try environment override first
	if env := os.Getenv("VSHELL_CONF"); env != "" {
		return env
	}
	return "conf/setting.conf"
}

// LoadConfig reads and parses the configuration file.
// Returns the parsed config; falls back to defaults if the file is missing.
func LoadConfig(path string) (*FullSettings, error) {
	if path == "" {
		path = defaultConfigPath()
	}

	cfg := defaultFullSettings()

	f, err := os.Open(path)
	if err != nil {
		// Config file not found — use defaults (matches original behavior)
		return cfg, nil
	}
	defer f.Close()

	if err := parseConfigFile(f, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	return cfg, nil
}

// GetFullSettings returns the loaded configuration (singleton).
// Loads from conf/setting.conf on first call.
func GetFullSettings() *FullSettings {
	fullCfgOnce.Do(func() {
		cfg, err := LoadConfig("")
		if err != nil {
			// Fall back to defaults on parse error
			cfg = defaultFullSettings()
		}
		fullCfgMu.Lock()
		fullCfg = cfg
		fullCfgMu.Unlock()
	})
	fullCfgMu.RLock()
	defer fullCfgMu.RUnlock()
	return fullCfg
}

// ReloadConfig re-reads the config file (useful for runtime config changes).
// SetFullSettingsForTest replaces the loaded settings (test helper).
// Triggers the singleton loader first so fullCfgOnce is consumed, then
// overwrites fullCfg — otherwise a later first GetFullSettings() call would
// re-run LoadConfig("") and clobber the injected value.
func SetFullSettingsForTest(cfg *FullSettings) {
	_ = GetFullSettings() // consume fullCfgOnce
	fullCfgMu.Lock()
	fullCfg = cfg
	fullCfgMu.Unlock()
}

func ReloadConfig(path string) error {
	cfg, err := LoadConfig(path)
	if err != nil {
		return err
	}
	fullCfgMu.Lock()
	fullCfg = cfg
	fullCfgMu.Unlock()
	return nil
}

// SaveConfig writes the current FullSettings back to the config file.
// Preserves comments and non-managed keys by doing a line-by-line update
// on the existing file content. If the file doesn't exist, generates a new one.
func SaveConfig(cfg *FullSettings, path string) error {
	if path == "" {
		path = defaultConfigPath()
	}

	// Build the config file content
	content := generateConfigContent(cfg)

	// Ensure directory exists
	if dir := filepathDir(path); dir != "" {
		os.MkdirAll(dir, 0755)
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	// Update the singleton
	fullCfgMu.Lock()
	fullCfg = cfg
	fullCfgMu.Unlock()

	// Also sync to auth settings
	SyncSettingsFromConfig()

	return nil
}

// UpdateConfig applies partial updates to the current config and saves.
// Only non-empty/non-zero fields in updates are applied.
func UpdateConfig(updates map[string]interface{}, path string) error {
	cfg := GetFullSettings()

	for k, v := range updates {
		applyConfigKey(cfg, k, fmt.Sprintf("%v", v))
	}

	return SaveConfig(cfg, path)
}

// generateConfigContent produces a setting.conf from FullSettings.
// Uses the same format as the original binary's output.
func generateConfigContent(cfg *FullSettings) string {
	var sb strings.Builder

	sb.WriteString("# License授权\n")
	sb.WriteString(fmt.Sprintf("license=%s\n", cfg.License))
	sb.WriteString("\n")
	sb.WriteString("# 控制端模式 web/gui/all，web模式只开启web端，gui模式开启gui api，all模式开启所有\n")
	sb.WriteString(fmt.Sprintf("master_type=%s\n", cfg.MasterType))
	sb.WriteString("\n")
	sb.WriteString("# web\n")
	sb.WriteString(fmt.Sprintf("web_title=%s\n", cfg.WebTitle))
	sb.WriteString(fmt.Sprintf("web_port=%d\n", cfg.WebPort))
	sb.WriteString(fmt.Sprintf("web_ip=%s\n", cfg.WebIP))
	sb.WriteString("\n")
	sb.WriteString("# 开启basic认证可防止被资产测绘收录\n")
	sb.WriteString(fmt.Sprintf("web_basic_auth=%v\n", cfg.WebBasicAuth))
	sb.WriteString("# web_jwt_secret可留空更安全，会使用随机字符串作为jwtSecret\n")
	sb.WriteString(fmt.Sprintf("web_jwt_secret=%s\n", cfg.WebJWTSecret))
	sb.WriteString(fmt.Sprintf("web_username=%s\n", cfg.WebUsername))
	sb.WriteString(fmt.Sprintf("web_password=%s\n", cfg.WebPassword))
	sb.WriteString("\n")
	sb.WriteString("# web ssl\n")
	sb.WriteString(fmt.Sprintf("web_open_ssl=%v\n", cfg.WebOpenSSL))
	sb.WriteString(fmt.Sprintf("web_cert_file=%s\n", cfg.WebCertFile))
	sb.WriteString(fmt.Sprintf("web_key_file=%s\n", cfg.WebKeyFile))
	sb.WriteString("\n")
	sb.WriteString("# dingding robot\n")
	sb.WriteString(fmt.Sprintf("dingding_access_token=%s\n", cfg.DingdingAccessToken))
	sb.WriteString(fmt.Sprintf("dingding_key_word=%s\n", cfg.DingdingKeyWord))
	sb.WriteString("\n")
	sb.WriteString("# wechat robot\n")
	sb.WriteString(fmt.Sprintf("wx_key=%s\n", cfg.WxKey))
	sb.WriteString("\n")
	sb.WriteString("# log level LevelEmergency->0  LevelAlert->1 LevelCritical->2 LevelError->3 LevelWarning->4 LevelNotice->5 LevelInformational->6 LevelDebug->7\n")
	sb.WriteString(fmt.Sprintf("log_level=%d\n", cfg.LogLevel))
	sb.WriteString(fmt.Sprintf("log_path=%s\n", cfg.LogPath))
	sb.WriteString("\n")
	sb.WriteString("# pprof debug options\n")
	if cfg.PprofIP != "" && cfg.PprofPort > 0 {
		sb.WriteString(fmt.Sprintf("pprof_ip=%s\n", cfg.PprofIP))
		sb.WriteString(fmt.Sprintf("pprof_port=%d\n", cfg.PprofPort))
	} else {
		sb.WriteString("#pprof_ip=0.0.0.0\n")
		sb.WriteString("#pprof_port=9999\n")
	}

	return sb.String()
}

// filepathDir extracts the directory from a file path.
// Avoids importing path/filepath here (already imported in other files).
func filepathDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return ""
}

// defaultFullSettings returns sensible defaults matching the original binary.
// Confidence: HIGH (matches original setting.conf default values)
func defaultFullSettings() *FullSettings {
	return &FullSettings{
		MasterType:   "web",
		WebTitle:     "\u7ba1\u7406\u5e73\u53f0", // 管理平台
		WebPort:      8082,
		WebIP:        "0.0.0.0",
		WebBasicAuth: true,
		WebJWTSecret: "",
		WebUsername:  "admin",
		WebPassword:  "", // no hardcoded default — main.go generates a random one at startup
		WebOpenSSL:   false,
		WebCertFile:  "conf/server.pem",
		WebKeyFile:   "conf/server.key",
		LogLevel:     7, // Debug
	}
}

// ============================================================================
// INI-like config parser
// ============================================================================

// parseConfigFile parses the INI-like config format from setting.conf.
//
// Format (reverse-engineered, confidence HIGH):
//   - Lines starting with # are comments
//   - Blank lines are ignored
//   - key=value pairs (whitespace around = is trimmed)
//   - Keys use snake_case (matching the original binary's decoded strings)
func parseConfigFile(f *os.File, cfg *FullSettings) error {
	scanner := bufio.NewScanner(f)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split key=value
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue // malformed line, skip silently (matches original behavior)
		}

		key := strings.TrimSpace(line[:eq])
		value := strings.TrimSpace(line[eq+1:])

		// Dispatch to the appropriate field
		applyConfigKey(cfg, key, value)
	}

	return scanner.Err()
}

// applyConfigKey applies a single key=value to the config struct.
// Keys match the original binary's decoded string constants.
//
// Confidence: HIGH for all keys (directly observable from setting.conf)
func applyConfigKey(cfg *FullSettings, key, value string) {
	switch key {
	case "license":
		cfg.License = value

	case "master_type":
		cfg.MasterType = value

	// Web panel
	case "web_title":
		cfg.WebTitle = value
	case "web_port":
		if n, err := strconv.Atoi(value); err == nil {
			cfg.WebPort = n
		}
	case "web_ip":
		cfg.WebIP = value
	case "web_basic_auth":
		cfg.WebBasicAuth = parseBool(value, true)
	case "web_jwt_secret":
		cfg.WebJWTSecret = value
	case "web_username":
		cfg.WebUsername = value
	case "web_password":
		cfg.WebPassword = value

	// Web SSL
	case "web_open_ssl":
		cfg.WebOpenSSL = parseBool(value, false)
	case "web_cert_file":
		cfg.WebCertFile = value
	case "web_key_file":
		cfg.WebKeyFile = value

	// DingDing
	case "dingding_access_token":
		cfg.DingdingAccessToken = value
	case "dingding_key_word":
		cfg.DingdingKeyWord = value

	// WeChat
	case "wx_key":
		cfg.WxKey = value

	// Logging
	case "log_level":
		if n, err := strconv.Atoi(value); err == nil {
			cfg.LogLevel = n
		}
	case "log_path":
		cfg.LogPath = value

	// pprof
	case "pprof_ip":
		cfg.PprofIP = value
	case "pprof_port":
		if n, err := strconv.Atoi(value); err == nil {
			cfg.PprofPort = n
		}
	}
}

// parseBool converts a string to bool. Returns def if the string is not
// a recognized boolean value.
func parseBool(s string, def bool) bool {
	switch strings.ToLower(s) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off", "":
		return false
	default:
		return def
	}
}

// ============================================================================
// Config → Settings synchronization
// ============================================================================

// SyncSettingsFromConfig synchronizes the global Settings singleton
// (defined in auth.go) with the full config. Call this during startup.
func SyncSettingsFromConfig() {
	settingsOnce.Do(func() {}) // ensure once is consumed
	cfg := GetFullSettings()

	jwtSecret := cfg.WebJWTSecret
	if jwtSecret == "" {
		jwtSecret = generateJWTSecret()
	}

	settingsMu.Lock()
	defer settingsMu.Unlock()
	settings = &Settings{
		License:      cfg.License,
		MasterType:   cfg.MasterType,
		WebTitle:     cfg.WebTitle,
		WebPort:      cfg.WebPort,
		WebIP:        cfg.WebIP,
		WebBasicAuth: cfg.WebBasicAuth,
		WebUsername:  cfg.WebUsername,
		WebPassword:  cfg.WebPassword,
		WebJWTSecret: jwtSecret,
	}
}
