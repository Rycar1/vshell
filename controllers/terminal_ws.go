package controllers

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// TerminalSession 表示与客户端的一个交互式终端会话。
// TerminalSession represents an interactive terminal session with a client.
type TerminalSession struct {
	ID          string    `json:"id"`
	ClientID    int64     `json:"client_id"`
	Type        string    `json:"type"` // cmd, powershell, bash, sh
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	LastActive  time.Time `json:"last_active"`
	Rows        int       `json:"rows"`
	Cols        int       `json:"cols"`
	cmd         *exec.Cmd
	stdin       io.WriteCloser
	stdout      io.ReadCloser
	stderr      io.ReadCloser
	output      strings.Builder
	mu          sync.Mutex
	done        chan struct{}
}

var (
	terminalSessions = make(map[string]*TerminalSession)
	terminalMu       sync.RWMutex
	terminalIDSeq    int64
)

// NewTerminalSession 创建新的终端会话。
// NewTerminalSession creates a new terminal session.
func NewTerminalSession(clientID int64, termType string, rows, cols int) (*TerminalSession, error) {
	terminalMu.Lock()
	terminalIDSeq++
	id := fmt.Sprintf("term_%d_%d_%d", clientID, terminalIDSeq, time.Now().UnixNano())
	terminalMu.Unlock()

	ts := &TerminalSession{
		ID:         id,
		ClientID:   clientID,
		Type:       termType,
		Status:     "initializing",
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
		Rows:       rows,
		Cols:       cols,
		done:       make(chan struct{}),
	}

	// Determine shell command
	var shell, shellArg string
	if runtime.GOOS == "windows" {
		switch termType {
		case "powershell":
			shell = "powershell.exe"
			shellArg = "-NoExit"
		default:
			shell = "cmd.exe"
			shellArg = "/Q"
		}
	} else {
		switch termType {
		case "bash":
			shell = "/bin/bash"
			shellArg = "--login"
		case "sh":
			shell = "/bin/sh"
			shellArg = ""
		default:
			shell = "/bin/bash"
			shellArg = ""
		}
	}

	// Start local shell process
	args := []string{}
	if shellArg != "" {
		args = append(args, shellArg)
	}

	cmd := exec.Command(shell, args...)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("TERM=xterm-%d", cols),
		fmt.Sprintf("LINES=%d", rows),
		fmt.Sprintf("COLUMNS=%d", cols),
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start shell: %w", err)
	}

	ts.cmd = cmd
	ts.stdin = stdin
	ts.stdout = stdout
	ts.stderr = stderr
	ts.Status = "running"

	// Start output collection
	go ts.collectOutput(stdout, false)
	go ts.collectOutput(stderr, true)

	// Store session
	terminalMu.Lock()
	terminalSessions[id] = ts
	terminalMu.Unlock()

	log.Printf("[Terminal] Session %s created (type: %s, pid: %d)", id, termType, cmd.Process.Pid)
	return ts, nil
}

func (ts *TerminalSession) collectOutput(reader io.Reader, isError bool) {
	buf := make([]byte, 4096)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			ts.mu.Lock()
			// Only store printable UTF-8 (for history)
			if utf8.Valid(buf[:n]) {
				ts.output.Write(buf[:n])
			}
			ts.LastActive = time.Now()
			ts.mu.Unlock()
		}
		if err != nil {
			break
		}
	}
	close(ts.done)
}

// Write 向终端发送输入。
// Write sends input to the terminal.
func (ts *TerminalSession) Write(data []byte) (int, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.LastActive = time.Now()
	return ts.stdin.Write(data)
}

// Resize 调整终端尺寸。
// Resize adjusts the terminal size.
func (ts *TerminalSession) Resize(rows, cols int) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.Rows = rows
	ts.Cols = cols
	// Update environment for next spawned processes
	ts.cmd.Env = append(os.Environ(),
		fmt.Sprintf("TERM=xterm-%d", cols),
		fmt.Sprintf("LINES=%d", rows),
		fmt.Sprintf("COLUMNS=%d", cols),
	)
}

// ReadOutput 读取累计的输出。
// ReadOutput reads all accumulated output.
func (ts *TerminalSession) ReadOutput() string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.output.String()
}

// Close 终止终端会话。
// Close terminates the terminal session.
func (ts *TerminalSession) Close() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.Status != "running" {
		return nil
	}

	ts.Status = "closed"
	ts.stdin.Close()

	// Kill the process
	if ts.cmd != nil && ts.cmd.Process != nil {
		ts.cmd.Process.Kill()
		ts.cmd.Wait()
	}

	terminalMu.Lock()
	delete(terminalSessions, ts.ID)
	terminalMu.Unlock()

	log.Printf("[Terminal] Session %s closed", ts.ID)
	return nil
}

// GetTerminalSession 获取终端会话。
// GetTerminalSession retrieves a terminal session.
func GetTerminalSession(id string) *TerminalSession {
	terminalMu.RLock()
	defer terminalMu.RUnlock()
	return terminalSessions[id]
}

// CleanupStaleTerminals 移除空闲过久的终端会话。
// CleanupStaleTerminals removes terminals that have been idle too long.
func CleanupStaleTerminals(maxIdle time.Duration) {
	terminalMu.Lock()
	defer terminalMu.Unlock()

	for id, ts := range terminalSessions {
		if time.Since(ts.LastActive) > maxIdle {
			ts.mu.Lock()
			ts.Status = "closed"
			ts.stdin.Close()
			if ts.cmd != nil && ts.cmd.Process != nil {
				ts.cmd.Process.Kill()
			}
			ts.mu.Unlock()
			delete(terminalSessions, id)
			log.Printf("[Terminal] Cleaned up stale session: %s", id)
		}
	}
}

// TerminalAPI 处理终端 WebSocket 升级与 HTTP 回退。
// TerminalAPI handles terminal WebSocket upgrade and HTTP fallback.
type TerminalAPI struct {
	BaseController
}

// Create 创建新终端会话（HTTP API）。
// Create creates a new terminal session (HTTP API).
func (t *TerminalAPI) Create() {
	clientID, _ := t.GetInt64("client_id")
	termType := t.GetString("type", "cmd")
	rows, _ := t.GetInt("rows", 24)
	cols, _ := t.GetInt("cols", 80)

	session, err := NewTerminalSession(clientID, termType, rows, cols)
	if err != nil {
		t.Error(err.Error())
		return
	}

	t.JSONOk(map[string]interface{}{
		"session_id": session.ID,
		"type":       session.Type,
		"created_at": session.CreatedAt,
		"rows":       session.Rows,
		"cols":       session.Cols,
	})
}

// SendInput 向终端会话发送输入。
// SendInput sends input to a terminal session.
func (t *TerminalAPI) SendInput() {
	sessionID := t.GetString("session_id")
	input := t.GetString("input")

	session := GetTerminalSession(sessionID)
	if session == nil {
		t.Error("Session not found")
		return
	}

	_, err := session.Write([]byte(input))
	if err != nil {
		t.Error(err.Error())
		return
	}

	t.JSONOk(map[string]interface{}{"sent": len(input)})
}

// GetOutput 获取累计的终端输出。
// GetOutput retrieves accumulated terminal output.
func (t *TerminalAPI) GetOutput() {
	sessionID := t.GetString("session_id")
	session := GetTerminalSession(sessionID)
	if session == nil {
		t.Error("Session not found")
		return
	}

	t.JSONOk(map[string]interface{}{
		"output": session.ReadOutput(),
	})
}

// CloseSession 关闭终端会话。
// CloseSession closes a terminal session.
func (t *TerminalAPI) CloseSession() {
	sessionID := t.GetString("session_id")
	session := GetTerminalSession(sessionID)
	if session == nil {
		t.Error("Session not found")
		return
	}

	session.Close()
	t.JSONOk(map[string]string{"status": "closed"})
}

// WSHandler 处理 WebSocket 终端连接。
// WSHandler handles WebSocket terminal connections.
func (t *TerminalAPI) WSHandler() {
	// Simplified: HTTP fallback for terminal interaction
	// Full WebSocket would use gorilla/websocket
	clientID, _ := t.GetInt64("client_id")
	action := t.GetString("action", "create")

	switch action {
	case "create":
		t.Create()
	case "write":
		t.SendInput()
	case "read":
		t.GetOutput()
	case "close":
		t.CloseSession()
	case "resize":
		sessionID := t.GetString("session_id")
		rows, _ := t.GetInt("rows", 24)
		cols, _ := t.GetInt("cols", 80)
		session := GetTerminalSession(sessionID)
		if session != nil {
			session.Resize(rows, cols)
			t.JSONOk(map[string]string{"status": "resized"})
		} else {
			t.Error("Session not found")
		}
	default:
		t.JSONOk(map[string]interface{}{
			"client_id": clientID,
			"sessions":  ListTerminalSessions(),
		})
	}
}

// ListTerminalSessions 返回所有活跃终端会话。
// ListTerminalSessions returns all active terminal sessions.
func ListTerminalSessions() []map[string]interface{} {
	terminalMu.RLock()
	defer terminalMu.RUnlock()

	result := make([]map[string]interface{}, 0, len(terminalSessions))
	for id, ts := range terminalSessions {
		ts.mu.Lock()
		result = append(result, map[string]interface{}{
			"id":         id,
			"client_id":  ts.ClientID,
			"type":       ts.Type,
			"status":     ts.Status,
			"created_at": ts.CreatedAt,
			"last_active": ts.LastActive,
			"rows":       ts.Rows,
			"cols":       ts.Cols,
		})
		ts.mu.Unlock()
	}
	return result
}

// TerminalCommand 执行一次性命令并返回结果。
// TerminalCommand executes a one-shot command and returns the result.
func TerminalCommand(clientID int64, command string, timeout int) (string, error) {
	var shell, shellFlag string
	if runtime.GOOS == "windows" {
		shell = "cmd.exe"
		shellFlag = "/C"
	} else {
		shell = "/bin/bash"
		shellFlag = "-c"
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, shell, shellFlag, command)
	output, err := cmd.CombinedOutput()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return string(output), fmt.Errorf("command timed out after %ds", timeout)
		}
		return string(output), err
	}

	return string(output), nil
}
