// Package controllers 实现 Web 管理面板的 MVC 控制器层：请求上下文、参数解析、
// 会话、JSON 响应以及各业务控制器（客户端/监听器/终端/文件/隧道等）。
// Package controllers implements the MVC controller layer of the web management
// panel: request context, parameter parsing, sessions, JSON responses, and the
// business controllers (clients/listeners/terminal/files/tunnels, etc.).
package controllers

import (
	"encoding/json"
	"html/template"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/sessions"
)

// ControllerInterface 定义标准控制器方法集合。
// ControllerInterface defines the standard controller methods.
type ControllerInterface interface {
	Init(ctx *Context)
	Prepare()
	Get()
	Post()
	Put()
	Delete()
	Head()
	Patch()
	Options()
}

// ActionHandler 将请求分发到控制器上指定名称的 action 方法。
// ActionHandler dispatches to a named action method on a controller.
type ActionHandler struct {
	Ctrl   ControllerInterface
	Action string
}

func (ah *ActionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := &Context{
		Request:        r,
		ResponseWriter: w,
	}
	ah.Ctrl.Init(ctx)
	ah.Ctrl.Prepare()

	// Dispatch based on action name
	switch ah.Action {
	case "Start":
		switch c := ah.Ctrl.(type) {
		case *ListenerController:
			c.Start()
		case *HostController:
			c.Start()
		case *TunnelController:
			c.Start()
		default:
			http.Error(w, "Unknown controller for Start action", 400)
		}
	case "Stop":
		switch c := ah.Ctrl.(type) {
		case *ListenerController:
			c.Stop()
		case *HostController:
			c.Stop()
		case *TunnelController:
			c.Stop()
		default:
			http.Error(w, "Unknown controller for Stop action", 400)
		}
	case "Block":
		if c, ok := ah.Ctrl.(*ClientController); ok {
			c.Block()
		}
	case "CheckIn":
		if c, ok := ah.Ctrl.(*ClientController); ok {
			c.CheckIn()
		}
	case "Unblock":
		if c, ok := ah.Ctrl.(*ClientController); ok {
			c.Unblock()
		}
	case "Note":
		if c, ok := ah.Ctrl.(*ClientController); ok {
			c.Note()
		}
	case "WS":
		if c, ok := ah.Ctrl.(*TerminalController); ok {
			c.WS()
		}
	case "Resize":
		if c, ok := ah.Ctrl.(*TerminalController); ok {
			c.Resize()
		}
	case "Download":
		if c, ok := ah.Ctrl.(*FileController); ok {
			c.Download()
		}
	case "Shell":
		if c, ok := ah.Ctrl.(*TerminalController); ok {
			c.Shell()
		}
	// Named Get/Post actions — the original beego router dispatches the
	// controller method named by the URL action regardless of HTTP method
	// (e.g. POST /api/setting/get still calls SettingController.Get()).
	case "Get":
		ah.Ctrl.Get()
	case "Post":
		ah.Ctrl.Post()
	// FileController extended action dispatch
	case "Ls", "Rm", "RmList", "Mv", "Cat", "Mkdir", "Touch", "Edit",
		"Modifytime", "Wget", "DownloadToServer",
		"DownloadToBrowser", "DownloadToOSS", "GetDownloadPer", "Getdisk":
		if fc, ok := ah.Ctrl.(*FileController); ok {
			dispatchFileAction(fc, ah.Action)
		}
	// Upload — handled by both FileController and RunnerController
	case "Upload":
		switch c := ah.Ctrl.(type) {
		case *FileController: c.Upload()
		case *RunnerController: c.Upload()
		}
	// Listener extended CRUD
	case "EditRemark", "Del", "Dellist":
		if lc, ok := ah.Ctrl.(*ListenerController); ok {
			dispatchListenerCRUD(lc, ah.Action)
		}
	// Runner controller actions
	case "RunPlugin":
		if rc, ok := ah.Ctrl.(*RunnerController); ok {
			rc.RunPlugin()
		}
	case "List":
		// Dispatch to the controller's named List method when it defines one;
		// otherwise fall back to Get() (generic list action).
		switch c := ah.Ctrl.(type) {
		case *RunnerController:
			c.List()
		case *ListenerController:
			c.List()
		case *TunnelController:
			c.List()
		case *HostController:
			c.List()
		case *DownloadController:
			c.Get()
		case *FileController:
			c.Get()
		default:
			ah.Ctrl.Get()
		}
	// DownloadController actions — without these the router's default
	// method-based dispatch calls the inherited no-op Post() and the agent
	// generation endpoints return an empty 200 body.
	case "Stage", "Stageless", "Shellcode", "Dll", "Listen", "ListenDll":
		if dc, ok := ah.Ctrl.(*DownloadController); ok {
			switch ah.Action {
			case "Stage":
				dc.Stage()
			case "Stageless":
				dc.Stageless()
			case "Shellcode":
				dc.Shellcode()
			case "Dll":
				dc.Dll()
			case "Listen":
				dc.Listen()
			case "ListenDll":
				dc.ListenDll()
			}
		}
	default:
		switch r.Method {
		case "GET":
			ah.Ctrl.Get()
		case "POST":
			ah.Ctrl.Post()
		case "PUT":
			ah.Ctrl.Put()
		case "DELETE":
			ah.Ctrl.Delete()
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// SessionControllerInterface 包装 sessionController 以符合 ControllerInterface。
// SessionControllerInterface wraps sessionController to implement ControllerInterface.
type SessionControllerInterface struct {
	sessionController
}

// BaseController 是所有控制器的基类：提供参数读取、会话与 JSON 响应等通用能力。
// BaseController is the base class of all controllers: provides parameter
// reading, sessions, and JSON responses.
type BaseController struct {
	Ctx     *Context
	Data    map[interface{}]interface{}
	session *sessions.Session
	store   *sessions.CookieStore
	mu      sync.RWMutex
}

// Context 保存一次 HTTP 请求的上下文（请求与响应对象）。
// Context holds the request context.
type Context struct {
	Request       *http.Request
	ResponseWriter http.ResponseWriter
}

// Ensure Context implements io.Writer
var _ io.Writer = (*Context)(nil)

func (ctx *Context) Write(p []byte) (n int, err error) {
	return ctx.ResponseWriter.Write(p)
}

// Init 初始化控制器：绑定上下文并准备数据/会话存储。
// Init initializes the controller.
func (c *BaseController) Init(ctx *Context) {
	c.Ctx = ctx
	c.Data = make(map[interface{}]interface{})
	c.store = sessions.NewCookieStore([]byte("vshell-session-key"))
}

// GetString 返回字符串参数。查找顺序与原版 beego 二进制一致：
// 1) URL 查询参数；2) 表单值；3) JSON 请求体。
// 每种来源都会同时尝试原始键与其 PascalCase 变体（vkey→Vkey、listen_addr→ListenAddr 等），
// 因为原版前端以 Go 字段名作为 JSON 键提交。
// GetString returns a string parameter value.
// Lookup order matches the original beego-based binary:
//  1. URL query string
//  2. form values (application/x-www-form-urlencoded)
//  3. JSON request body (application/json)
// Each source is tried with both the requested key and its PascalCase
// variant (vkey → Vkey, listen_addr → ListenAddr, ...) because the original
// frontend submits Go field names as JSON keys.
func (c *BaseController) GetString(key string, defaultValue ...string) string {
	val := c.Ctx.Request.URL.Query().Get(key)
	if val == "" {
		val = c.Ctx.Request.FormValue(key)
	}
	if val == "" {
		val = jsonBodyValue(c.Ctx.Request, key)
	}
	if val == "" {
		// PascalCase fallback (original binary parameter names)
		alt := pascalKey(key)
		if alt != key {
			val = c.Ctx.Request.URL.Query().Get(alt)
			if val == "" {
				val = c.Ctx.Request.FormValue(alt)
			}
			if val == "" {
				val = jsonBodyValue(c.Ctx.Request, alt)
			}
		}
	}
	if val == "" && len(defaultValue) > 0 {
		return defaultValue[0]
	}
	return val
}

// jsonBodyValue 从 JSON 请求体中读取键值（按请求缓存）。支持标量值与简单 map 结构。
// jsonBodyValue reads a key from a JSON request body (cached per request).
// Both scalar values and simple map[string]interface{} bodies are supported.
func jsonBodyValue(r *http.Request, key string) string {
	ct := r.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		return ""
	}
	body := jsonBodyCache(r)
	if body == nil {
		return ""
	}
	v, ok := body[key]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return ""
	}
}

// jsonBodyCache 每个请求只解析一次 JSON 请求体。
// jsonBodyCache parses the request JSON body once per request.
func jsonBodyCache(r *http.Request) map[string]interface{} {
	if v, ok := r.Body.(*bodyJSONCache); ok {
		return v.m
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}
	cache := &bodyJSONCache{raw: body, m: map[string]interface{}{}}
	if len(body) > 0 {
		json.Unmarshal(body, &cache.m)
	}
	// Replace body so subsequent reads (e.g. parseJSONBody) still work.
	r.Body = cache
	return cache.m
}

// bodyJSONCache 包装请求体：缓存解码后的 JSON map，同时保留原始字节供后续读取。
// bodyJSONCache wraps a request body: it caches the decoded JSON map while
// keeping the raw bytes readable for later consumers.
type bodyJSONCache struct {
	raw []byte
	m   map[string]interface{}
	pos int
}

func (c *bodyJSONCache) Read(p []byte) (int, error) {
	if c.pos >= len(c.raw) {
		return 0, io.EOF
	}
	n := copy(p, c.raw[c.pos:])
	c.pos += n
	return n, nil
}

func (c *bodyJSONCache) Close() error { return nil }

// pascalKey 将 snake_case 键转换为 PascalCase 变体（vkey→Vkey、listen_addr→ListenAddr 等）。
// pascalKey converts a snake_case form key into its PascalCase variant
// (vkey → Vkey, listen_addr → ListenAddr, encrypt_salt → EncryptSalt).
func pascalKey(key string) string {
	parts := strings.Split(key, "_")
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		out += strings.ToUpper(p[:1]) + p[1:]
	}
	return out
}

// GetStrings 返回某键的多个字符串值。
// GetStrings returns multiple string values for a key.
func (c *BaseController) GetStrings(key string) []string {
	return c.Ctx.Request.URL.Query()[key]
}

// GetInt 返回 int 参数。
// GetInt returns an int parameter.
func (c *BaseController) GetInt(key string, defaultValue ...int) (int, error) {
	val := c.GetString(key)
	if val == "" {
		if len(defaultValue) > 0 {
			return defaultValue[0], nil
		}
		return 0, nil
	}
	return strconv.Atoi(val)
}

// GetInt64 返回 int64 参数。
// GetInt64 returns an int64 parameter.
func (c *BaseController) GetInt64(key string, defaultValue ...int64) (int64, error) {
	val := c.GetString(key)
	if val == "" {
		if len(defaultValue) > 0 {
			return defaultValue[0], nil
		}
		return 0, nil
	}
	return strconv.ParseInt(val, 10, 64)
}

// GetUint32 返回 uint32 参数。
// GetUint32 returns a uint32 parameter.
func (c *BaseController) GetUint32(key string, defaultValue ...uint32) (uint32, error) {
	n, err := c.GetInt64(key)
	if err != nil {
		if len(defaultValue) > 0 {
			return defaultValue[0], nil
		}
		return 0, err
	}
	return uint32(n), nil
}

// GetBool 返回 bool 参数。
// GetBool returns a bool parameter.
func (c *BaseController) GetBool(key string, defaultValue ...bool) (bool, error) {
	val := c.GetString(key)
	if val == "" {
		if len(defaultValue) > 0 {
			return defaultValue[0], nil
		}
		return false, nil
	}
	return strconv.ParseBool(val)
}

// GetFloat 返回 float64 参数。
// GetFloat returns a float64 parameter.
func (c *BaseController) GetFloat(key string, defaultValue ...float64) (float64, error) {
	val := c.GetString(key)
	if val == "" {
		if len(defaultValue) > 0 {
			return defaultValue[0], nil
		}
		return 0, nil
	}
	return strconv.ParseFloat(val, 64)
}

// SetSession 写入会话值。
// SetSession sets a session value.
func (c *BaseController) SetSession(key interface{}, val interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == nil {
		c.session = sessions.NewSession(c.store, "vshell-session")
		c.session.Values[key] = val
		return
	}
	c.session.Values[key] = val
}

// GetSession 读取会话值。
// GetSession gets a session value.
func (c *BaseController) GetSession(key interface{}) interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.session == nil {
		return nil
	}
	return c.session.Values[key]
}

// DelSession 删除会话值。
// DelSession deletes a session value.
func (c *BaseController) DelSession(key interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil {
		delete(c.session.Values, key)
	}
}

// StartSession 初始化会话。
// StartSession initializes the session.
func (c *BaseController) StartSession() {
	c.session = sessions.NewSession(c.store, "vshell-session")
}

// DestroySession 清空会话。
// DestroySession clears the session.
func (c *BaseController) DestroySession() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.session = nil
}

// SetSecureCookie 写入加密 Cookie（24 小时有效）。
// SetSecureCookie sets an encrypted cookie.
func (c *BaseController) SetSecureCookie(secret string, name string, value string) {
	http.SetCookie(c.Ctx.ResponseWriter, &http.Cookie{
		Name:     name,
		Value:    url.QueryEscape(value),
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // HTTP, not HTTPS
		MaxAge:   86400, // 24 hours
	})
}

// GetSecureCookie 读取加密 Cookie。
// GetSecureCookie gets an encrypted cookie.
func (c *BaseController) GetSecureCookie(secret string, name string) string {
	cookie, err := c.Ctx.Request.Cookie(name)
	if err != nil {
		return ""
	}
	val, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return ""
	}
	return val
}

// Render 渲染服务端模板。
// Render renders a template.
func (c *BaseController) Render(tpl string) {
	c.Ctx.ResponseWriter.Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Ctx.ResponseWriter.WriteHeader(http.StatusOK)
	t, err := template.ParseFiles("views/" + tpl)
	if err != nil {
		http.Error(c.Ctx.ResponseWriter, err.Error(), http.StatusInternalServerError)
		return
	}
	t.Execute(c.Ctx.ResponseWriter, c.Data)
}

// JSON 发送 JSON 响应。
// JSON sends a JSON response.
func (c *BaseController) JSON(code int, data interface{}) {
	c.Ctx.ResponseWriter.Header().Set("Content-Type", "application/json; charset=utf-8")
	c.Ctx.ResponseWriter.WriteHeader(code)
	json.NewEncoder(c.Ctx.ResponseWriter).Encode(data)
}

// JSONOk 发送成功响应（原版二进制格式：code=0/message=ok/type=success）。
// JSONOk sends a success JSON response (original binary format).
func (c *BaseController) JSONOk(data interface{}) {
	c.JSON(200, map[string]interface{}{
		"code":    0,
		"message": "ok",
		"result":  data,
		"type":    "success",
	})
}

// JSONOkMessage 发送仅含 message 的成功响应。
// JSONOkMessage sends a success response with just a message (no result data).
func (c *BaseController) JSONOkMessage(message string) {
	c.JSON(200, map[string]interface{}{
		"code":    0,
		"message": message,
		"type":    "success",
	})
}

// JSONErr 发送错误响应，格式与原版一致：{"code":-1,"message":msg,"result":null,"type":"error"}
// JSONErr sends an error JSON response matching the original binary:
// {"code":-1,"message":msg,"result":null,"type":"error"}
func (c *BaseController) JSONErr(message string) {
	c.JSON(200, map[string]interface{}{
		"code":    -1,
		"message": message,
		"result":  nil,
		"type":    "error",
	})
}

// Error 是 JSONErr 的别名。
// Error is an alias for JSONErr.
func (c *BaseController) Error(message string) {
	c.JSONErr(message)
}

// Redirect 重定向到指定 URL。
// Redirect redirects to a URL.
func (c *BaseController) Redirect(url string, code int) {
	http.Redirect(c.Ctx.ResponseWriter, c.Ctx.Request, url, code)
}

// CustomAbort 以自定义状态码与内容终止请求。
// CustomAbort aborts with a custom error.
func (c *BaseController) CustomAbort(status int, body string) {
	c.Ctx.ResponseWriter.WriteHeader(status)
	c.Ctx.ResponseWriter.Write([]byte(body))
}

// Abort 以 404 终止请求。
// Abort aborts with 404.
func (c *BaseController) Abort(body string) {
	c.CustomAbort(http.StatusNotFound, body)
}

// ServeJSON 输出 JSON 内容。
// ServeJSON serves JSON content.
func (c *BaseController) ServeJSON(data interface{}) {
	c.JSON(200, data)
}

// ServeJSONP 输出 JSONP 内容。
// ServeJSONP serves JSONP content.
func (c *BaseController) ServeJSONP(data interface{}) {
	callback := c.GetString("callback", "callback")
	c.Ctx.ResponseWriter.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	c.Ctx.ResponseWriter.Write([]byte(callback + "("))
	json.NewEncoder(c.Ctx.ResponseWriter).Encode(data)
	c.Ctx.ResponseWriter.Write([]byte(")"))
}

// ServeXML 输出 XML 内容。
// ServeXML serves XML content.
func (c *BaseController) ServeXML(data interface{}) {
	c.Ctx.ResponseWriter.Header().Set("Content-Type", "application/xml; charset=utf-8")
	// Simplified - would need xml.Marshal
	json.NewEncoder(c.Ctx.ResponseWriter).Encode(data)
}

// ServeFormatted 根据 Accept 头输出格式化内容。
// ServeFormatted serves formatted content based on request Accept header.
func (c *BaseController) ServeFormatted(data interface{}) {
	accept := c.Ctx.Request.Header.Get("Accept")
	if strings.Contains(accept, "application/json") || strings.Contains(accept, "text/json") {
		c.ServeJSON(data)
	} else {
		c.ServeJSON(data)
	}
}

// IsAjax 判断请求是否为 AJAX。
// IsAjax checks if request is AJAX.
func (c *BaseController) IsAjax() bool {
	return c.Ctx.Request.Header.Get("X-Requested-With") == "XMLHttpRequest"
}

// Input 返回解析后的表单值。
// Input returns parsed form values.
func (c *BaseController) Input() url.Values {
	c.Ctx.Request.ParseForm()
	return c.Ctx.Request.Form
}

// ParseForm 解析表单（当前为空实现，兼容原版接口）。
// ParseForm parses the form (currently a no-op for interface compatibility).
func (c *BaseController) ParseForm(obj interface{}) error {
	return nil
}

// GetFile 获取上传的文件。
// GetFile retrieves an uploaded file.
func (c *BaseController) GetFile(key string) (multipart.File, *multipart.FileHeader, error) {
	return c.Ctx.Request.FormFile(key)
}

// GetFiles 获取多个上传文件（当前返回 nil，兼容接口）。
// GetFiles retrieves multiple uploaded files (currently unimplemented).
func (c *BaseController) GetFiles(key string) ([]*multipart.FileHeader, error) {
	return nil, nil
}

// SaveToFile 将上传文件保存到磁盘（当前为空实现）。
// SaveToFile saves an uploaded file to disk (currently a no-op).
func (c *BaseController) SaveToFile(file string, path string) error {
	return nil
}

// GetControllerAndAction 从 URL 中解析控制器名与 action 名。
// GetControllerAndAction returns the controller name and action.
func (c *BaseController) GetControllerAndAction() (string, string) {
	path := c.Ctx.Request.URL.Path
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > 0 {
		return parts[0], strings.Join(parts[1:], "/")
	}
	return "index", "index"
}

// URLFor 为控制器/action 生成 URL。
// URLFor generates a URL for a controller/action.
func (c *BaseController) URLFor(controller string, action string, params ...interface{}) string {
	return "/" + controller + "/" + strings.ToLower(action)
}

// URLMapping 返回 URL 映射表（当前为空）。
// URLMapping returns URL mappings (currently empty).
func (c *BaseController) URLMapping() map[string]string {
	return map[string]string{}
}

// Mapping 注册 URL 映射（占位实现）。
// Mapping registers URL mappings (placeholder).
func (c *BaseController) Mapping(method string, action string, handler func()) {
	// Placeholder for URL routing
}

// HandlerFunc 返回绑定到当前控制器的处理函数。
// HandlerFunc returns a handler function.
func (c *BaseController) HandlerFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c.Ctx = &Context{
			Request:        r,
			ResponseWriter: w,
		}
	}
}

// ServeYAML 设置 YAML 响应头（兼容接口）。
// ServeYAML serves YAML content.
func (c *BaseController) ServeYAML(data interface{}) {
	c.Ctx.ResponseWriter.Header().Set("Content-Type", "text/yaml; charset=utf-8")
}

// SessionRegenerateID 重新生成会话 ID。
// SessionRegenerateID regenerates the session ID.
func (c *BaseController) SessionRegenerateID() {
	c.StartSession()
}

// StopRun 终止请求处理。
// StopRun stops request processing.
func (c *BaseController) StopRun() {
	panic("stop run")
}

// Finish 请求结束后执行清理（当前为空实现）。
// Finish performs cleanup after request (currently a no-op).
func (c *BaseController) Finish() {}

// Trace 记录追踪日志（当前为空实现）。
// Trace logs a trace message (currently a no-op).
func (c *BaseController) Trace(v ...interface{}) {}

// Prepare 是预处理钩子，子类可覆写。
// Prepare is the prepare hook - override in subclasses.
func (c *BaseController) Prepare() {}

// Post 处理 POST 请求，子类可覆写。
// Post handles POST requests - override in subclasses.
func (c *BaseController) Post() {}

// Get 处理 GET 请求，子类可覆写。
// Get handles GET requests - override in subclasses.
func (c *BaseController) Get() {}

// Head 处理 HEAD 请求。
// Head handles HEAD requests.
func (c *BaseController) Head() {}

// Put 处理 PUT 请求。
// Put handles PUT requests.
func (c *BaseController) Put() {}

// Patch 处理 PATCH 请求。
// Patch handles PATCH requests.
func (c *BaseController) Patch() {}

// Delete 处理 DELETE 请求。
// Delete handles DELETE requests.
func (c *BaseController) Delete() {}

// Options 处理 OPTIONS 请求。
// Options handles OPTIONS requests.
func (c *BaseController) Options() {}

// SetData 设置模板数据。
// SetData sets template data.
func (c *BaseController) SetData(key interface{}, val interface{}) {
	c.Data[key] = val
}

// InputData 根据请求方法解析输入数据（GET 用查询串，其余用表单）。
// InputData parses input data based on the HTTP method.
func (c *BaseController) InputData() url.Values {
	if c.Ctx.Request.Method == "GET" {
		return c.Ctx.Request.URL.Query()
	}
	c.Ctx.Request.ParseForm()
	return c.Ctx.Request.PostForm
}

// ============================================================================
// Action dispatch helpers (for controllers with many action methods)
// ============================================================================

// dispatchFileAction 将文件控制器的 action 名称路由到对应方法。
// dispatchFileAction routes file controller action names to methods.
func dispatchFileAction(fc *FileController, action string) {
	switch action {
	case "Ls": fc.Ls()
	case "Rm": fc.Rm()
	case "RmList": fc.RmList()
	case "Mv": fc.Mv()
	case "Cat": fc.Cat()
	case "Mkdir": fc.Mkdir()
	case "Touch": fc.Touch()
	case "Edit": fc.Edit()
	case "Modifytime": fc.Modifytime()
	case "Wget": fc.Wget()
	case "Upload": fc.Upload()
	case "DownloadToServer": fc.DownloadToServer()
	case "DownloadToBrowser": fc.DownloadToBrowser()
	case "DownloadToOSS": fc.DownloadToOSS()
	case "GetDownloadPer": fc.GetDownloadPer()
	case "Getdisk": fc.Getdisk()
	}
}

// dispatchListenerCRUD 将监听器 CRUD action 名称路由到对应方法。
// dispatchListenerCRUD routes listener CRUD action names to methods.
func dispatchListenerCRUD(lc *ListenerController, action string) {
	switch action {
	case "EditRemark": lc.EditRemark()
	case "Del": lc.Del()
	case "Dellist": lc.Dellist()
	}
}

// dispatchRunnerAction 将 runner 控制器的 action 名称路由到对应方法。
// paginatedResult 以前端期望的格式包装分页数据。
// dispatchRunnerAction routes runner controller action names to methods.
// paginatedResult wraps items in the format the frontend expects:
func paginatedResult(items interface{}, total int) map[string]interface{} {
	return map[string]interface{}{
		"items": items,
		"total": total,
	}
}
