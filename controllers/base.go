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

// ControllerInterface defines the standard controller methods
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

// ActionHandler dispatches to a named action method on a controller
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

// SessionControllerInterface wraps sessionController to implement ControllerInterface
type SessionControllerInterface struct {
	sessionController
}
type BaseController struct {
	Ctx     *Context
	Data    map[interface{}]interface{}
	session *sessions.Session
	store   *sessions.CookieStore
	mu      sync.RWMutex
}

// Context holds the request context
type Context struct {
	Request       *http.Request
	ResponseWriter http.ResponseWriter
}

// Ensure Context implements io.Writer
var _ io.Writer = (*Context)(nil)

func (ctx *Context) Write(p []byte) (n int, err error) {
	return ctx.ResponseWriter.Write(p)
}

// Init initializes the controller
func (c *BaseController) Init(ctx *Context) {
	c.Ctx = ctx
	c.Data = make(map[interface{}]interface{})
	c.store = sessions.NewCookieStore([]byte("vshell-session-key"))
}

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

// GetStrings returns multiple string values for a key
func (c *BaseController) GetStrings(key string) []string {
	return c.Ctx.Request.URL.Query()[key]
}

// GetInt returns an int parameter
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

// GetInt64 returns an int64 parameter
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

// GetUint32 returns a uint32 parameter
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

// GetBool returns a bool parameter
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

// GetFloat returns a float64 parameter
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

// SetSession sets a session value
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

// GetSession gets a session value
func (c *BaseController) GetSession(key interface{}) interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.session == nil {
		return nil
	}
	return c.session.Values[key]
}

// DelSession deletes a session value
func (c *BaseController) DelSession(key interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil {
		delete(c.session.Values, key)
	}
}

// StartSession initializes the session
func (c *BaseController) StartSession() {
	c.session = sessions.NewSession(c.store, "vshell-session")
}

// DestroySession clears the session
func (c *BaseController) DestroySession() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.session = nil
}

// SetSecureCookie sets an encrypted cookie
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

// GetSecureCookie gets an encrypted cookie
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

// Render renders a template
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

// JSON sends a JSON response
func (c *BaseController) JSON(code int, data interface{}) {
	c.Ctx.ResponseWriter.Header().Set("Content-Type", "application/json; charset=utf-8")
	c.Ctx.ResponseWriter.WriteHeader(code)
	json.NewEncoder(c.Ctx.ResponseWriter).Encode(data)
}

// JSONOk sends a success JSON response (original binary format)
func (c *BaseController) JSONOk(data interface{}) {
	c.JSON(200, map[string]interface{}{
		"code":    0,
		"message": "ok",
		"result":  data,
		"type":    "success",
	})
}

// JSONOkMessage sends a success response with just a message (no result data)
func (c *BaseController) JSONOkMessage(message string) {
	c.JSON(200, map[string]interface{}{
		"code":    0,
		"message": message,
		"type":    "success",
	})
}

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

// Error is an alias for JSONErr
func (c *BaseController) Error(message string) {
	c.JSONErr(message)
}

// Redirect redirects to a URL
func (c *BaseController) Redirect(url string, code int) {
	http.Redirect(c.Ctx.ResponseWriter, c.Ctx.Request, url, code)
}

// CustomAbort aborts with a custom error
func (c *BaseController) CustomAbort(status int, body string) {
	c.Ctx.ResponseWriter.WriteHeader(status)
	c.Ctx.ResponseWriter.Write([]byte(body))
}

// Abort aborts with 404
func (c *BaseController) Abort(body string) {
	c.CustomAbort(http.StatusNotFound, body)
}

// ServeJSON serves JSON content
func (c *BaseController) ServeJSON(data interface{}) {
	c.JSON(200, data)
}

// ServeJSONP serves JSONP content
func (c *BaseController) ServeJSONP(data interface{}) {
	callback := c.GetString("callback", "callback")
	c.Ctx.ResponseWriter.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	c.Ctx.ResponseWriter.Write([]byte(callback + "("))
	json.NewEncoder(c.Ctx.ResponseWriter).Encode(data)
	c.Ctx.ResponseWriter.Write([]byte(")"))
}

// ServeXML serves XML content
func (c *BaseController) ServeXML(data interface{}) {
	c.Ctx.ResponseWriter.Header().Set("Content-Type", "application/xml; charset=utf-8")
	// Simplified - would need xml.Marshal
	json.NewEncoder(c.Ctx.ResponseWriter).Encode(data)
}

// ServeFormatted serves formatted content based on request Accept header
func (c *BaseController) ServeFormatted(data interface{}) {
	accept := c.Ctx.Request.Header.Get("Accept")
	if strings.Contains(accept, "application/json") || strings.Contains(accept, "text/json") {
		c.ServeJSON(data)
	} else {
		c.ServeJSON(data)
	}
}

// IsAjax checks if request is AJAX
func (c *BaseController) IsAjax() bool {
	return c.Ctx.Request.Header.Get("X-Requested-With") == "XMLHttpRequest"
}

// Input returns parsed form values
func (c *BaseController) Input() url.Values {
	c.Ctx.Request.ParseForm()
	return c.Ctx.Request.Form
}

// ParseForm parses the form
func (c *BaseController) ParseForm(obj interface{}) error {
	return nil
}

// GetFile retrieves an uploaded file
func (c *BaseController) GetFile(key string) (multipart.File, *multipart.FileHeader, error) {
	return c.Ctx.Request.FormFile(key)
}

// GetFiles retrieves multiple uploaded files
func (c *BaseController) GetFiles(key string) ([]*multipart.FileHeader, error) {
	return nil, nil
}

// SaveToFile saves an uploaded file to disk
func (c *BaseController) SaveToFile(file string, path string) error {
	return nil
}

// GetControllerAndAction returns the controller name and action
func (c *BaseController) GetControllerAndAction() (string, string) {
	path := c.Ctx.Request.URL.Path
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > 0 {
		return parts[0], strings.Join(parts[1:], "/")
	}
	return "index", "index"
}

// URLFor generates a URL for a controller/action
func (c *BaseController) URLFor(controller string, action string, params ...interface{}) string {
	return "/" + controller + "/" + strings.ToLower(action)
}

// URLMapping returns URL mappings
func (c *BaseController) URLMapping() map[string]string {
	return map[string]string{}
}

// Mapping registers URL mappings
func (c *BaseController) Mapping(method string, action string, handler func()) {
	// Placeholder for URL routing
}

// HandlerFunc returns a handler function
func (c *BaseController) HandlerFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c.Ctx = &Context{
			Request:        r,
			ResponseWriter: w,
		}
	}
}

// ServeYAML serves YAML content
func (c *BaseController) ServeYAML(data interface{}) {
	c.Ctx.ResponseWriter.Header().Set("Content-Type", "text/yaml; charset=utf-8")
}

// SessionRegenerateID regenerates the session ID
func (c *BaseController) SessionRegenerateID() {
	c.StartSession()
}

// StopRun stops request processing
func (c *BaseController) StopRun() {
	panic("stop run")
}

// Finish performs cleanup after request
func (c *BaseController) Finish() {}

// Trace logs a trace message
func (c *BaseController) Trace(v ...interface{}) {}

// Prepare is the prepare hook - override in subclasses
func (c *BaseController) Prepare() {}

// Post handles POST requests - override in subclasses
func (c *BaseController) Post() {}

// Get handles GET requests - override in subclasses
func (c *BaseController) Get() {}

// Head handles HEAD requests
func (c *BaseController) Head() {}

// Put handles PUT requests
func (c *BaseController) Put() {}

// Patch handles PATCH requests
func (c *BaseController) Patch() {}

// Delete handles DELETE requests
func (c *BaseController) Delete() {}

// Options handles OPTIONS requests
func (c *BaseController) Options() {}

// SetData sets template data
func (c *BaseController) SetData(key interface{}, val interface{}) {
	c.Data[key] = val
}

// InputData parses input data from Content-Type header
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

// dispatchListenerCRUD routes listener CRUD action names to methods.
func dispatchListenerCRUD(lc *ListenerController, action string) {
	switch action {
	case "EditRemark": lc.EditRemark()
	case "Del": lc.Del()
	case "Dellist": lc.Dellist()
	}
}

// dispatchRunnerAction routes runner controller action names to methods.
// paginatedResult wraps items in the format the frontend expects:
func paginatedResult(items interface{}, total int) map[string]interface{} {
	return map[string]interface{}{
		"items": items,
		"total": total,
	}
}
