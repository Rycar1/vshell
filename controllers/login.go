package controllers

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"vshell/models"
	"vshell/utils"
)

// LoginController handles authentication
type LoginController struct {
	BaseController
}

// GetUserInfo is the original binary's action name
// (nTApp6jPzv.(*LoginController).GetUserInfo).
func (c *LoginController) GetUserInfo() { c.Get() }

// Get handles GET /login - serves SPA index.html
func (c *LoginController) Get() {
	// Check if already authenticated via header token
	token := c.Ctx.Request.Header.Get("X-Token")
	if token == "" {
		token = c.Ctx.Request.URL.Query().Get("token")
	}
	if token != "" {
		_, err := utils.ValidateToken(token)
		if err == nil {
			c.Redirect("/dashboard", http.StatusFound)
			return
		}
	}
	// Serve SPA — frontend handles routing client-side
	http.ServeFile(c.Ctx.ResponseWriter, c.Ctx.Request, "static/index.html")
}

// Login is the original binary's action name
// (nTApp6jPzv.(*LoginController).Login).
func (c *LoginController) Login() { c.Post() }

// Post handles POST /login - authenticates user (original binary format)
func (c *LoginController) Post() {
	var req models.LoginRequest
	if err := json.NewDecoder(c.Ctx.Request.Body).Decode(&req); err != nil {
		c.JSON(200, models.LoginResponse{
			Code:    -1,
			Message: "Incorrect account or password！",
			Result:  nil,
			Type:    "error",
		})
		return
	}

	// Validate credentials
	if req.Username == "" || req.Password == "" {
		c.JSON(200, models.LoginResponse{
			Code:    -1,
			Message: "Incorrect account or password！",
			Result:  nil,
			Type:    "error",
		})
		return
	}

	// Get configured admin credentials
	settings := utils.GetSettings()
	if req.Username != settings.WebUsername {
		c.JSON(200, models.LoginResponse{
			Code:    -1,
			Message: "Incorrect account or password！",
			Result:  nil,
			Type:    "error",
		})
		return
	}

	if !utils.CheckPassword(req.Password, settings.WebPassword) {
		c.JSON(200, models.LoginResponse{
			Code:    -1,
			Message: "Incorrect account or password！",
			Result:  nil,
			Type:    "error",
		})
		return
	}

	// Generate JWT token with RBAC claims matching original binary
	token, err := utils.GenerateTokenWithRoles(req.Username, "1", "1")
	if err != nil {
		c.JSON(200, models.LoginResponse{
			Code:    -1,
			Message: "Failed to generate token",
			Result:  nil,
			Type:    "error",
		})
		return
	}

	// Set session
	c.SetSession("user_id", "1")
	c.SetSession("username", req.Username)
	c.SetSession("login_time", time.Now().Unix())

	// Return original binary format
	c.JSON(200, models.LoginResponse{
		Code:    0,
		Message: "ok",
		Type:    "success",
		Result: &models.LoginResult{
			Token:    token,
			UserID:   "1",
			Username: req.Username,
			Desc:     "manager",
			RealName: "admin",
			Roles: []models.RoleInfo{
				{RoleName: "Super Admin", Value: "super"},
			},
		},
	})
}

// Logout handles GET /logout
func (c *LoginController) Logout() {
	c.DelSession("user_id")
	c.DelSession("username")
	c.DelSession("login_time")
	c.Redirect("/login", http.StatusFound)
}

// Prepare middleware - checks authentication for protected routes
// Supports both Header authorization and ?token= URL parameter (original binary format)
func (c *LoginController) Prepare() {
	// Skip auth check for login page and API
	if c.Ctx.Request.URL.Path == "/login" || c.Ctx.Request.URL.Path == "/api/login" {
		return
	}

	// Check JWT token - first from ?token= query parameter (original binary format)
	token := c.Ctx.Request.URL.Query().Get("token")
	if token == "" {
		// Check from cookie
		token = c.GetSecureCookie(utils.GetJWTSecret(), "token")
	}
	if token == "" {
		// Check Authorization header
		authHeader := c.Ctx.Request.Header.Get("Authorization")
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			token = authHeader[7:]
		}
	}
	// Also check X-Token header
	if token == "" {
		token = c.Ctx.Request.Header.Get("X-Token")
	}

	if token == "" {
		c.CustomAbort(401, "Unauthorized")
		return
	}

	// Validate JWT token with role info
	claims, err := utils.ValidateTokenWithRole(token)
	if err != nil {
		c.CustomAbort(401, "Invalid or expired token")
		return
	}

	// Set user info from token
	c.SetSession("username", claims.Username)
	c.SetSession("user_id", claims.UserID)
	c.SetSession("role_id", claims.RoleID)

	// RBAC: check role permissions for API paths
	path := c.Ctx.Request.URL.Path
	if strings.HasPrefix(path, "/api/") && path != "/api/login" {
		// Convert role ID to value for permission check
		var roleVal string
		switch claims.RoleID {
		case "1":
			roleVal = utils.RoleSuperAdmin
		case "2":
			roleVal = utils.RoleAdmin
		case "3":
			roleVal = utils.RoleUser
		default:
			roleVal = utils.RoleUser
		}
		if !utils.HasPermission(roleVal, path) {
			c.CustomAbort(403, "Forbidden: insufficient permissions")
			return
		}
	}
}

// CheckXSRFCookie checks XSRF cookie
func (c *LoginController) CheckXSRFCookie() bool {
	return true
}

// XSRFFormHTML returns XSRF form HTML
func (c *LoginController) XSRFFormHTML() string {
	return ""
}

// XSRFToken generates XSRF token
func (c *LoginController) XSRFToken() string {
	return c.GetSecureCookie(utils.GetJWTSecret(), "_xsrf")
}

// parseJSONBody attempts to parse the request body as JSON and populate a target.
// Returns true if the body was valid JSON, false otherwise (body is form-encoded or empty).
func parseJSONBody(r *http.Request, target interface{}) bool {
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		body, err := io.ReadAll(r.Body)
		if err == nil && len(body) > 0 {
			json.Unmarshal(body, target)
			return true
		}
	}
	return false
}
