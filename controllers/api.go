// Package controllers/api 提供通用 API 基础控制器与响应辅助。
// Package controllers/api provides the generic API base controller and response helpers.
package controllers

import "vshell/models"

// ApiBaseController 提供通用 API 功能（认证检查与响应封装）。
// ApiBaseController provides common API functionality.
type ApiBaseController struct {
	BaseController
}

// Prepare 校验 API 路由的认证（Cookie 或 Authorization Bearer）。
// Prepare checks authentication for API routes.
func (c *ApiBaseController) Prepare() {
	token := c.GetSecureCookie("secret", "token")
	if token == "" {
		token = c.Ctx.Request.Header.Get("Authorization")
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}
	}
	if token == "" {
		c.CustomAbort(401, "Unauthorized")
	}
}

// Success 返回成功响应（原版二进制格式）。
// API response helpers (original binary format).
func (c *ApiBaseController) Success(data interface{}) {
	c.ServeJSON(models.APIResponse{
		Code:    0,
		Message: "ok",
		Type:    "success",
		Result:  data,
	})
}

// Error 返回错误响应。
// Error returns an error response.
func (c *ApiBaseController) Error(msg string) {
	c.ServeJSON(models.APIResponse{
		Code:    500,
		Message: msg,
		Type:    "error",
	})
}

// List 返回分页列表响应。
// List returns a paginated list response.
func (c *ApiBaseController) List(items interface{}, total int) {
	c.ServeJSON(models.ListResponse{
		Code:    0,
		Message: "ok",
		Type:    "success",
		Result: &models.ListResult{
			Items: items,
			Total: total,
		},
	})
}
