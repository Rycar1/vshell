package controllers

import "vshell/models"

// ApiBaseController provides common API functionality
type ApiBaseController struct {
	BaseController
}

// Prepare checks authentication for API routes
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

// API response helpers (original binary format)
func (c *ApiBaseController) Success(data interface{}) {
	c.ServeJSON(models.APIResponse{
		Code:    0,
		Message: "ok",
		Type:    "success",
		Result:  data,
	})
}

func (c *ApiBaseController) Error(msg string) {
	c.ServeJSON(models.APIResponse{
		Code:    500,
		Message: msg,
		Type:    "error",
	})
}

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
