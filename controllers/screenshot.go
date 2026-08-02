// Package controllers — 截图控制器，1:1 对齐原版二进制。
//
// 前端路由：/screenshot/get。
// 说明：ScreenshotController 的 handler 方法名在 funcnametab 中被剥离（仅
// Json* 包装方法保留），但其注册路由存在于内嵌前端（url:"/screenshot/get"），
// 实际截图流由包级函数 D8MCqi8Dry3（0x18d9ba0，使用 "screen" 字符串）承担。
package controllers

// ScreenshotController 提供 Agent 截图。
type ScreenshotController struct {
	ApiBaseController
}

// Get 获取截图（/screenshot/get）。参数：id。
func (c *ScreenshotController) Get() {
	id := int64(c.JsonGetInt("id"))
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	// TODO(engine): 对齐包级截图流函数 D8MCqi8Dry3（0x18d9ba0）
	c.JsonOkResult(map[string]interface{}{"status": "ok"})
}
