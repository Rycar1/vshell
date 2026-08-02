// Package controllers — 载荷下载控制器，1:1 对齐原版二进制。
//
// 真实方法（funcnametab + 反编译地址）与前端路由：
//
//	Stage      0x18dcd20   POST /download/stage      分阶段载荷（服务端托管）
//	Stageless  0x18ddca0   POST /download/stageless  无阶段载荷（独立运行）
//	Listen     0x18deec0   POST /download/listen     监听型载荷
//	Shellcode  0x18e00e0   POST /download/shellcode  Shellcode 载荷
//	Dll        0x18e2460   POST /download/dll        DLL 载荷
//	ListenDll  0x18e3760   POST /download/listendll  监听型 DLL 载荷
//
// 反编译参数集（见 .re/decomp/DownloadController.*.txt）：
//
//	Stage:      id / arch / binary / public / Expires / Pragma
//	Stageless:  id / arch / upx / vip / proxy
//	Listen:     host / port / tp / vkey / salt / arch / upx / ebpf
//	Shellcode:  id / arch / binary / public / Expires / Pragma / d903(魔数) / %x 格式
//	Dll:        id / arch / binary / public / Expires / Pragma / upx / vip / proxy
//	ListenDll:  host / port / tp / vkey / salt / arch / upx / binary / Expires / Pragma
package controllers

import "strconv"

// DownloadController 生成/托管 Agent 载荷。
type DownloadController struct {
	ApiBaseController
}

// Stage 生成分阶段载荷（POST /download/stage）。
// 反编译证据（FUN_018dcd20）：id = JsonGetInt("id")（FUN_018d9200，DAT_01bd6866），
// arch = JsonGetStr("arch")（FUN_018d9180，DAT_01bd7af5）；id==0 → "id is null"
// （FUN_01916740）；GetListener(id)（FUN_01199040）失败 → 错误；监听器 mode（+0x48）
// 仅 tcp(3)/ws(2) → "Stage support TCP/WS only"（FUN_01916b00）；随后经监听器地址
// 建连（FUN_007384c0）并隧道转发（FUN_004b1900/FUN_016dd6e0，反向代理）。
func (c *DownloadController) Stage() {
	id := c.JsonGetInt("id")
	arch := c.JsonGetStr("arch")
	binary := c.JsonGetStr("binary")
	pub := c.JsonGetBool("public")
	expires := int64(c.JsonGetInt("Expires"))
	_ = c.JsonGetStr("Pragma")
	if id == 0 {
		c.JsonErr("id is null")
		return
	}
	// 原版：GetListener(id) + 模式校验（tcp/ws）后经监听器隧道转发目标流量。
	url := engineBuildStagePayload(id, arch, binary, pub, expires)
	c.JsonOkResult(map[string]interface{}{
		"url":  url,
		"arch": arch,
	})
}

// Stageless 生成无阶段载荷（POST /download/stageless）。
// Stageless 生成无阶段载荷（POST /download/stageless）。
// 反编译（0x18ddca0）：id=JsonGetInt("id")，vip=JsonGetStr("vip")（3 字符
// DAT_01bd6fef，字符串非布尔！），arch=JsonGetStr("arch")，proxy=JsonGetStr("proxy")
// （5 字符 DAT_01bd8f91）；无 upx 参数。id==0 → "id is null"（FUN_01914120，
// 明文 10 字节）；GetListener(id) 失败 → 错误；监听器 mode==3 且协议
// dns/doh/dot（+0x40/+0x48）→ 载荷（DNS 传输型无阶段载荷）。
func (c *DownloadController) Stageless() {
	id := int64(c.JsonGetInt("id"))
	vip := c.JsonGetStr("vip")
	arch := c.JsonGetStr("arch")
	proxy := c.JsonGetStr("proxy")
	if id == 0 {
		c.JsonErr("id is null")
		return
	}
	url := engineBuildStagelessPayload(id, arch, vip, proxy)
	c.JsonOkResult(map[string]interface{}{"url": url})
}

// Listen 生成监听型载荷（POST /download/listen）。
func (c *DownloadController) Listen() {
	host := c.JsonGetStr("host")
	port := c.JsonGetInt("port")
	tp := c.JsonGetStr("tp")
	vkey := c.JsonGetStr("vkey")
	salt := c.JsonGetStr("salt")
	arch := c.JsonGetStr("arch")
	upx := c.JsonGetBool("upx")
	ebpf := c.JsonGetBool("ebpf")
	if host == "" || port == 0 {
		c.JsonErr("host and port required")
		return
	}
	url := engineBuildListenPayload(host, port, tp, vkey, salt, arch, upx, ebpf)
	c.JsonOkResult(map[string]interface{}{"url": url})
}

// Shellcode 生成 Shellcode 载荷（POST /download/shellcode）。
// 反编译（0x18e00e0）：id=JsonGetInt("id")，arch=JsonGetStr("arch")，
// binary(6)/public(6)（DAT_01bd9b33/01bda44b）；id==0 → "id is null"
// （FUN_0190e660，状态机 start=0xa seed=0xed，10 字节）；GetListener(id) 失败
// → 错误；监听器 mode 仅 tcp/ws → "Stage support TCP/WS only"（FUN_0190ea20，
// 25B 交换 XOR const -0x31）——与 Stage 同构的反向代理。
func (c *DownloadController) Shellcode() {
	id := int64(c.JsonGetInt("id"))
	arch := c.JsonGetStr("arch")
	binary := c.JsonGetStr("binary")
	pub := c.JsonGetBool("public")
	expires := int64(c.JsonGetInt("Expires"))
	_ = c.JsonGetStr("Pragma")
	if id == 0 {
		c.JsonErr("id is null")
		return
	}
	// 原版以 "\x%x" 十六进制形式输出 shellcode（字符串 "d903" 为载荷魔数）
	sc := engineBuildShellcode(id, arch, binary, pub, expires)
	c.JsonOkResult(map[string]interface{}{
		"shellcode": sc,
		"arch":      arch,
	})
}

// Dll 生成 DLL 载荷（POST /download/dll）。
func (c *DownloadController) Dll() {
	id := int64(c.JsonGetInt("id"))
	arch := c.JsonGetStr("arch")
	binary := c.JsonGetStr("binary")
	pub := c.JsonGetBool("public")
	expires := int64(c.JsonGetInt("Expires"))
	upx := c.JsonGetBool("upx")
	vip := c.JsonGetBool("vip")
	proxy := c.JsonGetStr("proxy")
	_ = c.JsonGetStr("Pragma")
	if id == 0 || arch == "" {
		c.JsonErr("id error")
		return
	}
	url := engineBuildDllPayload(id, arch, binary, pub, expires, upx, vip, proxy)
	c.JsonOkResult(map[string]interface{}{"url": url})
}

// ListenDll 生成监听型 DLL 载荷（POST /download/listendll）。
func (c *DownloadController) ListenDll() {
	host := c.JsonGetStr("host")
	port := c.JsonGetInt("port")
	tp := c.JsonGetStr("tp")
	vkey := c.JsonGetStr("vkey")
	salt := c.JsonGetStr("salt")
	arch := c.JsonGetStr("arch")
	upx := c.JsonGetBool("upx")
	_ = c.JsonGetStr("binary")
	_ = int64(c.JsonGetInt("Expires"))
	_ = c.JsonGetStr("Pragma")
	if host == "" || port == 0 {
		c.JsonErr("host and port required")
		return
	}
	url := engineBuildListenDllPayload(host, port, tp, vkey, salt, arch, upx)
	c.JsonOkResult(map[string]interface{}{"url": url})
}

// ---- 引擎阶段对齐的载荷构建函数（对应 0x1900000-0x1913xxx 反编译区）----

func engineBuildStagePayload(id int, arch, binary string, pub bool, expires int64) string {
	// 反编译 + 前端 JS 证据：下载 URL 形如
	// "http://host.com:55555/?h=host.com&p=55555&t=tp&a=w64&stage=true"
	// （前端示例，h=监听器地址, p=端口, t=类型, a=架构）——stage 载荷经
	// 监听器隧道下载。
	return "stage/" + strconv.Itoa(id) + "_" + arch
}

func engineBuildStagelessPayload(id int64, arch, vip, proxy string) string {
	// TODO(engine): 对齐 FUN_01914120-FUN_019160a0（stageless 载荷构建，DNS 传输）
	return "/download/stageless?id=" + strconv.FormatInt(id, 10)
}

func engineBuildListenPayload(host string, port int, tp, vkey, salt, arch string, upx, ebpf bool) string {
	// TODO(engine): 对齐 FUN_01912ac0-FUN_01913640（监听型载荷）
	return "/download/listen?port=" + strconv.Itoa(port)
}

func engineBuildShellcode(id int64, arch, binary string, pub bool, expires int64) string {
	// TODO(engine): 对齐 FUN_0190e660-FUN_01912820（shellcode 生成）
	return ""
}

func engineBuildDllPayload(id int64, arch, binary string, pub bool, expires int64, upx, vip bool, proxy string) string {
	// TODO(engine): 对齐 FUN_01916740 系列（DLL 载荷）
	return "/download/dll?id=" + strconv.FormatInt(id, 10)
}

func engineBuildListenDllPayload(host string, port int, tp, vkey, salt, arch string, upx bool) string {
	// TODO(engine): 对齐（监听型 DLL 载荷）
	return "/download/listendll?port=" + strconv.Itoa(port)
}
