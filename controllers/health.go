// Package controllers/health 提供轻量级后端健康检查端点。
// Package controllers/health provides lightweight backend health-check endpoints.
package controllers

import (
	"runtime"
	"time"

	"vshell/c2engine"
	"vshell/models"
)

// HealthController 暴露轻量级后端健康检查，兼容原版 /health 与 /api/health 的返回结构，
// 并复用恢复的系统健康采集器。
// HealthController exposes lightweight backend health checks.
// It is compatible with the original frontend/backlog expectations for
// /health and /api/health while reusing the restored system health collectors.
type HealthController struct {
	BaseController
}

// Get 返回数据库、运行时、C2 引擎与系统层面的健康信息。
// Get returns health info across database, runtime, C2 engine, and system.
func (c *HealthController) Get() {
	db := models.GetDB()
	dbStatus := "disabled"
	clients := 0
	listeners := 0
	if db != nil {
		dbStatus = "ok"
		clients, _ = db.GetClientCount()
		listeners, _ = db.GetListenerCount()
	}

	engine := c2engine.GetEngine()
	if engine != nil {
		clients = len(engine.GetClientList())
	}

	sys := c2engine.GetSystemStats()
	c.JSON(200, map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
		"database":  dbStatus,
		"runtime": map[string]interface{}{
			"go_version": runtime.Version(),
			"goroutines": runtime.NumGoroutine(),
		},
		"engine": map[string]interface{}{
			"clients":   clients,
			"listeners": listeners,
		},
		"system": map[string]interface{}{
			"uptime_seconds":   sys.UptimeSeconds,
			"total_checkins":   sys.TotalCheckins,
			"total_commands":   sys.TotalCommands,
			"total_uploads":    sys.TotalUploads,
			"total_downloads":  sys.TotalDownloads,
			"active_clients":   sys.ActiveClients,
			"active_listeners": sys.ActiveListeners,
			"active_tunnels":   sys.ActiveTunnels,
		},
	})
}
