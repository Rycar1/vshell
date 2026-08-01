package controllers

import (
	"runtime"
	"time"

	"vshell/c2engine"
	"vshell/models"
)

// HealthController exposes lightweight backend health checks.
// It is compatible with the original frontend/backlog expectations for
// /health and /api/health while reusing the restored system health collectors.
type HealthController struct {
	BaseController
}

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
