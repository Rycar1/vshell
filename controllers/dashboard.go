package controllers

import (
	"net/http"
	"strconv"
	"strings"

	"vshell/c2engine"
	"vshell/models"
	"vshell/utils"
)

// DashboardController handles the main management panel
type DashboardController struct {
	BaseController
}

// Get renders the dashboard page or returns JSON for API
func (c *DashboardController) Get() {
	path := c.Ctx.Request.URL.Path

	// API endpoint → JSON always
	if strings.Contains(path, "/api/") {
		stats := c.collectStats()
		c.JSONOk(stats)
		return
	}

	// HTML page - serve the SPA index.html for client-side routing
	http.ServeFile(c.Ctx.ResponseWriter, c.Ctx.Request, "static/index.html")
}

// Post is the same as Get — the original beego router dispatches the action
// named in the URL regardless of HTTP method, so POST /api/dashboard/info
// must return the same payload as GET.
func (c *DashboardController) Post() {
	c.Get()
}

// Info is the original binary's dashboard action name
// (nTApp6jPzv.(*DashboardController).Info).
func (c *DashboardController) Info() { c.Get() }

// GetOverview returns overview statistics for the dashboard
func (c *DashboardController) GetOverview() {
	stats := c.collectStats()
	c.JSONOk(stats)
}

// collectStats builds the dashboard statistics payload in the original
// binary's flat wire format.
//
// Black-box evidence from the original v_windows_amd64.exe
// (POST /api/dashboard/info, auth: JWT token header):
//
//	{"code":0,"message":"ok","result":{
//	  "clientCount":0,"clientNum":"99","clientOnlineCount":0,
//	  "cpu":4,"disk":70,"exportFlowCount":0,"flowStoreInterval":"",
//	  "hostCount":0,"httpProxyCount":0,"httpProxyPort":"","httpsProxyPort":"",
//	  "inletFlowCount":0,"io_recv":400,"io_send":496,"ipLimit":"",
//	  "licTime":"20991201","listenerCount":0,"listenerOnlineCount":0,
//	  "load":"{\"load1\":0.08,\"load5\":0.02,\"load15\":0.01}",
//	  "logLevel":"7","logPath":"","p2pCount":0,"p2pPort":"",
//	  "secretCount":0,"socks5Count":0,"swap_mem":55,"tcpC":0,"tcpCount":0,
//	  "udpCount":0,"version":"4.9.3","vip":true,"virtual_mem":76,
//	  "web_basic_auth":true,"web_port":"8082"},
//	"type":"success"}
//
// The original frontend dashboard component reads exactly these keys
// (its reactive state object lists the same fields).
func (c *DashboardController) collectStats() map[string]interface{} {
	db := models.GetDB()
	clientCount := 0
	listenerCount := 0

	if db != nil {
		clientCount, _ = db.GetClientCount()
		listenerCount, _ = db.GetListenerCount()
	}

	// Count online clients via C2 engine
	onlineClients := len(GetActiveClients())

	// Collect real-time system resource stats
	cfg := utils.GetFullSettings()
	config := &c2engine.Config{
		WebPort: cfg.WebPort,
	}
	monitor := c2engine.GetSystemMonitor()
	sysStats := monitor.Collect(config)

	// Override license values with real license status
	licStatus := utils.GetLicenseStatus()
	sysStats.LicenseEndTime = licStatus.EndTime
	sysStats.AdvancedLicense = licStatus.Advanced
	sysStats.LicenseClientCap = licStatus.MaxClients
	sysStats.BasicAuth = cfg.WebBasicAuth
	sysStats.WebPort = cfg.WebPort
	sysStats.AppVersion = "4.9.3" // match original binary version string

	// CPU percent (0-100 integer, like the original "cpu":4)
	cpu := int(sysStats.CPUPercent)
	if cpu < 0 {
		cpu = 0
	}
	if cpu > 100 {
		cpu = 100
	}

	return map[string]interface{}{
		"clientCount":         clientCount,
		"clientNum":           "99", // license client cap as string
		"clientOnlineCount":   onlineClients,
		"cpu":                 cpu,
		"disk":                int(sysStats.DiskPercent),
		"exportFlowCount":     0,
		"flowStoreInterval":   "",
		"hostCount":           0,
		"httpProxyCount":      0,
		"httpProxyPort":       "",
		"httpsProxyPort":      "",
		"inletFlowCount":      0,
		"io_recv":             parseBandwidthBytes(sysStats.InBandwidth),
		"io_send":             parseBandwidthBytes(sysStats.OutBandwidth),
		"ipLimit":             "",
		"licTime":             sysStats.LicenseEndTime,
		"listenerCount":       listenerCount,
		"listenerOnlineCount": 0,
		"load":                sysStats.LoadJSON,
		"logLevel":            sysStats.LogLevel,
		"logPath":             sysStats.LogFile,
		"p2pCount":            0,
		"p2pPort":             "",
		"secretCount":         0,
		"socks5Count":         0,
		"swap_mem":            int(sysStats.VMemPercent),
		"tcpC":                sysStats.TCPConns,
		"tcpCount":            sysStats.TCPConns,
		"udpCount":            sysStats.UDPConns,
		"version":             sysStats.AppVersion,
		"vip":                 sysStats.AdvancedLicense,
		"virtual_mem":         int(sysStats.VMemPercent),
		"web_basic_auth":      sysStats.BasicAuth,
		"web_port":            formatPort(sysStats.WebPort),
	}
}

// formatPort renders the web port the way the original dashboard reports it
// (string in the JSON payload, e.g. "8082").
func formatPort(port int) string {
	if port <= 0 {
		return ""
	}
	return strconv.Itoa(port)
}

// parseBandwidthBytes converts the monitor's "N B/s" string into the integer
// bytes-per-second value the original dashboard reports (io_recv / io_send).
func parseBandwidthBytes(s string) int {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, " B/s")
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return int(v)
}
