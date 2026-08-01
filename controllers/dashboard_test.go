package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDashboardInfoFlatResponse verifies /api/dashboard/info returns the
// original binary's flat field set (clientCount, clientNum, cpu, disk,
// io_recv, io_send, licTime, listenerCount, logLevel, logPath, swap_mem,
// tcpC, tcpCount, udpCount, version, vip, virtual_mem, web_basic_auth,
// web_port, load, ...) — not the nested stats/system shape.
func TestDashboardInfoFlatResponse(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard/info", nil)
	w := httptest.NewRecorder()
	dc := &DashboardController{}
	dc.Init(&Context{Request: req, ResponseWriter: w})
	dc.Prepare()
	dc.Get()

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp struct {
		Code   int                    `json:"code"`
		Result map[string]interface{} `json:"result"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != 0 {
		t.Fatalf("code = %d, want 0: %s", resp.Code, w.Body.String())
	}

	// The original frontend's dashboard component reads these exact keys.
	for _, key := range []string{
		"clientCount", "clientNum", "clientOnlineCount",
		"cpu", "disk", "exportFlowCount", "flowStoreInterval",
		"hostCount", "httpProxyCount", "httpProxyPort", "httpsProxyPort",
		"inletFlowCount", "io_recv", "io_send", "ipLimit",
		"licTime", "listenerCount", "listenerOnlineCount",
		"load", "logLevel", "logPath", "p2pCount", "p2pPort",
		"secretCount", "socks5Count", "swap_mem", "tcpC", "tcpCount",
		"udpCount", "version", "vip", "virtual_mem",
		"web_basic_auth", "web_port",
	} {
		if _, ok := resp.Result[key]; !ok {
			t.Errorf("missing dashboard key %q in: %v", key, resp.Result)
		}
	}

	// web_port must be a string in the original payload (e.g. "8082").
	if v, ok := resp.Result["web_port"].(string); ok {
		if v == "" {
			t.Errorf("web_port empty string")
		}
	} else {
		t.Errorf("web_port should be string, got %T", resp.Result["web_port"])
	}

	// version should be the original binary version string.
	if v, _ := resp.Result["version"].(string); v != "4.9.3" {
		t.Errorf("version = %q, want 4.9.3", v)
	}
}
