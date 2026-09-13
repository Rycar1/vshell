package c2engine

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// buildAgentResultBlock 构造记录块，形态为复刻端与服务器解析之间的契约
// （不是已恢复的原版线格式，见 agent/main.go「Result frames on the wire」）：
// 0x75 记录（A=0,B=1,C=0，+0x10 为负载长度）+ 0x54 终止记录（A=1,B=1,C=0）
// + 负载文本。依据 FUN_01094ba0 / FUN_0100d160。
func buildAgentResultBlock(text string) []byte {
	b := make([]byte, 48+len(text))
	b[0] = 0x75
	binary.LittleEndian.PutUint32(b[4:], 0)
	binary.LittleEndian.PutUint32(b[8:], 1)
	binary.LittleEndian.PutUint32(b[12:], 0)
	binary.LittleEndian.PutUint64(b[16:], uint64(len(text)))
	b[24] = 0x54
	binary.LittleEndian.PutUint32(b[24+4:], 1)
	binary.LittleEndian.PutUint32(b[24+8:], 1)
	copy(b[48:], text)
	return b
}

// TestDecodeAgentRecordText 验证记录块 → 文本的还原（与 agent 端编码对称）。
func TestDecodeAgentRecordText(t *testing.T) {
	recs := ParseAgentRecordBlock(buildAgentResultBlock("whoami output"))
	if len(recs) != 2 {
		t.Fatalf("记录数 = %d, want 2", len(recs))
	}
	if recs[0].Kind != 0x75 || recs[0].A != 0 || recs[0].B != 1 || recs[0].C != 0 {
		t.Fatalf("记录 0 = %+v", recs[0])
	}
	if recs[1].Kind != 0x54 || recs[1].A != 1 || recs[1].B != 1 {
		t.Fatalf("记录 1 = %+v", recs[1])
	}
	if got := DecodeAgentRecordText(buildAgentResultBlock("whoami output")); got != "whoami output" {
		t.Fatalf("文本 = %q, want %q", got, "whoami output")
	}
	// 标量记录（0x48 + 0x54）不带行内文本：不产生输出，也不 panic。
	if got := DecodeAgentRecordText(buildAgentResultBlock("")); got != "" {
		t.Fatalf("空负载文本 = %q, want \"\"", got)
	}
}

// TestHandlePostResultRecordBlock 验证服务器能从 GCM 帧里解析 agent 现在发出的
// 记录块（而不是只认 ResultRequest JSON），且凭据规则不误伤记录块。
func TestHandlePostResultRecordBlock(t *testing.T) {
	e := GetEngine()
	e.Init(&Config{DBPath: "db/data.db"})

	listener := &Listener{
		ID:          77,
		Status:      true,
		ListenAddr:  "127.0.0.1:0",
		Mode:        "http",
		VerifyKey:   "rec-vkey",
		EncryptSalt: "rec-salt",
	}
	e.listeners[77] = listener
	cl := NewC2Listener(listener)

	client, err := e.NewClient("rec-vkey", "http", "127.0.0.1:1234", "10.0.0.5",
		"user", "host", "linux", "agent", "amd64")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// 会话由签到写入；记录块不带 client id，归属依赖这张表。
	cl.sessions["s1"] = &AgentSession{SessionID: "s1", ClientID: client.ID, ListenerID: listener.ID}

	body, err := FrameEncrypt(buildAgentResultBlock("hello from agent"), listener.EncryptSalt)
	if err != nil {
		t.Fatalf("FrameEncrypt: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/result", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	cl.handlePostResult(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("记录块结果被拒：status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp ResultResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析：%v", err)
	}
	if !resp.Received {
		t.Fatalf("响应 = %+v, want Received=true", resp)
	}

	// 旧版 ResultRequest JSON 仍须可用（兼容既有凭据规则）。
	legacy := ResultRequest{ClientID: client.ID, CommandID: 1, Result: "json path",
		Status: "completed", VerifyKey: "rec-vkey"}
	lb, _ := json.Marshal(legacy)
	enc, err := FrameEncrypt(lb, listener.EncryptSalt)
	if err != nil {
		t.Fatalf("FrameEncrypt legacy: %v", err)
	}
	req2 := httptest.NewRequest(http.MethodPost, "/api/result", bytes.NewReader(enc))
	req2.RemoteAddr = "127.0.0.1:1234"
	w2 := httptest.NewRecorder()
	cl.handlePostResult(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("JSON 路径回归：status = %d, body = %s", w2.Code, w2.Body.String())
	}
}

// TestRecordBlockDroppedWhenAmbiguous 确认无法唯一归属客户端时记录块不会被
// 猜测分配给某个客户端（响应仍为 ok，但 Received=false）。
func TestRecordBlockDroppedWhenAmbiguous(t *testing.T) {
	e := GetEngine()
	e.Init(&Config{DBPath: "db/data.db"})

	listener := &Listener{
		ID: 78, Status: true, ListenAddr: "127.0.0.1:0", Mode: "http",
		VerifyKey: "amb-vkey", EncryptSalt: "amb-salt",
	}
	e.listeners[78] = listener
	cl := NewC2Listener(listener)
	cl.sessions["a"] = &AgentSession{SessionID: "a", ClientID: 1001, ListenerID: listener.ID}
	cl.sessions["b"] = &AgentSession{SessionID: "b", ClientID: 1002, ListenerID: listener.ID}

	body, err := FrameEncrypt(buildAgentResultBlock("ambiguous"), listener.EncryptSalt)
	if err != nil {
		t.Fatalf("FrameEncrypt: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/result", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	cl.handlePostResult(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp ResultResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析：%v", err)
	}
	if resp.Received {
		t.Fatalf("客户端的归属不唯一时不应接收：%+v", resp)
	}
}

// TestRecordBlockNotFoundInJSONPath 确认乱码帧不会被当成记录块接受。
func TestRecordBlockRejectsGarbage(t *testing.T) {
	e := GetEngine()
	e.Init(&Config{DBPath: "db/data.db"})
	listener := &Listener{ID: 79, Status: true, Mode: "http",
		VerifyKey: "g-vkey", EncryptSalt: "g-salt"}
	e.listeners[79] = listener
	cl := NewC2Listener(listener)

	garbage := make([]byte, 25) // 非 24 的整数倍
	for i := range garbage {
		garbage[i] = byte(i)
	}
	body, _ := FrameEncrypt(garbage, listener.EncryptSalt)
	req := httptest.NewRequest(http.MethodPost, "/api/result", bytes.NewReader(body))
	w := httptest.NewRecorder()
	cl.handlePostResult(w, req)
	// 乱码帧既不是记录块也不是合法 JSON 结果，必须被拒绝（400 帧/记录块不合法，
	// 401 JSON 路径缺少凭据 —— 两条都是拒绝，不能当成结果接收）。
	if w.Code != http.StatusBadRequest && w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 400/401", w.Code)
	}
	if strings.Contains(w.Body.String(), `"Received":true`) {
		t.Fatalf("乱码帧被当成结果接收：%s", w.Body.String())
	}
}
