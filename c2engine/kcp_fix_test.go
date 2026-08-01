package c2engine

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

// testKCPClient mirrors the agent's kcpTransport wire protocol:
// kcp-go UDP session, bare-JSON check-in handshake, then
// [2-byte length][LinkMsgType][payload] frames.
type testKCPClient struct {
	sess *kcp.UDPSession
}

func dialTestKCP(addr, salt, vkey string) (*testKCPClient, error) {
	sess, err := kcp.DialWithOptions(addr, kcpBlockCrypt(salt, vkey), 10, 3)
	if err != nil {
		return nil, err
	}
	sess.SetStreamMode(true)
	sess.SetWriteDelay(false)
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(128, 128)
	sess.SetMtu(1350)
	return &testKCPClient{sess: sess}, nil
}

func (c *testKCPClient) writeFrame(msgType LinkMsgType, payload []byte) error {
	msg := make([]byte, 1+len(payload))
	msg[0] = byte(msgType)
	copy(msg[1:], payload)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(msg)))
	c.sess.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := c.sess.Write(append(lenBuf, msg...))
	return err
}

func (c *testKCPClient) readFrame() (LinkMsgType, []byte, error) {
	lenBuf := make([]byte, 2)
	c.sess.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.ReadFull(c.sess, lenBuf); err != nil {
		return 0, nil, err
	}
	data := make([]byte, binary.BigEndian.Uint16(lenBuf))
	if _, err := io.ReadFull(c.sess, data); err != nil {
		return 0, nil, err
	}
	if len(data) == 0 {
		return 0, nil, nil
	}
	return LinkMsgType(data[0]), data[1:], nil
}

func (c *testKCPClient) close() { c.sess.Close() }

// TestKCPListenerEndToEnd verifies the KCP listener accepts the agent's
// kcp-go client protocol: bare-JSON handshake, check-in response with the
// client ID, task polling, and result submission (with verify-key auth).
func TestKCPListenerEndToEnd(t *testing.T) {
	cfg := &Config{DBPath: "db/data.db"}
	e := GetEngine()
	e.Init(cfg)

	const vkey = "short" // short key: previously panicked in the [:32] slice
	kl := NewKCPListener(9000, "127.0.0.1:0", vkey, "")
	if err := kl.Start(); err != nil {
		t.Fatalf("Start (short key must not panic): %v", err)
	}
	defer kl.Stop()

	addr := kl.listener.Addr().String()

	client, err := dialTestKCP(addr, "", vkey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.close()

	// 1. Handshake: bare JSON (no length prefix, no type byte).
	hs, _ := json.Marshal(map[string]interface{}{
		"verify_key": vkey,
		"hostname":   "e2e-host",
		"username":   "e2e-user",
		"os":         "linux",
		"process":    "agent",
	})
	client.sess.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := client.sess.Write(hs); err != nil {
		t.Fatalf("handshake write: %v", err)
	}

	msgType, resp, err := client.readFrame()
	if err != nil {
		t.Fatalf("read checkin response: %v", err)
	}
	if msgType != LinkMsgMain {
		t.Fatalf("checkin response type = %d, want %d", msgType, LinkMsgMain)
	}
	var cr CheckinResponse
	if err := json.Unmarshal(resp, &cr); err != nil {
		t.Fatalf("checkin resp: %v", err)
	}
	if cr.ClientID == 0 {
		t.Fatal("checkin response did not assign a client id")
	}

	// 2. Task poll (empty first).
	poll := func() TaskResponse {
		req, _ := json.Marshal(map[string]interface{}{
			"type":       "task_poll",
			"client_id":  cr.ClientID,
			"verify_key": vkey,
		})
		if err := client.writeFrame(LinkMsgMain, req); err != nil {
			t.Fatalf("task poll write: %v", err)
		}
		_, data, err := client.readFrame()
		if err != nil {
			t.Fatalf("task poll read: %v", err)
		}
		var tr TaskResponse
		if err := json.Unmarshal(data, &tr); err != nil {
			t.Fatalf("task poll resp: %v", err)
		}
		return tr
	}

	if tr := poll(); len(tr.Tasks) != 0 {
		t.Fatalf("expected no tasks, got %d", len(tr.Tasks))
	}

	// 3. Queue a task, then poll: the task must be delivered.
	task, err := e.CreateTask(cr.ClientID, "shell echo hi", 10)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	tr := poll()
	if len(tr.Tasks) != 1 || tr.Tasks[0].ID != task.ID || tr.Tasks[0].Command != "shell echo hi" {
		t.Fatalf("task not delivered: %+v", tr.Tasks)
	}

	// 4. Submit a result with the verify key: task must complete.
	body, _ := json.Marshal(ResultRequest{
		ClientID:  cr.ClientID,
		CommandID: task.ID,
		Result:    "hi",
		Status:    "completed",
		VerifyKey: vkey,
	})
	if err := client.writeFrame(LinkMsgMain, body); err != nil {
		t.Fatalf("result write: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		got := e.GetTask(task.ID)
		if got != nil && got.Status == "completed" && got.Result == "hi" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("result was not applied")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 5. Wrong verify key on task poll must be rejected (no task disclosure).
	req, _ := json.Marshal(map[string]interface{}{
		"type":       "task_poll",
		"client_id":  cr.ClientID,
		"verify_key": "wrong-key",
	})
	if err := client.writeFrame(LinkMsgMain, req); err != nil {
		t.Fatalf("bad-key poll write: %v", err)
	}
	// The listener drops the message without a reply; a second valid poll
	// must still work (proving the loop is alive).
	if tr := poll(); len(tr.Tasks) != 0 {
		t.Fatalf("expected no tasks after bad-key poll, got %d", len(tr.Tasks))
	}
}

// TestKCPFragmentReassembly verifies oversized payloads (e.g. screenshots) are
// split into fragments by the agent client and reassembled server-side before
// being applied as a task result.
func TestKCPFragmentReassembly(t *testing.T) {
	cfg := &Config{DBPath: "db/data.db"}
	e := GetEngine()
	e.Init(cfg)

	kl := NewKCPListener(9001, "127.0.0.1:0", "frag-key", "")
	if err := kl.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer kl.Stop()

	client, err := dialTestKCP(kl.listener.Addr().String(), "", "frag-key")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.close()

	hs, _ := json.Marshal(map[string]interface{}{"verify_key": "frag-key", "hostname": "h", "username": "u", "os": "linux", "process": "a"})
	client.sess.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := client.sess.Write(hs); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	_, resp, err := client.readFrame()
	if err != nil {
		t.Fatalf("checkin resp: %v", err)
	}
	var cr CheckinResponse
	json.Unmarshal(resp, &cr)

	task, err := e.CreateTask(cr.ClientID, "shell big", 10)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	// Simulate the agent's fragmentation of a ~150KB result.
	big := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("IMG"), 50000)) // ~200KB
	payload, _ := json.Marshal(ResultRequest{
		ClientID:  cr.ClientID,
		CommandID: task.ID,
		Result:    big,
		Status:    "completed",
		VerifyKey: "frag-key",
	})
	const chunk = 60000 / 4 * 3
	var chunks [][]byte
	for len(payload) > 0 {
		n := len(payload)
		if n > chunk {
			n = chunk
		}
		chunks = append(chunks, payload[:n])
		payload = payload[n:]
	}
	for i, c := range chunks {
		frag, _ := json.Marshal(map[string]interface{}{
			"_frag":  i,
			"_total": len(chunks),
			"_data":  base64.StdEncoding.EncodeToString(c),
		})
		if err := client.writeFrame(LinkMsgMain, frag); err != nil {
			t.Fatalf("frag %d write: %v", i, err)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		got := e.GetTask(task.ID)
		if got != nil && got.Status == "completed" && got.Result == big {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("reassembled result not applied; got status=%v", got)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestEngineBlockedKeyRejectsCheckin verifies the blocklist is enforced on the
// real check-in path (engine.NewClient), keyed by verify key so a fresh client
// ID cannot bypass it.
func TestEngineBlockedKeyRejectsCheckin(t *testing.T) {
	cfg := &Config{DBPath: "db/data.db"}
	e := GetEngine()
	e.Init(cfg)

	e.BlockKey("banned-key")
	defer e.UnblockKey("banned-key")

	_, err := e.NewClient("banned-key", "http", "1.2.3.4:5", "", "u", "h", "linux", "agent")
	if err == nil {
		t.Fatal("NewClient with a blocked verify key should fail")
	}

	// A different key must still be accepted.
	c, err := e.NewClient("allowed-key", "http", "1.2.3.4:5", "", "u", "h", "linux", "agent")
	if err != nil {
		t.Fatalf("NewClient with allowed key failed: %v", err)
	}
	if c == nil {
		t.Fatal("NewClient returned nil client")
	}

	// Unblocking restores access.
	e.UnblockKey("banned-key")
	if _, err := e.NewClient("banned-key", "http", "1.2.3.4:5", "", "u", "h", "linux", "agent"); err != nil {
		t.Fatalf("NewClient after unblock failed: %v", err)
	}
}

// TestKCPBlockCryptShortKey verifies short key material does not panic.
func TestKCPBlockCryptShortKey(t *testing.T) {
	for _, m := range []struct{ salt, key string }{
		{"", "admin"},
		{"s", ""},
		{"", ""},
		{"aVeryLongSaltValueThatExceedsThirtyTwoBytesTotal", "key"},
	} {
		bc := kcpBlockCrypt(m.salt, m.key)
		if bc == nil {
			t.Fatalf("kcpBlockCrypt(%q, %q) returned nil", m.salt, m.key)
		}
	}
}
