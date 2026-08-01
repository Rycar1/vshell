package c2engine

import (
	"testing"
)

func TestEngineVerifyVkey(t *testing.T) {
	e := &Engine{
		clients:   make(map[int64]*Client),
		vkeyIndex: make(map[string]int64),
		storage:   &Storage{},
	}
	c := NewClient(1, "secret-key", "http", "1.2.3.4:80")
	e.clients[1] = c

	if !e.VerifyVkey(1, "secret-key") {
		t.Error("VerifyVkey should accept matching key")
	}
	if e.VerifyVkey(1, "wrong") {
		t.Error("VerifyVkey should reject wrong key")
	}
	if e.VerifyVkey(999, "secret-key") {
		t.Error("VerifyVkey should reject unknown client")
	}
}

func TestEngineTaskCRUD(t *testing.T) {
	e := &Engine{
		clients:   make(map[int64]*Client),
		vkeyIndex: make(map[string]int64),
		tasks:     make(map[int64]*Task),
		storage:   &Storage{},
	}
	e.clients[1] = NewClient(1, "k", "http", "1.2.3.4:80")

	// NewTask (alias of CreateTask)
	task, err := e.NewTask(1, "whoami", 30)
	if err != nil {
		t.Fatalf("NewTask: %v", err)
	}
	if task.ID == 0 || task.ClientID != 1 || task.Command != "whoami" {
		t.Fatalf("task fields wrong: %+v", task)
	}

	// GetTask
	got := e.GetTask(task.ID)
	if got == nil || got.ID != task.ID {
		t.Fatalf("GetTask returned %+v", got)
	}
	if e.GetTask(99999) != nil {
		t.Error("GetTask should return nil for unknown id")
	}

	// DelTask
	if err := e.DelTask(task.ID); err != nil {
		t.Fatalf("DelTask: %v", err)
	}
	if e.GetTask(task.ID) != nil {
		t.Error("task should be gone after DelTask")
	}
	if err := e.DelTask(task.ID); err == nil {
		t.Error("DelTask should error on unknown id")
	}
}

func TestApplicationPingUpdatesSeen(t *testing.T) {
	e := &Engine{
		clients:   make(map[int64]*Client),
		vkeyIndex: make(map[string]int64),
		tasks:     make(map[int64]*Task),
		storage:   &Storage{},
	}
	c := NewClient(1, "k", "http", "1.2.3.4:80")
	old := c.LastSeen
	e.clients[1] = c

	app := &Application{engine: e}
	app.Ping(1)
	// LastSeen must be at or after the pre-Ping value (nanosecond resolution
	// can make the two time.Now() calls identical).
	if c.LastSeen.Before(old) {
		t.Errorf("LastSeen went backwards after Ping (old=%v new=%v)", old, c.LastSeen)
	}
	if c.PingCheckTime == 0 {
		t.Error("PingCheckTime should be set after Ping")
	}
	// Ping on unknown client must not panic
	app.Ping(999)
}

func TestHostConnectionHandlerAuth(t *testing.T) {
	e := &Engine{
		clients:   make(map[int64]*Client),
		vkeyIndex: make(map[string]int64),
		tasks:     make(map[int64]*Task),
		storage:   &Storage{},
	}
	c := NewClient(1, "k", "http", "1.2.3.4:80")
	c.Status = true
	e.clients[1] = c

	cm := &ConnectionManager{engine: e, clientInfo: make(map[int64]*ClientConnectionInfo)}
	cm.clientInfo[1] = &ClientConnectionInfo{}

	h := &HostConnectionHandler{connMgr: cm, clientID: 1}
	if !h.Auth("u", "p") {
		t.Error("Auth should accept a registered active client")
	}

	// Unknown client → reject
	h2 := &HostConnectionHandler{connMgr: cm, clientID: 999}
	if h2.Auth("u", "p") {
		t.Error("Auth should reject unknown client")
	}

	// Blocked client → reject
	c.Status = false
	if h.Auth("u", "p") {
		t.Error("Auth should reject blocked client")
	}
}
