package c2engine

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStorageSQLiteRoundTrip verifies the decoded SQL schema + statements work:
// the 4 decoded tables are created, Store* round-trips through the decoded
// INSERT OR REPLACE statements, and Load* reads back via the decoded SELECTs.
func TestStorageSQLiteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "data.db")

	s := NewStorage(dbPath)
	if s.db == nil {
		t.Fatal("sqlite db not opened")
	}

	// clients round-trip
	clients := map[int64]*Client{
		1: {
			ID:        1,
			IsConnect: true,
			VerifyKey: "vkey-1",
			Type:      "tcp",
			Addr:      "1.2.3.4:5555",
			Remark:    "test-client",
			Status:    true,
			LocalIP:   "10.0.0.1",
			UserName:  "admin",
			HostName:  "HOST-1",
			Location:  "CN",
			OsName:    "Windows",
			ProcessName: "agent.exe",
			PingCheckTime: 12345,
			RateLimit: 10,
			Flow:      &Flow{Inlet: 100, Export: 200, ImportFlow: 300},
			NoStore:   false,
			NoDisplay: false,
			MaxConn:   5,
			NowConn:   2,
		},
	}
	s.StoreClients(clients)

	loaded := map[int64]*Client{}
	var seq int64
	if err := s.LoadClients(loaded, &seq); err != nil {
		t.Fatalf("load clients: %v", err)
	}
	c, ok := loaded[1]
	if !ok {
		t.Fatal("client 1 not loaded")
	}
	if c.VerifyKey != "vkey-1" || c.Addr != "1.2.3.4:5555" || c.OsName != "Windows" {
		t.Fatalf("client fields mismatch: %+v", c)
	}
	if c.Flow == nil || c.Flow.Inlet != 100 || c.Flow.Export != 200 {
		t.Fatalf("flow mismatch: %+v", c.Flow)
	}
	if seq != 1 {
		t.Fatalf("seq = %d, want 1", seq)
	}

	// listeners round-trip
	listeners := map[int64]*Listener{
		1: {
			ID:          1,
			Status:      true,
			ListenAddr:  "0.0.0.0:8080",
			ConnectAddr: "1.2.3.4:8080",
			Remark:      "test-listener",
			Mode:        "tcp",
			VerifyKey:   "lvkey",
			EncryptSalt: "salt",
			DisconnectTimeout: 60,
			PingInterval: 10,
			DNSDomain:   "example.com",
			PublicDNS:   "8.8.8.8",
			MaxDNSsize:  255,
			OssUrl:      "",
			NoStore:     false,
		},
	}
	s.StoreListeners(listeners)
	loadedL := map[int64]*Listener{}
	var lseq int64
	if err := s.LoadListeners(loadedL, &lseq); err != nil {
		t.Fatalf("load listeners: %v", err)
	}
	l, ok := loadedL[1]
	if !ok || l.ListenAddr != "0.0.0.0:8080" || l.Mode != "tcp" || l.VerifyKey != "lvkey" {
		t.Fatalf("listener mismatch: %+v", l)
	}

	// hosts round-trip
	hosts := map[int64]*Host{
		1: {
			ID:        1,
			ClientID:  1,
			Host:      "example.com",
			TargetStr: "1.2.3.4:80",
			Scheme:    "http",
			Remark:    "test-host",
			Flow:      &Flow{Inlet: 5, Export: 6},
		},
	}
	s.StoreHosts(hosts)
	loadedH := map[int64]*Host{}
	var hseq int64
	if err := s.LoadHosts(loadedH, &hseq); err != nil {
		t.Fatalf("load hosts: %v", err)
	}
	h, ok := loadedH[1]
	if !ok || h.Host != "example.com" || h.TargetStr != "1.2.3.4:80" {
		t.Fatalf("host mismatch: %+v", h)
	}

	// tasks round-trip (persisted into the tunnels table per the binary)
	tasks := map[int64]*Task{
		1: {ID: 1, ClientID: 1, Command: "dir", Result: "ok", Status: "completed"},
	}
	s.StoreTasks(tasks)
	loadedT := map[int64]*Task{}
	var tseq int64
	if err := s.LoadTasks(loadedT, &tseq); err != nil {
		t.Fatalf("load tasks: %v", err)
	}
	tt, ok := loadedT[1]
	if !ok {
		t.Fatal("task 1 not loaded")
	}
	if tt.Command != "dir" || tt.Result != "ok" {
		t.Fatalf("task mismatch: %+v", tt)
	}

	// deletes
	s.DelClient(1)
	loaded = map[int64]*Client{}
	seq = 0
	_ = s.LoadClients(loaded, &seq)
	if _, ok := loaded[1]; ok {
		t.Fatal("client 1 not deleted")
	}

	s.db.Close()
	_ = os.RemoveAll(dir)
}
