package models

import (
	"testing"
	"time"
)

func TestDBPersistsClientsListenersAndCommands(t *testing.T) {
	path := t.TempDir() + "/data.db"
	if err := InitDB(path); err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	db := GetDB()
	if db == nil {
		t.Fatal("GetDB returned nil")
	}
	defer db.Close()

	clientID, err := db.CreateClient(&Client{VerifyKey: "vk", HostName: "host", UserName: "user", Status: true})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if err := db.UpdateClientRemark(clientID, "note"); err != nil {
		t.Fatalf("UpdateClientRemark: %v", err)
	}
	clients, err := db.ListClients()
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(clients) != 1 || clients[0].Remark != "note" {
		t.Fatalf("clients = %#v, want one client with remark", clients)
	}

	if err := db.BlockClient(clientID); err != nil {
		t.Fatalf("BlockClient: %v", err)
	}
	blocked, err := db.GetBlockedClientIDs()
	if err != nil {
		t.Fatalf("GetBlockedClientIDs: %v", err)
	}
	if len(blocked) != 1 || blocked[0] != clientID {
		t.Fatalf("blocked = %#v, want [%d]", blocked, clientID)
	}
	if err := db.UnblockClient(clientID); err != nil {
		t.Fatalf("UnblockClient: %v", err)
	}

	listenerID, err := db.CreateListener(&Listener{ListenAddr: "0.0.0.0:8080", ConnectAddr: "127.0.0.1:8080", Mode: "http", VerifyKey: "vk"})
	if err != nil {
		t.Fatalf("CreateListener: %v", err)
	}
	listener, err := db.GetListener(listenerID)
	if err != nil {
		t.Fatalf("GetListener: %v", err)
	}
	listener.Remark = "updated"
	if err := db.UpdateListener(listener); err != nil {
		t.Fatalf("UpdateListener: %v", err)
	}
	listeners, err := db.ListListeners()
	if err != nil {
		t.Fatalf("ListListeners: %v", err)
	}
	if len(listeners) != 1 || listeners[0].Remark != "updated" {
		t.Fatalf("listeners = %#v, want updated listener", listeners)
	}

	cmdID, err := db.CreateCommand(clientID, "whoami", 30)
	if err != nil {
		t.Fatalf("CreateCommand: %v", err)
	}
	pending, err := db.GetPendingCommands(clientID)
	if err != nil {
		t.Fatalf("GetPendingCommands: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != cmdID {
		t.Fatalf("pending = %#v, want command %d", pending, cmdID)
	}
	if err := db.MarkCommandDispatched(cmdID); err != nil {
		t.Fatalf("MarkCommandDispatched: %v", err)
	}
	if err := db.CompleteCommand(cmdID, "ok", "completed"); err != nil {
		t.Fatalf("CompleteCommand: %v", err)
	}
	cmd, err := db.GetCommand(cmdID)
	if err != nil {
		t.Fatalf("GetCommand: %v", err)
	}
	if cmd.Result != "ok" || cmd.Status != "completed" || cmd.DoneAt == nil {
		t.Fatalf("cmd = %#v, want completed result", cmd)
	}
}

func TestDBPersistsAgentSessions(t *testing.T) {
	path := t.TempDir() + "/sessions.db"
	if err := InitDB(path); err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	db := GetDB()
	if db == nil {
		t.Fatal("GetDB returned nil")
	}
	defer db.Close()

	created := time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)
	lastSeen := created.Add(2 * time.Minute)
	session := &AgentSession{
		ID:          "sess_1",
		ClientID:    7,
		ListenerID:  3,
		Type:        "shell",
		Status:      "initializing",
		RemoteAddr:  "10.0.0.8:4444",
		CreatedAt:   created,
		LastSeen:    lastSeen,
		CommandID:   99,
		Description: "interactive shell",
	}

	if err := db.UpsertAgentSession(session); err != nil {
		t.Fatalf("UpsertAgentSession: %v", err)
	}
	if err := db.UpdateAgentSessionStatus("sess_1", "active", lastSeen.Add(time.Minute)); err != nil {
		t.Fatalf("UpdateAgentSessionStatus: %v", err)
	}

	all, err := db.ListAgentSessions(0)
	if err != nil {
		t.Fatalf("ListAgentSessions all: %v", err)
	}
	if len(all) != 1 || all[0].Status != "active" || all[0].ClientID != 7 || all[0].CommandID != 99 {
		t.Fatalf("all sessions = %#v, want active persisted session", all)
	}

	byClient, err := db.ListAgentSessions(7)
	if err != nil {
		t.Fatalf("ListAgentSessions client: %v", err)
	}
	if len(byClient) != 1 || byClient[0].ID != "sess_1" {
		t.Fatalf("client sessions = %#v, want sess_1", byClient)
	}

	if err := db.DeleteAgentSession("sess_1"); err != nil {
		t.Fatalf("DeleteAgentSession: %v", err)
	}
	afterDelete, err := db.ListAgentSessions(0)
	if err != nil {
		t.Fatalf("ListAgentSessions after delete: %v", err)
	}
	if len(afterDelete) != 0 {
		t.Fatalf("after delete = %#v, want empty", afterDelete)
	}
}
