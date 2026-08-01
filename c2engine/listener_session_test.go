package c2engine

import "testing"

func TestC2ListenerGetSessionsReturnsSnapshots(t *testing.T) {
	listener := NewC2Listener(&Listener{ID: 42, Mode: ListenerModeHTTP})
	listener.sessions["sess_42_1"] = &AgentSession{SessionID: "sess_42_1", ClientID: 7, ListenerID: 42, RemoteAddr: "127.0.0.1:5000"}

	sessions := listener.GetSessions()
	if len(sessions) != 1 {
		t.Fatalf("len(GetSessions()) = %d, want 1", len(sessions))
	}
	if sessions[0].SessionID != "sess_42_1" || sessions[0].ClientID != 7 || sessions[0].ListenerID != 42 {
		t.Fatalf("session snapshot = %#v, want stored session", sessions[0])
	}

	// Mutating returned snapshots must not mutate listener-owned session state.
	sessions[0].ClientID = 99
	again := listener.GetSessions()
	if again[0].ClientID != 7 {
		t.Fatalf("GetSessions leaked mutable state: got client %d, want 7", again[0].ClientID)
	}
}
