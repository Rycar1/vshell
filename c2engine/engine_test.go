package c2engine

import "testing"

func TestEngineIsPubClientReturnsStoredClientStatus(t *testing.T) {
	e := &Engine{
		clients: map[int64]*Client{
			1: {ID: 1, Status: true},
			2: {ID: 2, Status: false},
		},
	}

	if !e.IsPubClient(1) {
		t.Fatalf("expected enabled client to be public")
	}
	if e.IsPubClient(2) {
		t.Fatalf("expected disabled client not to be public")
	}
	if e.IsPubClient(3) {
		t.Fatalf("expected missing client not to be public")
	}
}
