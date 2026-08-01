package c2engine

import "testing"

func TestHostConnectionHandlerCheckFlowAndConnNumDelegatesToConnectionManager(t *testing.T) {
	cm := &ConnectionManager{
		engine: &Engine{
			clients: map[int64]*Client{
				1: {ID: 1, Flow: &Flow{}},
			},
		},
		clientInfo: map[int64]*ClientConnectionInfo{
			1: {ClientID: 1, MaxConns: 2, ActiveConns: 1},
		},
	}
	handler := &HostConnectionHandler{connMgr: cm, clientID: 1}

	if !handler.CheckFlowAndConnNum() {
		t.Fatalf("expected host connection handler to allow client within connection and flow limits")
	}

	cm.clientInfo[1].ActiveConns = 2
	if handler.CheckFlowAndConnNum() {
		t.Fatalf("expected host connection handler to reject client at connection limit")
	}
}

func TestHostConnectionHandlerDealClientDelegatesToConnectionManager(t *testing.T) {
	cm := &ConnectionManager{
		engine: &Engine{
			clients: map[int64]*Client{
				1: {ID: 1, Flow: &Flow{}},
			},
		},
		clientInfo: map[int64]*ClientConnectionInfo{
			1: {ClientID: 1, MaxConns: 2, ActiveConns: 0},
		},
	}
	handler := &HostConnectionHandler{connMgr: cm, clientID: 1}

	if err := handler.DealClient(); err != nil {
		t.Fatalf("DealClient returned error: %v", err)
	}
	if got := cm.clientInfo[1].ActiveConns; got != 1 {
		t.Fatalf("expected delegated DealClient to increment active connections to 1, got %d", got)
	}
}

func TestHostConnectionHandlerFlowAddHostDelegatesToConnectionManager(t *testing.T) {
	cm := &ConnectionManager{
		engine: &Engine{
			hosts: map[int64]*Host{
				2: {ID: 2, Flow: &Flow{}},
			},
		},
	}
	handler := &HostConnectionHandler{connMgr: cm, clientID: 1}

	handler.FlowAddHost(2, 11)

	if got := cm.engine.hosts[2].Flow.ExportFlow; got != 11 {
		t.Fatalf("expected delegated FlowAddHost to add export flow 11, got %d", got)
	}
}
