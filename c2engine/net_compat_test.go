package c2engine

import (
	"net"
	"testing"
)

func TestNetUnixConnCompatibilityAnchor(t *testing.T) {
	var unixConn *net.UnixConn
	if unixConn != nil {
		t.Fatalf("expected nil UnixConn anchor, got %v", unixConn)
	}
}

func TestNetTCPConnCompatibilityAnchor(t *testing.T) {
	var tcpConn *net.TCPConn
	if tcpConn != nil {
		t.Fatalf("expected nil TCPConn anchor, got %v", tcpConn)
	}
}

func TestNetUDPConnCompatibilityAnchor(t *testing.T) {
	var udpConn *net.UDPConn
	if udpConn != nil {
		t.Fatalf("expected nil UDPConn anchor, got %v", udpConn)
	}
}

func TestNetUnixListenerCompatibilityAnchor(t *testing.T) {
	var unixListener *net.UnixListener
	if unixListener != nil {
		t.Fatalf("expected nil UnixListener anchor, got %v", unixListener)
	}
}
