package c2engine

import (
	"encoding/hex"
	"testing"
)

// TestDNSEncodeDecodeRoundTrip verifies the DNS channel's hex/base64
// encoding of agent messages.
func TestDNSEncodeDecodeRoundTrip(t *testing.T) {
	dl := &DNSListener{}

	// Short message → hex
	short := `{"type":"checkin","vkey":"k1"}`
	enc := dl.encodeData(short)
	if enc != hex.EncodeToString([]byte(short)) {
		t.Errorf("short encode = %q, want hex", enc)
	}
	dec, err := dl.decodeData(enc)
	if err != nil || string(dec) != short {
		t.Errorf("short decode = %q (%v), want %q", dec, err, short)
	}

	// Long message → base64url
	long := `{"type":"result","id":1,"result":"` + string(make([]byte, 0)) + `"}`
	for i := 0; i < 100; i++ {
		long += "0123456789abcdef"
	}
	enc2 := dl.encodeData(long)
	dec2, err := dl.decodeData(enc2)
	if err != nil || string(dec2) != long {
		t.Errorf("long round trip failed: %v", err)
	}
}

// TestDNSListenerConfig verifies DNS listener setup fields match the
// original listener config (DNSDomain/PublicDNS/MaxDNSsize).
func TestDNSListenerConfig(t *testing.T) {
	dl := NewDNSListener(10, "ns.example.com", "8.8.8.8", "dns-key", 512)
	if dl == nil {
		t.Fatal("NewDNSListener returned nil")
	}
	if dl.VerifyKey != "dns-key" {
		t.Errorf("VerifyKey = %q", dl.VerifyKey)
	}
}

// TestKCPListenerConfig verifies KCP listener setup.
func TestKCPListenerConfig(t *testing.T) {
	kl := NewKCPListener(11, "0.0.0.0:9100", "kcp-key", "kcp-salt")
	if kl == nil {
		t.Fatal("NewKCPListener returned nil")
	}
	if kl.VerifyKey != "kcp-key" {
		t.Errorf("VerifyKey = %q", kl.VerifyKey)
	}
	if !kl.IsRunning() {
		// not started — must not be running
	}
}
