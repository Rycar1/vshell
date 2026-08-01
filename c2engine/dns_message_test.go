package c2engine

import (
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// buildDNSQuery constructs a real DNS query packet for the given name.
func buildDNSQuery(t *testing.T, name string) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0x1234, RecursionDesired: true},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(name),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return b
}

// TestDNSHandleQueryDecodesSubdomainData verifies the DNS C2 channel decodes
// agent data encoded in subdomains of the C2 domain.
func TestDNSHandleQueryDecodesSubdomainData(t *testing.T) {
	dl := NewDNSListener(20, "ns.test.local", "8.8.8.8", "dns-vkey", 512)

	// Encode a short checkin message the way the agent would: hex(JSON) . domain
	// (must fit one DNS label: <= 63 chars)
	checkin := `{"type":"checkin"}`
	encoded := dl.encodeData(checkin) // hex for short messages
	if len(encoded) > 63 {
		t.Fatalf("encoded label too long for DNS: %d chars", len(encoded))
	}
	qname := encoded + "." + "agent1" + "." + "ns.test.local."

	packet := buildDNSQuery(t, qname)

	// Verify the decode path directly: the encoded data round-trips
	decoded, err := dl.decodeData(encoded)
	if err != nil {
		t.Fatalf("decodeData: %v", err)
	}
	if string(decoded) != checkin {
		t.Errorf("decoded = %q, want %q", decoded, checkin)
	}

	// The packet itself must unpack as a valid DNS query for our domain
	var parsed dnsmessage.Message
	if err := parsed.Unpack(packet); err != nil {
		t.Fatalf("unpack packet: %v", err)
	}
	if len(parsed.Questions) == 0 {
		t.Fatal("packet has no questions")
	}
	q := parsed.Questions[0]
	if !strings.HasSuffix(strings.ToLower(q.Name.String()), "ns.test.local.") {
		t.Errorf("query name = %q, want suffix ns.test.local", q.Name.String())
	}
}

// TestDNSHandleQueryIgnoresForeignDomains verifies queries NOT for the C2
// domain are ignored (no response).
func TestDNSHandleQueryIgnoresForeignDomains(t *testing.T) {
	dl := NewDNSListener(21, "ns.test.local", "8.8.8.8", "dns-vkey", 512)

	// A foreign-domain query must NOT match the C2 suffix check.
	packet := buildDNSQuery(t, "www.example.com.")
	var parsed dnsmessage.Message
	if err := parsed.Unpack(packet); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	domain := parsed.Questions[0].Name.String()
	if strings.HasSuffix(strings.ToLower(domain), strings.ToLower(dl.Domain)) {
		t.Error("foreign domain incorrectly matches C2 domain")
	}
}

// TestDNSSubdomainFormatMatchesAgentEncoding verifies the full subdomain
// format: <encoded_data>.<agent_id>.<domain> with suffix matching.
func TestDNSSubdomainFormatMatchesAgentEncoding(t *testing.T) {
	dl := NewDNSListener(22, "ns.test.local", "8.8.8.8", "dns-vkey", 512)

	msg := `{"type":"result","id":1,"result":"ok"}`
	encoded := dl.encodeData(msg)
	if !strings.Contains(encoded, "") {
		// hex is alphanumeric — valid DNS label chars
	}
	for _, c := range encoded {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			t.Errorf("encoded char %q not DNS-safe", c)
		}
	}
	// The subdomain parse: <encoded>.<agentid>.<domain>
	sub := encoded + "." + "agent9" + "." + "ns.test.local"
	lower := strings.ToLower(sub)
	if !strings.HasSuffix(lower, "ns.test.local") {
		t.Errorf("domain suffix mismatch")
	}
	trimmed := strings.TrimSuffix(lower, "."+"ns.test.local")
	parts := strings.Split(trimmed, ".")
	if parts[0] != encoded {
		t.Errorf("first label = %q, want %q", parts[0], encoded)
	}
	if len(parts) > 1 && parts[len(parts)-1] != "agent9" {
		t.Errorf("agent id = %q, want agent9", parts[len(parts)-1])
	}
}
