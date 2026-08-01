package c2engine

import (
	"bufio"
	"strings"
	"testing"
)

// TestLinkAddStatus verifies WriteAddOk/WriteAddFail/GetAddStatus
// (Xq5KwGZr4i.(*XBp86cUq4) equivalents).
func TestLinkAddStatus(t *testing.T) {
	link := NewLink(&stubBufferedConn{}, 1, &Flow{})
	link.WriteAddOk()
	if !link.GetAddStatus() {
		t.Error("GetAddStatus should be true after WriteAddOk")
	}
	link.WriteAddFail()
	if link.GetAddStatus() {
		t.Error("GetAddStatus should be false after WriteAddFail")
	}
}

// TestLinkSetAlive verifies SetAlive refreshes activity time.
func TestLinkSetAlive(t *testing.T) {
	link := NewLink(&stubBufferedConn{}, 1, &Flow{})
	link.SetAlive()
	if link.lastActive.IsZero() {
		t.Error("lastActive should be set after SetAlive")
	}
}

// TestBufferedIOReadMethods verifies the KAJqdSn-equivalent surface
// (Read, ReadByte, Peek, Reader, GetReq) using a strings.Reader.
func TestBufferedIOReadMethods(t *testing.T) {
	bio := &BufferedIO{reader: bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))}

	req, err := bio.GetReq()
	if err != nil {
		t.Fatalf("GetReq: %v", err)
	}
	if req.Method != "GET" || req.Host != "x" {
		t.Errorf("req = %s %s", req.Method, req.Host)
	}
	if bio.Buffered() != 0 {
		t.Errorf("Buffered = %d after full read", bio.Buffered())
	}

	// Read/ReadByte/Peek/Reader on a fresh stream
	bio2 := &BufferedIO{reader: bufio.NewReader(strings.NewReader("abc"))}
	b, err := bio2.ReadByte()
	if err != nil || b != 'a' {
		t.Fatalf("ReadByte = %q, %v", b, err)
	}
	p, err := bio2.Peek(1)
	if err != nil || string(p) != "b" {
		t.Fatalf("Peek = %q, %v", p, err)
	}
	out := make([]byte, 2)
	n, err := bio2.Read(out)
	if err != nil || n != 2 || string(out) != "bc" {
		t.Fatalf("Read = %d %q, %v", n, out, err)
	}
	if bio2.Reader() == nil {
		t.Error("Reader() should not be nil")
	}
}
