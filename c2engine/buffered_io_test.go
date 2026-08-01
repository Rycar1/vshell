package c2engine

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type stubBufferedConn struct {
	localAddr     net.Addr
	remoteAddr    net.Addr
	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time
}

func (c *stubBufferedConn) Read(_ []byte) (int, error)    { return 0, io.EOF }
func (c *stubBufferedConn) Write(p []byte) (int, error)   { return len(p), nil }
func (c *stubBufferedConn) Close() error                  { return nil }
func (c *stubBufferedConn) LocalAddr() net.Addr           { return c.localAddr }
func (c *stubBufferedConn) RemoteAddr() net.Addr          { return c.remoteAddr }
func (c *stubBufferedConn) SetDeadline(t time.Time) error { c.deadline = t; return nil }
func (c *stubBufferedConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}
func (c *stubBufferedConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

func TestBufferedIOBufferreadRequestReadsHTTPRequest(t *testing.T) {
	bio := &BufferedIO{
		reader: bufio.NewReader(strings.NewReader("GET /api/ping HTTP/1.1\r\nHost: example.com\r\n\r\n")),
	}

	req, err := bio.BufferreadRequest()
	if err != nil {
		t.Fatalf("BufferreadRequest returned error: %v", err)
	}
	if req.Method != "GET" {
		t.Fatalf("expected method GET, got %q", req.Method)
	}
	if req.URL.Path != "/api/ping" {
		t.Fatalf("expected path /api/ping, got %q", req.URL.Path)
	}
	if req.Host != "example.com" {
		t.Fatalf("expected host example.com, got %q", req.Host)
	}
}

func TestBufferedIOUnreadByteDelegatesToReader(t *testing.T) {
	bio := &BufferedIO{reader: bufio.NewReader(strings.NewReader("ab"))}

	first, err := bio.reader.ReadByte()
	if err != nil {
		t.Fatalf("ReadByte returned error: %v", err)
	}
	if first != 'a' {
		t.Fatalf("expected first byte a, got %q", first)
	}
	if err := bio.UnreadByte(); err != nil {
		t.Fatalf("UnreadByte returned error: %v", err)
	}
	again, err := bio.reader.ReadByte()
	if err != nil {
		t.Fatalf("ReadByte after UnreadByte returned error: %v", err)
	}
	if again != 'a' {
		t.Fatalf("expected unread byte a, got %q", again)
	}
}

func TestBufferedIOUnreadRuneDelegatesToReader(t *testing.T) {
	bio := &BufferedIO{reader: bufio.NewReader(strings.NewReader("界面"))}

	first, _, err := bio.reader.ReadRune()
	if err != nil {
		t.Fatalf("ReadRune returned error: %v", err)
	}
	if first != '界' {
		t.Fatalf("expected first rune 界, got %q", first)
	}
	if err := bio.UnreadRune(); err != nil {
		t.Fatalf("UnreadRune returned error: %v", err)
	}
	again, _, err := bio.reader.ReadRune()
	if err != nil {
		t.Fatalf("ReadRune after UnreadRune returned error: %v", err)
	}
	if again != '界' {
		t.Fatalf("expected unread rune 界, got %q", again)
	}
}

func TestBufferedIOBufferedDelegatesToReader(t *testing.T) {
	bio := &BufferedIO{reader: bufio.NewReader(strings.NewReader("buffered"))}

	if _, err := bio.reader.Peek(3); err != nil {
		t.Fatalf("Peek returned error: %v", err)
	}
	want := bio.reader.Buffered()
	if got := bio.Buffered(); got != want {
		t.Fatalf("expected buffered count %d, got %d", want, got)
	}
}

func TestBufferedIOLocalAddrDelegatesToConn(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444}
	bio := &BufferedIO{conn: &stubBufferedConn{localAddr: local}}

	if got := bio.LocalAddr(); got != local {
		t.Fatalf("expected local addr %v, got %v", local, got)
	}
}

func TestBufferedIORemoteAddrDelegatesToConn(t *testing.T) {
	remote := &net.TCPAddr{IP: net.ParseIP("10.0.0.8"), Port: 9001}
	bio := &BufferedIO{conn: &stubBufferedConn{remoteAddr: remote}}

	if got := bio.RemoteAddr(); got != remote {
		t.Fatalf("expected remote addr %v, got %v", remote, got)
	}
}

func TestBufferedIOSetDeadlineDelegatesToConn(t *testing.T) {
	conn := &stubBufferedConn{}
	bio := &BufferedIO{conn: conn}
	deadline := time.Unix(1700000000, 0)

	if err := bio.SetDeadline(deadline); err != nil {
		t.Fatalf("SetDeadline returned error: %v", err)
	}
	if !conn.deadline.Equal(deadline) {
		t.Fatalf("expected deadline %v, got %v", deadline, conn.deadline)
	}
}

func TestBufferedIOSetReadDeadlineDelegatesToConn(t *testing.T) {
	conn := &stubBufferedConn{}
	bio := &BufferedIO{conn: conn}
	deadline := time.Unix(1700000100, 0)

	if err := bio.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline returned error: %v", err)
	}
	if !conn.readDeadline.Equal(deadline) {
		t.Fatalf("expected read deadline %v, got %v", deadline, conn.readDeadline)
	}
}

func TestBufferedIOSetWriteDeadlineDelegatesToConn(t *testing.T) {
	conn := &stubBufferedConn{}
	bio := &BufferedIO{conn: conn}
	deadline := time.Unix(1700000200, 0)

	if err := bio.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline returned error: %v", err)
	}
	if !conn.writeDeadline.Equal(deadline) {
		t.Fatalf("expected write deadline %v, got %v", deadline, conn.writeDeadline)
	}
}
