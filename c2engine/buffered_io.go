package c2engine

import (
	"bufio"
	"net"
	"net/http"
	"time"
)

// BufferedIO 包装带缓冲的协议 I/O。
// BufferedIO wraps buffered protocol I/O.
type BufferedIO struct {
	conn   net.Conn
	reader *bufio.Reader
}

// NewBufferedIO 在连接之上创建带缓冲的 I/O 包装。
// NewBufferedIO creates a buffered I/O wrapper over a connection.
func NewBufferedIO(conn net.Conn) *BufferedIO {
	return &BufferedIO{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

// BufferreadRequest 从缓冲读取器读取一个 HTTP 请求。
// BufferreadRequest reads an HTTP request from the buffered reader.
func (b *BufferedIO) BufferreadRequest() (*http.Request, error) {
	return http.ReadRequest(b.reader)
}

// UnreadByte 将缓冲读取器最后读取的字节退回。
// UnreadByte unreads the last byte read from the buffered reader.
func (b *BufferedIO) UnreadByte() error {
	return b.reader.UnreadByte()
}

// UnreadRune 将缓冲读取器最后读取的 rune 退回。
// UnreadRune unreads the last rune read from the buffered reader.
func (b *BufferedIO) UnreadRune() error {
	return b.reader.UnreadRune()
}

// Buffered 返回读取器中已缓冲的字节数。
// Buffered returns the number of bytes buffered in the reader.
func (b *BufferedIO) Buffered() int {
	return b.reader.Buffered()
}

// Read 从底层缓冲读取器读取（对应原版 Xq5KwGZr4i.(*KAJqdSn).Read）。
// Read reads from the underlying buffered reader.
// Original binary: Xq5KwGZr4i.(*KAJqdSn).Read.
func (b *BufferedIO) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

// ReadByte 读取单个字节（对应原版 Xq5KwGZr4i.(*KAJqdSn).ReadByte）。
// ReadByte reads a single byte.
// Original binary: Xq5KwGZr4i.(*KAJqdSn).ReadByte.
func (b *BufferedIO) ReadByte() (byte, error) {
	return b.reader.ReadByte()
}

// Peek 在不推进读取器的情况下查看接下来 n 个字节（对应原版 Xq5KwGZr4i.(*KAJqdSn).Peek）。
// Peek returns the next n bytes without advancing the reader.
// Original binary: Xq5KwGZr4i.(*KAJqdSn).Peek.
func (b *BufferedIO) Peek(n int) ([]byte, error) {
	return b.reader.Peek(n)
}

// Reader 暴露底层缓冲读取器（对应原版 Xq5KwGZr4i.(*KAJqdSn).Reader）。
// Reader exposes the underlying buffered reader.
// Original binary: Xq5KwGZr4i.(*KAJqdSn).Reader.
func (b *BufferedIO) Reader() *bufio.Reader {
	return b.reader
}

// GetReq 从缓冲读取器读取 HTTP 请求（别名，对应原版 Xq5KwGZr4i.(*KAJqdSn).GetReq）。
// GetReq reads an HTTP request from the buffered reader (alias).
// Original binary: Xq5KwGZr4i.(*KAJqdSn).GetReq.
func (b *BufferedIO) GetReq() (*http.Request, error) {
	return http.ReadRequest(b.reader)
}

// LocalAddr 返回底层连接的本地地址。
// LocalAddr returns the local address of the underlying connection.
func (b *BufferedIO) LocalAddr() net.Addr {
	return b.conn.LocalAddr()
}

// RemoteAddr 返回底层连接的远端地址。
// RemoteAddr returns the remote address of the underlying connection.
func (b *BufferedIO) RemoteAddr() net.Addr {
	return b.conn.RemoteAddr()
}

// SetDeadline sets the deadline of the underlying connection.
func (b *BufferedIO) SetDeadline(t time.Time) error {
	return b.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline of the underlying connection.
func (b *BufferedIO) SetReadDeadline(t time.Time) error {
	return b.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline of the underlying connection.
func (b *BufferedIO) SetWriteDeadline(t time.Time) error {
	return b.conn.SetWriteDeadline(t)
}
