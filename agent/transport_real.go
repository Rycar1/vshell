package main

// transportReal implements the agent transport layer aligned to the binary
// (0xfc0000-0xfd0000, sessions 534-535 maps):
//
//   - pooled connections: FUN_00fc7560 (get-or-create, fold-compare reuse,
//     refcount +0x8c, conn chain +0x48, global pool DAT_1e4909c8)
//   - connect core: FUN_00fc9de0 (mode dispatch WS=2 / TCP, dial loop with
//     bounded retry/backoff, register token 0xc48d)
//   - wire: <u32 LE len><[16B IV][ct]> (message_wire.go encryptFrame)
//
// This mirrors the mapped pool structure; the socket dialect (KCP vs raw
// TCP) is selected by the server listener mode.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// poolEntry mirrors FUN_00fc7560's pool entry: +0x04 name, +0x48 conn chain,
// +0x8c refcount, +0x4c next.
type poolEntry struct {
	name     string
	conn     *realConn
	refcount int
	next     *poolEntry
}

// realConn is a single transport connection with its send/receive state.
type realConn struct {
	mu       sync.Mutex
	nc       net.Conn
	sessKeys sessionKeys
	counter  messageCounter
}

// transportReal is the pooled transport (FUN_00fc7560 semantics).
type transportReal struct {
	mu    sync.Mutex
	pool  *poolEntry // DAT_1e4909c8 equivalent
	cfg   transportCfg
}

// transportCfg mirrors dialer +0x8 config (+0x30 hostname, +0x8 cfg).
type transportCfg struct {
	hostname string
	mode     int // 2 = ws, else tcp (binary: DAT_1e490794)
	verify   string
	salt     string
}

// getOrCreateConnection mirrors FUN_00fc7560: fold-compare name against the
// pool; reuse on hit (refcount++), else dial via connectCore.
func (t *transportReal) getOrCreateConnection() (*realConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for e := t.pool; e != nil; e = e.next {
		if foldCompare(e.name, t.cfg.hostname) == 0 {
			e.refcount++
			return e.conn, nil
		}
	}

	conn, err := t.connectCore()
	if err != nil {
		return nil, err
	}
	t.pool = &poolEntry{name: t.cfg.hostname, conn: conn, refcount: 1, next: t.pool}
	return conn, nil
}

// connectCore mirrors FUN_00fc9de0: dial with bounded retry/backoff.
func (t *transportReal) connectCore() (*realConn, error) {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		nc, err := net.DialTimeout("tcp", t.cfg.hostname, 10*time.Second)
		if err == nil {
			return &realConn{nc: nc}, nil
		}
		lastErr = err
		time.Sleep(time.Duration(1<<uint(attempt)) * 500 * time.Millisecond)
	}
	return nil, lastErr
}

// sendFrame encrypts payload (message_wire.go) and writes <u32 LE len><frame>.
func (c *realConn) sendFrame(sk *sessionKeys, counter *messageCounter, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	msg := encryptFrame(sk, counter, payload)
	if err := c.nc.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	_, err := c.nc.Write(msg)
	return err
}

// readFrame reads <u32 LE len><frame> and returns the frame.
func (c *realConn) readFrame() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var hdr [4]byte
	if err := c.nc.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(c.nc, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n == 0 || n > 1<<20 {
		return nil, errors.New("bad frame length")
	}
	frame := make([]byte, n)
	if _, err := io.ReadFull(c.nc, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

// deriveSessionKeys derives the session key material from the config
// (binary: key0/key2 at 0xbb20e0/0xbb20f0 are runtime-populated from the
// checkin config; here we derive a stable 32B session key).
func deriveSessionKeys(verify, salt string) sessionKeys {
	h := sha256.Sum256([]byte(salt + ":" + verify))
	var sk sessionKeys
	copy(sk.key0[:], h[:16])
	copy(sk.key2[:], h[16:32])
	return sk
}

// foldCompare is the fold-compare used by the pool (DAT_1e2f00a0 semantics).
func foldCompare(a, b string) int {
	// case-fold compare: lower-case both, byte compare
	la, lb := len(a), len(b)
	n := la
	if lb < n {
		n = lb
	}
	for i := 0; i < n; i++ {
		ca, cb := lowerByte(a[i]), lowerByte(b[i])
		if ca != cb {
			if ca < cb {
				return -1
			}
			return 1
		}
	}
	if la < lb {
		return -1
	}
	if la > lb {
		return 1
	}
	return 0
}

func lowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}
