package controllers

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"vshell/models"
)

// TunnelEngine manages all running tunnels and proxies
type TunnelEngine struct {
	mu      sync.RWMutex
	tunnels map[int64]*TunnelInstance
	proxies map[int64]*HostProxy
}

// TunnelInstance represents a running tunnel
type TunnelInstance struct {
	ID        int64     `json:"id"`
	Mode      string    `json:"mode"`
	LocalAddr string    `json:"local_addr"`
	StartedAt time.Time `json:"started_at"`
	stopCh    chan struct{}
	listener  net.Listener
	flowIn    int64
	flowOut   int64
	mu        sync.RWMutex
}

// HostProxy represents a running HTTP reverse proxy
type HostProxy struct {
	ID        int64     `json:"id"`
	Host      string    `json:"host"`
	Scheme    string    `json:"scheme"`
	StartedAt time.Time `json:"started_at"`
	server    *http.Server
	stopCh    chan struct{}
	flowIn    int64
	flowOut   int64
	mu        sync.RWMutex
}

var tunnelMgr = &TunnelEngine{
	tunnels: make(map[int64]*TunnelInstance),
	proxies: make(map[int64]*HostProxy),
}

// ========== Tunnel Operations ==========

// StartTunnel starts a new tunnel
func (te *TunnelEngine) StartTunnel(config *models.Tunnel) (*TunnelInstance, error) {
	te.mu.Lock()
	defer te.mu.Unlock()

	if _, exists := te.tunnels[config.ID]; exists {
		return nil, fmt.Errorf("tunnel %d already running", config.ID)
	}

	t := &TunnelInstance{
		ID:        config.ID,
		Mode:      config.Mode,
		LocalAddr: fmt.Sprintf("0.0.0.0:%d", config.Port),
		StartedAt: time.Now(),
		stopCh:    make(chan struct{}),
	}

	switch config.Mode {
	case "tcp":
		if err := te.startTCPTunnel(t, config); err != nil {
			return nil, err
		}
	case "socks5":
		if err := te.startSocksTunnel(t, config); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported tunnel mode: %s", config.Mode)
	}

	te.tunnels[config.ID] = t
	log.Printf("[Tunnel] Started %s tunnel %d on %s -> client %d (target: %s)",
		config.Mode, config.ID, t.LocalAddr, config.ClientID, config.TargetAddr)
	return t, nil
}

func (te *TunnelEngine) startTCPTunnel(t *TunnelInstance, config *models.Tunnel) error {
	listener, err := net.Listen("tcp", t.LocalAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", t.LocalAddr, err)
	}
	t.listener = listener

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-t.stopCh:
					return
				default:
					log.Printf("[Tunnel %d] Accept error: %v", t.ID, err)
					continue
				}
			}
			go handleTCPProxy(conn, config)
		}
	}()
	return nil
}

func (te *TunnelEngine) startSocksTunnel(t *TunnelInstance, config *models.Tunnel) error {
	listener, err := net.Listen("tcp", t.LocalAddr)
	if err != nil {
		return fmt.Errorf("listen SOCKS %s: %w", t.LocalAddr, err)
	}
	t.listener = listener

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-t.stopCh:
					return
				default:
					log.Printf("[SOCKS %d] Accept error: %v", t.ID, err)
					continue
				}
			}
			go handleSocksProxy(conn, config, t)
		}
	}()
	return nil
}

func handleTCPProxy(localConn net.Conn, config *models.Tunnel) {
	defer localConn.Close()

	targetAddr := config.TargetAddr
	if targetAddr == "" {
		targetAddr = "127.0.0.1:22"
	}

	remoteConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Printf("[Tunnel] Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer remoteConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(remoteConn, localConn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(localConn, remoteConn)
	}()
	wg.Wait()
}

func handleSocksProxy(conn net.Conn, config *models.Tunnel, t *TunnelInstance) {
	defer conn.Close()

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	authMethod := byte(0x00)
	if config.Username != "" {
		authMethod = 0x02
	}
	conn.Write([]byte{0x05, authMethod})

	if authMethod == 0x02 {
		n, err = conn.Read(buf)
		if err != nil || n < 5 || buf[0] != 0x01 {
			return
		}
		ulen := int(buf[1])
		if ulen < 0 || ulen > 255 || 2+ulen > n {
			return
		}
		uname := string(buf[2 : 2+ulen])
		if 2+ulen >= n {
			return
		}
		plen := int(buf[2+ulen])
		if plen < 0 || plen > 255 || 3+ulen+plen > n {
			return
		}
		passwd := string(buf[3+ulen : 3+ulen+plen])
		if uname != config.Username || passwd != config.Password {
			conn.Write([]byte{0x01, 0xFF})
			return
		}
		conn.Write([]byte{0x01, 0x00})
	}

	n, err = conn.Read(buf)
	if err != nil || n < 4 {
		return
	}

	if buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	var targetAddr string
	atyp := buf[3]
	switch atyp {
	case 0x01:
		if n < 10 {
			return
		}
		targetAddr = fmt.Sprintf("%s:%d", net.IP(buf[4:8]).String(), (int(buf[8])<<8)|int(buf[9]))
	case 0x03:
		addrLen := int(buf[4])
		if addrLen < 1 || addrLen > 255 || 5+addrLen+2 > n {
			return
		}
		targetAddr = fmt.Sprintf("%s:%d", string(buf[5:5+addrLen]), (int(buf[5+addrLen])<<8)|int(buf[6+addrLen]))
	case 0x04:
		if n < 22 {
			return
		}
		targetAddr = fmt.Sprintf("%s:%d", net.IP(buf[4:20]).String(), (int(buf[20])<<8)|int(buf[21]))
	default:
		return
	}

	remote, err := net.Dial("tcp", targetAddr)
	if err != nil {
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer remote.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr)
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01,
		localAddr.IP.To4()[0], localAddr.IP.To4()[1],
		localAddr.IP.To4()[2], localAddr.IP.To4()[3],
		byte(localAddr.Port >> 8), byte(localAddr.Port & 0xFF)})

	t.mu.Lock()
	t.flowIn++
	t.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(remote, conn) }()
	go func() { defer wg.Done(); io.Copy(conn, remote) }()
	wg.Wait()
}

// StopTunnel stops a running tunnel
func (te *TunnelEngine) StopTunnel(id int64) error {
	te.mu.Lock()
	defer te.mu.Unlock()

	t, exists := te.tunnels[id]
	if !exists {
		return nil
	}

	close(t.stopCh)
	if t.listener != nil {
		t.listener.Close()
	}
	delete(te.tunnels, id)
	log.Printf("[Tunnel] Stopped tunnel %d", id)
	return nil
}

// GetTunnelStatus returns the status of a tunnel
func (te *TunnelEngine) GetTunnelStatus(id int64) *TunnelInstance {
	te.mu.RLock()
	defer te.mu.RUnlock()
	return te.tunnels[id]
}

// ListTunnels returns all active tunnels
func (te *TunnelEngine) ListTunnels() []*TunnelInstance {
	te.mu.RLock()
	defer te.mu.RUnlock()
	result := make([]*TunnelInstance, 0, len(te.tunnels))
	for _, t := range te.tunnels {
		result = append(result, t)
	}
	return result
}

// ========== Reverse Proxy Operations ==========

// StartHostProxy starts an HTTP reverse proxy
func (te *TunnelEngine) StartHostProxy(config *models.Host) (*HostProxy, error) {
	te.mu.Lock()
	defer te.mu.Unlock()

	if _, exists := te.proxies[config.ID]; exists {
		return nil, fmt.Errorf("proxy %d already running", config.ID)
	}

	hp := &HostProxy{
		ID:        config.ID,
		Host:      config.Host,
		Scheme:    config.Scheme,
		StartedAt: time.Now(),
		stopCh:    make(chan struct{}),
	}

	rp := &reverseProxy{config: config, hp: hp}

	hp.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", config.ID%57536+8000),
		Handler: rp,
	}

	go func() {
		log.Printf("[Proxy] Starting reverse proxy %d for %s", config.ID, config.Host)
		if err := hp.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Proxy %d] Error: %v", config.ID, err)
		}
	}()

	te.proxies[config.ID] = hp
	return hp, nil
}

// StopHostProxy stops a reverse proxy
func (te *TunnelEngine) StopHostProxy(id int64) error {
	te.mu.Lock()
	defer te.mu.Unlock()

	hp, exists := te.proxies[id]
	if !exists {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hp.server.Shutdown(ctx)
	delete(te.proxies, id)
	log.Printf("[Proxy] Stopped proxy %d", id)
	return nil
}

// reverseProxy implements http.Handler for reverse proxying
type reverseProxy struct {
	config *models.Host
	hp     *HostProxy
}

func (rp *reverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rp.hp.mu.Lock()
	rp.hp.flowIn++
	rp.hp.mu.Unlock()

	targetStr := rp.config.TargetStr
	if targetStr == "" {
		http.Error(w, "no upstream target", 502)
		return
	}

	scheme := rp.config.Scheme
	if scheme == "" {
		scheme = "http"
	}

	upstreamURL := fmt.Sprintf("%s://%s%s", scheme, targetStr, r.URL.Path)
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	proxyReq, err := http.NewRequest(r.Method, upstreamURL, r.Body)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}

	for key, values := range r.Header {
		for _, v := range values {
			proxyReq.Header.Add(key, v)
		}
	}
	if rp.config.HostChange != "" {
		proxyReq.Host = rp.config.HostChange
	}
	if rp.config.HeaderChange != "" {
		parts := strings.SplitN(rp.config.HeaderChange, ":", 2)
		if len(parts) == 2 {
			proxyReq.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	n, _ := io.Copy(w, resp.Body)
	rp.hp.mu.Lock()
	rp.hp.flowOut += n
	rp.hp.mu.Unlock()
}
