// Package models 提供 Web 管理面板的 SQLite 持久化层（客户端、监听器、命令、会话）。
// Package models provides the SQLite persistence layer for the web management panel
// (clients, listeners, commands, and agent sessions).
package models

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// DB 是 SQLite 数据库的轻量封装，所有读写均经过该结构。
// DB is a lightweight wrapper around the SQLite database; all reads/writes go through it.
type DB struct {
	sql *sql.DB // 底层数据库句柄 / underlying database handle
	mu  sync.Mutex // 写操作互斥锁 / mutex for write operations
}

var (
	globalDB *DB // 全局单例数据库实例 / global singleton database instance
	dbMu     sync.RWMutex // 保护 globalDB 的读写锁 / RWMutex guarding globalDB
)

// InitDB 初始化全局数据库：创建目录、打开 SQLite、执行建表迁移。
// InitDB initializes the global database: creates the directory, opens SQLite, and runs migrations.
func InitDB(path string) error {
	if path == "" {
		path = "db/data.db"
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	db := &DB{sql: sqlDB}
	if err := db.migrate(); err != nil {
		sqlDB.Close()
		return err
	}
	dbMu.Lock()
	globalDB = db
	dbMu.Unlock()
	return nil
}

// GetDB 返回全局数据库实例（可能为 nil，需先调用 InitDB）。
// GetDB returns the global database instance (may be nil until InitDB is called).
func GetDB() *DB {
	dbMu.RLock()
	defer dbMu.RUnlock()
	return globalDB
}

// Close 关闭数据库连接。
// Close closes the database connection.
func (db *DB) Close() error {
	if db == nil || db.sql == nil {
		return nil
	}
	return db.sql.Close()
}

// migrate 创建所有业务表（幂等，IF NOT EXISTS）。
// migrate creates all business tables (idempotent, IF NOT EXISTS).
func (db *DB) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS clients (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			IsConnect INTEGER NOT NULL DEFAULT 0,
			VerifyKey TEXT,
			Tp TEXT,
			Addr TEXT,
			Remark TEXT,
			Status INTEGER NOT NULL DEFAULT 1,
			LocalIP TEXT,
			UserName TEXT,
			HostName TEXT,
			Location TEXT,
			OsName TEXT,
			ProcessName TEXT,
			PingCheckTime INTEGER,
			RateLimit INTEGER,
			InletFlow INTEGER,
			ExportFlow INTEGER,
			FlowLimit INTEGER,
			NoStore INTEGER NOT NULL DEFAULT 0,
			NoDisplay INTEGER NOT NULL DEFAULT 0,
			MaxConn INTEGER,
			NowConn INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS listeners (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			Status INTEGER NOT NULL DEFAULT 0,
			ListenAddr TEXT,
			ConnectAddr TEXT,
			Remark TEXT,
			Mode TEXT,
			Vkey TEXT,
			EncryptSalt TEXT,
			DisconnectTimeout INTEGER,
			PingInterval INTEGER,
			DNSDomain TEXT,
			PublicDNS TEXT,
			MaxDNSsize INTEGER,
			OssUrl TEXT,
			NoStore INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS commands (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			client_id INTEGER NOT NULL,
			command TEXT NOT NULL,
			result TEXT,
			status TEXT NOT NULL,
			sent_at TEXT,
			done_at TEXT,
			timeout INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS agent_sessions (
			id TEXT PRIMARY KEY,
			client_id INTEGER NOT NULL,
			listener_id INTEGER,
			type TEXT,
			status TEXT,
			remote_addr TEXT,
			created_at TEXT,
			last_seen TEXT,
			command_id INTEGER,
			description TEXT
		)`,
	}
	for _, stmt := range stmts {
		if _, err := db.sql.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// CreateClient 插入一条客户端记录并回填自增 ID。
// CreateClient inserts a client record and backfills the auto-increment ID.
func (db *DB) CreateClient(client *Client) (int64, error) {
	if client == nil {
		return 0, fmt.Errorf("client is nil")
	}
	now := time.Now()
	if client.CreatedAt.IsZero() {
		client.CreatedAt = now
	}
	if client.LastSeen.IsZero() {
		client.LastSeen = now
	}
	res, err := db.sql.Exec(`INSERT INTO clients (
		IsConnect, VerifyKey, Tp, Addr, Remark, Status, LocalIP, UserName, HostName,
		Location, OsName, ProcessName, PingCheckTime, RateLimit, InletFlow, ExportFlow,
		FlowLimit, NoStore, NoDisplay, MaxConn, NowConn
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		boolInt(client.IsConnect), client.VerifyKey, client.Type, client.Addr, client.Remark, boolInt(client.Status),
		client.LocalIP, client.UserName, client.HostName, client.Location, client.OsName, client.ProcessName,
		client.PingCheckTime, client.RateLimit, client.InletFlow, client.ExportFlow, client.FlowLimit,
		boolInt(client.NoStore), boolInt(client.NoDisplay), client.MaxConn, client.NowConn)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err == nil {
		client.ID = id
	}
	return id, err
}

// ListClients 按 ID 升序返回全部客户端。
// ListClients returns all clients ordered by ID ascending.
func (db *DB) ListClients() ([]*Client, error) {
	rows, err := db.sql.Query(`SELECT id, IsConnect, VerifyKey, Tp, Addr, Remark, Status, LocalIP, UserName, HostName,
		Location, OsName, ProcessName, PingCheckTime, RateLimit, InletFlow, ExportFlow, FlowLimit,
		NoStore, NoDisplay, MaxConn, NowConn FROM clients ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var clients []*Client
	for rows.Next() {
		client := &Client{}
		var isConnect, Status, noStore, noDisplay int
		var createdAt, lastSeen string
		if err := rows.Scan(&client.ID, &isConnect, &client.VerifyKey, &client.Type, &client.Addr, &client.Remark, &Status,
			&client.LocalIP, &client.UserName, &client.HostName, &client.Location, &client.OsName, &client.ProcessName,
			&client.PingCheckTime, &client.RateLimit, &client.InletFlow, &client.ExportFlow, &client.FlowLimit,
			&noStore, &noDisplay, &client.MaxConn, &client.NowConn); err != nil {
			return nil, err
		}
		client.IsConnect = isConnect != 0
		client.Status = Status != 0
		client.NoStore = noStore != 0
		client.NoDisplay = noDisplay != 0
		client.CreatedAt = parseDBTime(createdAt)
		client.LastSeen = parseDBTime(lastSeen)
		clients = append(clients, client)
	}
	return clients, rows.Err()
}

// DeleteClient 按 ID 删除客户端记录。
// DeleteClient removes a client record by ID.
func (db *DB) DeleteClient(id int64) error {
	_, err := db.sql.Exec(`DELETE FROM clients WHERE id = ?`, id)
	return err
}

// BlockClient 将客户端标记为禁用（Status=0），用于拉黑。
// BlockClient marks a client as disabled (Status=0), used to block it.
func (db *DB) BlockClient(id int64) error {
	_, err := db.sql.Exec(`UPDATE clients SET Status = 0 WHERE id = ?`, id)
	return err
}

// UnblockClient 恢复客户端为启用状态（Status=1）。
// UnblockClient restores a client to enabled status (Status=1).
func (db *DB) UnblockClient(id int64) error {
	_, err := db.sql.Exec(`UPDATE clients SET Status = 1 WHERE id = ?`, id)
	return err
}

// GetBlockedClientIDs 返回所有被拉黑的客户端 ID 列表。
// GetBlockedClientIDs returns the IDs of all blocked clients.
func (db *DB) GetBlockedClientIDs() ([]int64, error) {
	rows, err := db.sql.Query(`SELECT id FROM clients WHERE Status = 0 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// UpdateClientRemark 更新客户端的备注信息。
// UpdateClientRemark updates a client's remark/note.
func (db *DB) UpdateClientRemark(id int64, Remark string) error {
	_, err := db.sql.Exec(`UPDATE clients SET Remark = ? WHERE id = ?`, Remark, id)
	return err
}

// GetClientCount 返回客户端总数。
// GetClientCount returns the total number of clients.
func (db *DB) GetClientCount() (int, error) {
	return db.count(`SELECT COUNT(*) FROM clients`)
}

// CreateListener 插入一条监听器配置并回填自增 ID。
// CreateListener inserts a listener configuration and backfills its ID.
func (db *DB) CreateListener(listener *Listener) (int64, error) {
	if listener == nil {
		return 0, fmt.Errorf("listener is nil")
	}
	if listener.CreatedAt.IsZero() {
		listener.CreatedAt = time.Now()
	}
	res, err := db.sql.Exec(`INSERT INTO listeners (
		Status, ListenAddr, ConnectAddr, Remark, Mode, Vkey, EncryptSalt, DisconnectTimeout,
		PingInterval, DNSDomain, PublicDNS, MaxDNSsize, OssUrl, NoStore
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		boolInt(listener.Status), listener.ListenAddr, listener.ConnectAddr, listener.Remark, listener.Mode,
		listener.VerifyKey, listener.EncryptSalt, listener.DisconnectTimeout, listener.PingInterval,
		listener.DNSDomain, listener.PublicDNS, listener.MaxDNSsize, listener.OssUrl, boolInt(listener.NoStore),
		formatTime(listener.CreatedAt))
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err == nil {
		listener.ID = id
	}
	return id, err
}

// GetListener 按 ID 查询监听器。
// GetListener fetches a listener by ID.
func (db *DB) GetListener(id int64) (*Listener, error) {
	row := db.sql.QueryRow(`SELECT id, Status, ListenAddr, ConnectAddr, Remark, Mode, Vkey, EncryptSalt,
		DisconnectTimeout, PingInterval, DNSDomain, PublicDNS, MaxDNSsize, OssUrl, NoStore
		FROM listeners WHERE id = ?`, id)
	return scanListener(row)
}

// ListListeners 按 ID 升序返回全部监听器。
// ListListeners returns all listeners ordered by ID ascending.
func (db *DB) ListListeners() ([]*Listener, error) {
	rows, err := db.sql.Query(`SELECT id, Status, ListenAddr, ConnectAddr, Remark, Mode, Vkey, EncryptSalt,
		DisconnectTimeout, PingInterval, DNSDomain, PublicDNS, MaxDNSsize, OssUrl, NoStore
		FROM listeners ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var listeners []*Listener
	for rows.Next() {
		listener, err := scanListener(rows)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, listener)
	}
	return listeners, rows.Err()
}

// UpdateListener 持久化监听器的全部可编辑字段。
// UpdateListener persists all editable fields of a listener.
func (db *DB) UpdateListener(listener *Listener) error {
	if listener == nil {
		return fmt.Errorf("listener is nil")
	}
	_, err := db.sql.Exec(`UPDATE listeners SET Status=?, ListenAddr=?, ConnectAddr=?, Remark=?, Mode=?, Vkey=?,
		EncryptSalt=?, DisconnectTimeout=?, PingInterval=?, DNSDomain=?, PublicDNS=?, MaxDNSsize=?, OssUrl=?, NoStore=?
		WHERE id=?`,
		boolInt(listener.Status), listener.ListenAddr, listener.ConnectAddr, listener.Remark, listener.Mode,
		listener.VerifyKey, listener.EncryptSalt, listener.DisconnectTimeout, listener.PingInterval,
		listener.DNSDomain, listener.PublicDNS, listener.MaxDNSsize, listener.OssUrl, boolInt(listener.NoStore), listener.ID)
	return err
}

// DeleteListener 按 ID 删除监听器。
// DeleteListener removes a listener by ID.
func (db *DB) DeleteListener(id int64) error {
	_, err := db.sql.Exec(`DELETE FROM listeners WHERE id = ?`, id)
	return err
}

// GetListenerCount 返回监听器总数。
// GetListenerCount returns the total number of listeners.
func (db *DB) GetListenerCount() (int, error) {
	return db.count(`SELECT COUNT(*) FROM listeners`)
}

// CreateCommand 创建一条待下发（pending）的命令任务。
// CreateCommand creates a pending command task for a client.
func (db *DB) CreateCommand(clientID int64, Command string, Timeout int) (int64, error) {
	res, err := db.sql.Exec(`INSERT INTO commands (client_id, command, result, status, sent_at, timeout) VALUES (?, ?, '', 'pending', ?, ?)`,
		clientID, Command, formatTime(time.Now()), Timeout)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetPendingCommands 返回指定客户端所有 pending 状态的命令。
// GetPendingCommands returns all pending commands for a client.
func (db *DB) GetPendingCommands(clientID int64) ([]*Command, error) {
	return db.listCommands(`SELECT id, client_id, command, result, status, sent_at, done_at, timeout FROM commands WHERE client_id=? AND status='pending' ORDER BY id`, clientID)
}

// MarkCommandDispatched 将命令标记为已派发（dispatched）。
// MarkCommandDispatched marks a command as dispatched.
func (db *DB) MarkCommandDispatched(id int64) error {
	_, err := db.sql.Exec(`UPDATE commands SET status='dispatched' WHERE id=?`, id)
	return err
}

// CompleteCommand 写入命令结果并标记完成/失败等终态。
// CompleteCommand writes the result and marks a terminal status (completed/failed, etc.).
func (db *DB) CompleteCommand(id int64, Result, Status string) error {
	if Status == "" {
		Status = "completed"
	}
	_, err := db.sql.Exec(`UPDATE commands SET result=?, status=?, done_at=? WHERE id=?`, Result, Status, formatTime(time.Now()), id)
	return err
}

// GetCommand 按 ID 查询单条命令，不存在时返回 sql.ErrNoRows。
// GetCommand fetches one command by ID, returning sql.ErrNoRows when absent.
func (db *DB) GetCommand(id int64) (*Command, error) {
	cmds, err := db.listCommands(`SELECT id, client_id, command, result, status, sent_at, done_at, timeout FROM commands WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	if len(cmds) == 0 {
		return nil, sql.ErrNoRows
	}
	return cmds[0], nil
}

// ListCommands 列出命令；clientID<=0 时返回全部，按 ID 倒序。
// ListCommands lists commands; clientID<=0 returns all, ordered by ID descending.
func (db *DB) ListCommands(clientID int64) ([]*Command, error) {
	if clientID > 0 {
		return db.listCommands(`SELECT id, client_id, command, result, status, sent_at, done_at, timeout FROM commands WHERE client_id=? ORDER BY id DESC`, clientID)
	}
	return db.listCommands(`SELECT id, client_id, command, result, status, sent_at, done_at, timeout FROM commands ORDER BY id DESC`)
}

// UpsertAgentSession 插入或更新一条交互式 Agent 会话（按 ID 冲突覆盖）。
// UpsertAgentSession inserts or updates an interactive agent session (upsert by ID).
func (db *DB) UpsertAgentSession(session *AgentSession) error {
	if session == nil {
		return fmt.Errorf("agent session is nil")
	}
	if session.CreatedAt.IsZero() {
		session.CreatedAt = time.Now()
	}
	if session.LastSeen.IsZero() {
		session.LastSeen = session.CreatedAt
	}
	_, err := db.sql.Exec(`INSERT INTO agent_sessions (
		id, client_id, listener_id, type, status, remote_addr, created_at, last_seen, command_id, description
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		client_id=excluded.client_id,
		listener_id=excluded.listener_id,
		type=excluded.type,
		status=excluded.status,
		remote_addr=excluded.remote_addr,
		created_at=excluded.created_at,
		last_seen=excluded.last_seen,
		command_id=excluded.command_id,
		description=excluded.description`,
		session.ID, session.ClientID, session.ListenerID, session.Type, session.Status, session.RemoteAddr,
		formatTime(session.CreatedAt), formatTime(session.LastSeen), session.CommandID, session.Description)
	return err
}

// UpdateAgentSessionStatus 更新会话状态与最后心跳时间。
// UpdateAgentSessionStatus updates a session's status and last-seen timestamp.
func (db *DB) UpdateAgentSessionStatus(id, Status string, lastSeen time.Time) error {
	if lastSeen.IsZero() {
		lastSeen = time.Now()
	}
	_, err := db.sql.Exec(`UPDATE agent_sessions SET status=?, last_seen=? WHERE id=?`, Status, formatTime(lastSeen), id)
	return err
}

// DeleteAgentSession 按 ID 删除会话。
// DeleteAgentSession deletes a session by ID.
func (db *DB) DeleteAgentSession(id string) error {
	_, err := db.sql.Exec(`DELETE FROM agent_sessions WHERE id=?`, id)
	return err
}

// ListAgentSessions 列出会话；clientID>0 时仅返回该客户端的会话。
// ListAgentSessions lists sessions; clientID>0 filters to that client only.
func (db *DB) ListAgentSessions(clientID int64) ([]*AgentSession, error) {
	query := `SELECT id, client_id, listener_id, type, status, remote_addr, created_at, last_seen, command_id, description FROM agent_sessions`
	args := []interface{}{}
	if clientID > 0 {
		query += ` WHERE client_id=?`
		args = append(args, clientID)
	}
	query += ` ORDER BY created_at DESC, id`

	rows, err := db.sql.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []*AgentSession
	for rows.Next() {
		session := &AgentSession{}
		var createdAt, lastSeen string
		if err := rows.Scan(&session.ID, &session.ClientID, &session.ListenerID, &session.Type, &session.Status,
			&session.RemoteAddr, &createdAt, &lastSeen, &session.CommandID, &session.Description); err != nil {
			return nil, err
		}
		session.CreatedAt = parseDBTime(createdAt)
		session.LastSeen = parseDBTime(lastSeen)
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

// count 执行 COUNT 查询并返回数值。
// count runs a COUNT query and returns the numeric result.
func (db *DB) count(query string) (int, error) {
	var n int
	err := db.sql.QueryRow(query).Scan(&n)
	return n, err
}

// scanner 抽象 sql.Row / sql.Rows，便于复用扫描逻辑。
// scanner abstracts sql.Row / sql.Rows so scan logic can be shared.
type scanner interface {
	Scan(dest ...interface{}) error
}

// scanListener 将一行查询结果映射为 Listener。
// scanListener maps a single query row into a Listener.
func scanListener(s scanner) (*Listener, error) {
	listener := &Listener{}
	var Status, noStore int
	if err := s.Scan(&listener.ID, &Status, &listener.ListenAddr, &listener.ConnectAddr, &listener.Remark,
		&listener.Mode, &listener.VerifyKey, &listener.EncryptSalt, &listener.DisconnectTimeout,
		&listener.PingInterval, &listener.DNSDomain, &listener.PublicDNS, &listener.MaxDNSsize,
		&listener.OssUrl, &noStore); err != nil {
		return nil, err
	}
	listener.Status = Status != 0
	listener.NoStore = noStore != 0
	return listener, nil
}

// listCommands 执行命令查询并把结果行映射为 []*Command。
// listCommands runs a command query and maps the rows into []*Command.
func (db *DB) listCommands(query string, args ...interface{}) ([]*Command, error) {
	rows, err := db.sql.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cmds []*Command
	for rows.Next() {
		cmd := &Command{}
		var sentAt, doneAt sql.NullString
		if err := rows.Scan(&cmd.ID, &cmd.ClientID, &cmd.Command, &cmd.Result, &cmd.Status, &sentAt, &doneAt, &cmd.Timeout); err != nil {
			return nil, err
		}
		if sentAt.Valid {
			cmd.SentAt = parseDBTime(sentAt.String)
		}
		if doneAt.Valid && doneAt.String != "" {
			t := parseDBTime(doneAt.String)
			cmd.DoneAt = &t
		}
		cmds = append(cmds, cmd)
	}
	return cmds, rows.Err()
}

// boolInt 将 bool 转为 SQLite 的 0/1。
// boolInt converts a bool into SQLite 0/1.
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// formatTime 将时间格式化为 UTC RFC3339Nano 字符串（零值返回空串）。
// formatTime formats a time as UTC RFC3339Nano (empty string for zero time).
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// parseDBTime 解析数据库中的时间字符串，失败时返回零值。
// parseDBTime parses a DB time string, returning the zero time on failure.
func parseDBTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}
