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

type DB struct {
	sql *sql.DB
	mu  sync.Mutex
}

var (
	globalDB *DB
	dbMu     sync.RWMutex
)

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

func GetDB() *DB {
	dbMu.RLock()
	defer dbMu.RUnlock()
	return globalDB
}

func (db *DB) Close() error {
	if db == nil || db.sql == nil {
		return nil
	}
	return db.sql.Close()
}

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

func (db *DB) DeleteClient(id int64) error {
	_, err := db.sql.Exec(`DELETE FROM clients WHERE id = ?`, id)
	return err
}

func (db *DB) BlockClient(id int64) error {
	_, err := db.sql.Exec(`UPDATE clients SET Status = 0 WHERE id = ?`, id)
	return err
}

func (db *DB) UnblockClient(id int64) error {
	_, err := db.sql.Exec(`UPDATE clients SET Status = 1 WHERE id = ?`, id)
	return err
}

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

func (db *DB) UpdateClientRemark(id int64, Remark string) error {
	_, err := db.sql.Exec(`UPDATE clients SET Remark = ? WHERE id = ?`, Remark, id)
	return err
}

func (db *DB) GetClientCount() (int, error) {
	return db.count(`SELECT COUNT(*) FROM clients`)
}

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

func (db *DB) GetListener(id int64) (*Listener, error) {
	row := db.sql.QueryRow(`SELECT id, Status, ListenAddr, ConnectAddr, Remark, Mode, Vkey, EncryptSalt,
		DisconnectTimeout, PingInterval, DNSDomain, PublicDNS, MaxDNSsize, OssUrl, NoStore
		FROM listeners WHERE id = ?`, id)
	return scanListener(row)
}

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

func (db *DB) DeleteListener(id int64) error {
	_, err := db.sql.Exec(`DELETE FROM listeners WHERE id = ?`, id)
	return err
}

func (db *DB) GetListenerCount() (int, error) {
	return db.count(`SELECT COUNT(*) FROM listeners`)
}

func (db *DB) CreateCommand(clientID int64, Command string, Timeout int) (int64, error) {
	res, err := db.sql.Exec(`INSERT INTO commands (client_id, command, result, status, sent_at, timeout) VALUES (?, ?, '', 'pending', ?, ?)`,
		clientID, Command, formatTime(time.Now()), Timeout)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) GetPendingCommands(clientID int64) ([]*Command, error) {
	return db.listCommands(`SELECT id, client_id, command, result, status, sent_at, done_at, timeout FROM commands WHERE client_id=? AND status='pending' ORDER BY id`, clientID)
}

func (db *DB) MarkCommandDispatched(id int64) error {
	_, err := db.sql.Exec(`UPDATE commands SET status='dispatched' WHERE id=?`, id)
	return err
}

func (db *DB) CompleteCommand(id int64, Result, Status string) error {
	if Status == "" {
		Status = "completed"
	}
	_, err := db.sql.Exec(`UPDATE commands SET result=?, status=?, done_at=? WHERE id=?`, Result, Status, formatTime(time.Now()), id)
	return err
}

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

func (db *DB) ListCommands(clientID int64) ([]*Command, error) {
	if clientID > 0 {
		return db.listCommands(`SELECT id, client_id, command, result, status, sent_at, done_at, timeout FROM commands WHERE client_id=? ORDER BY id DESC`, clientID)
	}
	return db.listCommands(`SELECT id, client_id, command, result, status, sent_at, done_at, timeout FROM commands ORDER BY id DESC`)
}

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

func (db *DB) UpdateAgentSessionStatus(id, Status string, lastSeen time.Time) error {
	if lastSeen.IsZero() {
		lastSeen = time.Now()
	}
	_, err := db.sql.Exec(`UPDATE agent_sessions SET status=?, last_seen=? WHERE id=?`, Status, formatTime(lastSeen), id)
	return err
}

func (db *DB) DeleteAgentSession(id string) error {
	_, err := db.sql.Exec(`DELETE FROM agent_sessions WHERE id=?`, id)
	return err
}

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

func (db *DB) count(query string) (int, error) {
	var n int
	err := db.sql.QueryRow(query).Scan(&n)
	return n, err
}

type scanner interface {
	Scan(dest ...interface{}) error
}

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

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseDBTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}
