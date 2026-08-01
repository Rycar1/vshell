// Package models 定义 Web 管理面板的数据模型（客户端、监听器、隧道、命令、会话等）。
// Package models defines the data models for the web management panel
// (clients, listeners, tunnels, commands, sessions, etc.).
package models

import (
	"time"
)

// Client 表示一个已连接的 Agent / 客户端。
// Client represents a connected agent/client.
type Client struct {
	ID            int64     `json:"Id"`
	IsConnect     bool      `json:"IsConnect"`
	VerifyKey     string    `json:"VerifyKey"`
	Type          string    `json:"Tp"` // Tp
	Addr          string    `json:"Addr"`
	Remark        string    `json:"Remark"`
	Status        bool      `json:"Status"`
	LocalIP       string    `json:"LocalIP"`
	UserName      string    `json:"UserName"`
	HostName      string    `json:"HostName"`
	Location      string    `json:"Location"`
	OsName        string    `json:"OsName"`
	ProcessName   string    `json:"ProcessName"`
	PingCheckTime int64     `json:"PingCheckTime"`
	RateLimit     int64     `json:"RateLimit"`
	InletFlow     int64     `json:"InletFlow"`
	ExportFlow    int64     `json:"ExportFlow"`
	FlowLimit     int64     `json:"FlowLimit"`
	NoStore       bool      `json:"NoStore"`
	NoDisplay     bool      `json:"NoDisplay"`
	MaxConn       int       `json:"MaxConn"`
	NowConn       int       `json:"NowConn"`
	CreatedAt     time.Time `json:"-"`
	LastSeen      time.Time `json:"-"`
}

// Listener 表示一条 C2 监听器配置。
// Listener represents a C2 listener configuration.
type Listener struct {
	ID                int64     `json:"Id"`
	Status            bool      `json:"Status"`
	ListenAddr        string    `json:"ListenAddr"`  // Local bind Address
	ConnectAddr       string    `json:"ConnectAddr"` // External connect Address
	Remark            string    `json:"Remark"`
	Mode              string    `json:"Mode"` // http/dns/reverse
	VerifyKey         string    `json:"Vkey"`
	EncryptSalt       string    `json:"EncryptSalt"`
	DisconnectTimeout int       `json:"DisconnectTimeout"`
	PingInterval      int       `json:"PingInterval"`
	DNSDomain         string    `json:"DNSDomain"`
	PublicDNS         string    `json:"PublicDNS"`
	MaxDNSsize        int       `json:"MaxDNSsize"`
	OssUrl            string    `json:"OssUrl"`
	NoStore           bool      `json:"NoStore"`
	CreatedAt         time.Time `json:"-"`
}

// Tunnel 表示服务端与 Agent 之间的隧道/代理配置。
// Tunnel represents a tunnel/proxy configuration between server and agent.
type Tunnel struct {
	ID                  int64     `json:"Id"`
	Port                int       `json:"Port"`
	ServerIP            string    `json:"ServerIp"`
	Mode                string    `json:"Mode"`
	Status              bool      `json:"Status"`
	RunStatus           bool      `json:"RunStatus"`
	ClientID            int64     `json:"ClientId"`
	Ports               string    `json:"Ports"`
	InletFlow           int64     `json:"InletFlow"`
	ExportFlow          int64     `json:"ExportFlow"`
	FlowLimit           int64     `json:"FlowLimit"`
	Username            string    `json:"Username"`
	Password            string    `json:"Password"`
	Remark              string    `json:"Remark"`
	TargetAddr          string    `json:"Target"`
	NoStore             bool      `json:"NoStore"`
	LocalPath           string    `json:"LocalPath"`
	StripPre            string    `json:"StripPre"`
	HealthCheckTimeout  int       `json:"HealthCheckTimeout"`
	HealthMaxFail       int       `json:"HealthMaxFail"`
	HealthCheckInterval int       `json:"HealthCheckInterval"`
	HealthNextTime      time.Time `json:"HealthNextTime"`
	HttpHealthUrl       string    `json:"HttpHealthUrl"`
	HealthCheckType     string    `json:"HealthCheckType"`
	HealthCheckTarget   string    `json:"HealthCheckTarget"`
}

// Host 表示一条反代 Host 配置。
// Host represents a reverse proxy Host configuration.
type Host struct {
	ID                  int64     `json:"Id"`
	Host                string    `json:"Host"`
	HeaderChange        string    `json:"HeaderChange"`
	HostChange          string    `json:"HostChange"`
	Location            string    `json:"Location"`
	Remark              string    `json:"Remark"`
	Scheme              string    `json:"Scheme"`
	CertFilePath        string    `json:"CertFilePath"`
	KeyFilePath         string    `json:"KeyFilePath"`
	NoStore             bool      `json:"NoStore"`
	IsClose             bool      `json:"IsClose"`
	InletFlow           int64     `json:"InletFlow"`
	ExportFlow          int64     `json:"ExportFlow"`
	FlowLimit           int64     `json:"FlowLimit"`
	ClientID            int64     `json:"ClientId"`
	TargetStr           string    `json:"TargetStr"`
	HealthCheckTimeout  int       `json:"HealthCheckTimeout"`
	HealthMaxFail       int       `json:"HealthMaxFail"`
	HealthCheckInterval int       `json:"HealthCheckInterval"`
	HealthNextTime      time.Time `json:"HealthNextTime"`
	HttpHealthUrl       string    `json:"HttpHealthUrl"`
	HealthCheckType     string    `json:"HealthCheckType"`
	HealthCheckTarget   string    `json:"HealthCheckTarget"`
}

// User 表示 Web 管理员用户。
// User represents the web admin user.
type User struct {
	ID       int64  `json:"Id"`
	Username string `json:"username"`
	Password string `json:"-"` // hashed
	Role     string `json:"role"`
}

// Session 表示用户 Web 登录会话。
// Session represents a user web login session.
type Session struct {
	SessionID string    `json:"session_Id"`
	UserID    int64     `json:"user_Id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip"`
}

// AgentSession 表示一条持久的交互式 Agent 会话（如终端、屏幕流）。
// AgentSession represents a persistent interactive agent session (terminal, screen stream).
type AgentSession struct {
	ID          string    `json:"Id"`
	ClientID    int64     `json:"ClientId"`
	ListenerID  int64     `json:"listener_Id"`
	Type        string    `json:"type"`
	Status      string    `json:"Status"`
	RemoteAddr  string    `json:"remote_Addr"`
	CreatedAt   time.Time `json:"created_at"`
	LastSeen    time.Time `json:"last_seen"`
	CommandID   int64     `json:"command_Id"`
	Description string    `json:"description"`
}

// Command 表示下发到客户端的一条命令任务。
// Command represents a command task sent to a client.
type Command struct {
	ID       int64      `json:"Id"`
	ClientID int64      `json:"ClientId"`
	Command  string     `json:"command"`
	Result   string     `json:"result"`
	Status   string     `json:"Status"` // pending/dispatched/running/completed/failed/timeout
	SentAt   time.Time  `json:"sent_at"`
	DoneAt   *time.Time `json:"done_at,omitempty"`
	Timeout  int        `json:"timeout"`
}

// API Response types — API 响应类型定义
type (
	LoginRequest struct {
		Username string `json:"username" form:"username"`
		Password string `json:"Password" form:"password"`
	}

	LoginResponse struct {
		Code    int          `json:"code"`
		Message string       `json:"message"`
		Type    string       `json:"type,omitempty"`
		Result  *LoginResult `json:"result,omitempty"`
	}

	LoginResult struct {
		Token    string     `json:"token"`
		UserID   string     `json:"userId"`
		Username string     `json:"username"`
		Desc     string     `json:"desc"`
		RealName string     `json:"realName"`
		Roles    []RoleInfo `json:"roles"`
	}

	RoleInfo struct {
		RoleName string `json:"roleName"`
		Value    string `json:"value"`
	}

	APIResponse struct {
		Code    int         `json:"code"`
		Message string      `json:"message"`
		Type    string      `json:"type"`
		Result  interface{} `json:"result,omitempty"`
	}

	ListResponse struct {
		Code    int         `json:"code"`
		Message string      `json:"message"`
		Type    string      `json:"type"`
		Result  interface{} `json:"result"`
	}

	ListResult struct {
		Items interface{} `json:"items"`
		Total int         `json:"total"`
	}

	FileUploadResponse struct {
		Code    int         `json:"code"`
		Message string      `json:"message"`
		Type    string      `json:"type"`
		Result  interface{} `json:"result,omitempty"`
	}
)

// Plugin 表示已加载的插件（exe/dll/elf/so）。
// Plugin represents a loaded plugin (exe/dll/elf/so).
type Plugin struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Type        string `json:"type"` // exe/dll/elf/so
	Size        int64  `json:"size"`
	Description string `json:"description"`
}
