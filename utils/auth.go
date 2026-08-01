// Package utils/auth 实现 JWT 令牌、RBAC 角色权限与密码哈希等认证逻辑。
// Package utils/auth implements JWT tokens, RBAC role permissions, and password hashing.
package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	settings     *Settings
	settingsOnce sync.Once
	settingsMu   sync.RWMutex
)

// Settings 保存应用运行配置。
// Settings holds application configuration.
type Settings struct {
	License      string
	MasterType   string
	WebTitle     string
	WebPort      int
	WebIP        string
	WebBasicAuth bool
	WebUsername  string
	WebPassword  string
	WebJWTSecret string
}

// GetSettings 返回应用配置（惰性初始化单例）。
// GetSettings returns the application settings (lazily initialized singleton).
func GetSettings() *Settings {
	settingsOnce.Do(func() {
		settings = &Settings{
			MasterType:   "web",
			WebTitle:     "管理平台",
			WebPort:      8082,
			WebIP:        "0.0.0.0",
			WebBasicAuth: true,
			WebUsername:  "admin",
			WebPassword:  "", // no hardcoded default — main.go generates a random one at startup
			WebJWTSecret: generateJWTSecret(), // random per process if not overridden
		}
	})
	settingsMu.RLock()
	defer settingsMu.RUnlock()
	return settings
}

// GetJWTSecret 返回 JWT 签名密钥。
// GetJWTSecret returns the JWT signing secret.
func GetJWTSecret() string {
	return GetSettings().WebJWTSecret
}

// generateJWTSecret 生成随机 JWT 密钥。
// generateJWTSecret generates a random JWT secret.
func generateJWTSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// JWTClaims 表示 JWT 令牌声明（与原版二进制格式一致）。
// JWTClaims represents JWT token claims (matching original binary format).
type JWTClaims struct {
	TokenType string `json:"token_type"`
	UserID    string `json:"user_id"`
	RoleID    string `json:"role_id"`
	Username  string `json:"username"`
	Exp       int64  `json:"exp"`
	Iat       int64  `json:"iat"`
}

// 角色定义：与原版二进制一致 / Role definitions matching original binary
const (
	RoleSuperAdmin = "super"
	RoleAdmin      = "admin"
	RoleUser       = "user"
)

// rolePermissions 定义各角色可访问的 API 路径前缀。
// rolePermissions maps each role to the API path prefixes it may access.
var rolePermissions = map[string][]string{
	RoleSuperAdmin: {"*"},
	RoleAdmin: {
		"/api/listener/", "/api/client/", "/api/dashboard/",
		"/api/file/", "/api/terminal/", "/api/tunnel/",
		"/api/download/", "/api/install/", "/api/screen/",
		"/api/screenshot/", "/api/runner/", "/api/settings/",
	},
	RoleUser: {
		"/api/dashboard/", "/api/client/list", "/api/client/get",
	},
}

// GetRoleID 将角色值转换为角色 ID。
// GetRoleID converts a role value into a role ID.
func GetRoleID(role string) string {
	switch role {
	case RoleSuperAdmin:
		return "1"
	case RoleAdmin:
		return "2"
	case RoleUser:
		return "3"
	default:
		return "0"
	}
}

// GetRoleName 将角色 ID 转换为可读名称。
// GetRoleName converts a role ID into a human-readable name.
func GetRoleName(roleID string) string {
	switch roleID {
	case "1":
		return "Super Admin"
	case "2":
		return "Admin"
	case "3":
		return "User"
	default:
		return "Unknown"
	}
}

// HasPermission 判断某角色是否可访问指定路径（超级管理员永远放行）。
// HasPermission checks whether a role may access a path (super admin always allowed).
func HasPermission(roleValue string, path string) bool {
	if roleValue == RoleSuperAdmin {
		return true
	}
	perms, ok := rolePermissions[roleValue]
	if !ok {
		return false
	}
	for _, prefix := range perms {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// UserInfoResponse 与原版 /api/getUserInfo 返回格式一致。
// UserInfoResponse matches the original binary's /api/getUserInfo format.
type UserInfoResponse struct {
	Code    int      `json:"code"`
	Message string   `json:"message"`
	Type    string   `json:"type"`
	Result  UserInfo `json:"result"`
}

// UserInfo 是用户信息详情。
// UserInfo carries the user profile details.
type UserInfo struct {
	Avatar   string         `json:"avatar"`
	UserID   string         `json:"userId"`
	Username string         `json:"username"`
	RealName string         `json:"realName"`
	Desc     string         `json:"desc"`
	HomePath string         `json:"homePath"`
	Roles    []RoleInfoResp `json:"roles"`
	Token    string         `json:"token"`
}

// RoleInfoResp 是角色信息。
// RoleInfoResp carries role information.
type RoleInfoResp struct {
	RoleName string `json:"roleName"`
	Value    string `json:"value"`
}

// GenerateToken 以默认超级管理员角色创建 JWT 令牌。
// GenerateToken creates a JWT token with the default super-admin role.
func GenerateToken(username string) (string, error) {
	return GenerateTokenWithRoles(username, "1", "1")
}

// GenerateTokenWithRoles 创建带 RBAC 声明的 JWT，格式与原版一致。
// 原始格式：{"token_type":"jwt","user_id":"1","role_id":"1","username":"admin","exp":...,"iat":...}
// GenerateTokenWithRoles creates a JWT token with RBAC claims matching the original binary.
// Original format: {"token_type":"jwt","user_id":"1","role_id":"1","username":"admin","exp":...,"iat":...}
func GenerateTokenWithRoles(username, userID, roleID string) (string, error) {
	secret := GetJWTSecret()
	now := time.Now()

	header := `{"alg":"HS256","typ":"JWT"}`
	claims := fmt.Sprintf(`{"token_type":"jwt","user_id":"%s","role_id":"%s","username":"%s","exp":%d,"iat":%d}`,
		userID, roleID, username, now.Add(24*time.Hour).Unix(), now.Unix())

	headerB64 := base64URLEncode([]byte(header))
	claimsB64 := base64URLEncode([]byte(claims))

	signingInput := headerB64 + "." + claimsB64
	sig := hmacSHA256([]byte(secret), []byte(signingInput))
	sigB64 := base64URLEncode(sig)

	return signingInput + "." + sigB64, nil
}

// ValidateToken 校验 JWT 并返回用户名。
// ValidateToken validates a JWT token and returns the username.
func ValidateToken(tokenString string) (string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid token format")
	}

	// Verify signature
	secret := GetJWTSecret()
	signingInput := parts[0] + "." + parts[1]
	sig := hmacSHA256([]byte(secret), []byte(signingInput))
	expectedSig := base64URLEncode(sig)

	if parts[2] != expectedSig {
		return "", errors.New("invalid token signature")
	}

	// Decode claims
	claimsJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return "", errors.New("invalid token payload")
	}

	claimsStr := string(claimsJSON)

	// Extract username
	username := extractJSONValue(claimsStr, "username")
	if username == "" {
		return "", errors.New("invalid token: missing username")
	}

	// Check expiration
	exp := extractJSONValue(claimsStr, "exp")
	if exp != "" {
		expTime := parseInt64(exp)
		if expTime > 0 && time.Now().Unix() > expTime {
			return "", errors.New("token expired")
		}
	}

	return username, nil
}

// ValidateTokenWithRole 校验 JWT 并返回完整声明（含角色信息）。
// ValidateTokenWithRole validates a JWT token and returns full claims including role info.
func ValidateTokenWithRole(tokenString string) (*JWTClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	secret := GetJWTSecret()
	signingInput := parts[0] + "." + parts[1]
	sig := hmacSHA256([]byte(secret), []byte(signingInput))
	expectedSig := base64URLEncode(sig)

	if parts[2] != expectedSig {
		return nil, errors.New("invalid token signature")
	}

	claimsJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, errors.New("invalid token payload")
	}

	claimsStr := string(claimsJSON)

	claims := &JWTClaims{
		Username:  extractJSONValue(claimsStr, "username"),
		TokenType: extractJSONValue(claimsStr, "token_type"),
		UserID:    extractJSONValue(claimsStr, "user_id"),
		RoleID:    extractJSONValue(claimsStr, "role_id"),
	}

	if claims.Username == "" {
		return nil, errors.New("invalid token: missing username")
	}

	exp := extractJSONValue(claimsStr, "exp")
	if exp != "" {
		claims.Exp = parseInt64(exp)
		if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
			return nil, errors.New("token expired")
		}
	}

	return claims, nil
}

// CheckPassword 校验密码与存储哈希是否匹配（支持明文与 SHA256 哈希）。
// CheckPassword verifies a password against the stored hash (plaintext or SHA256).
func CheckPassword(password, stored string) bool {
	if password == stored {
		return true
	}

	// Check if stored is a SHA256 hash
	if len(stored) == 64 {
		h := sha256.Sum256([]byte(password))
		return hex.EncodeToString(h[:]) == stored
	}

	return false
}

// HashPassword 计算密码的 SHA256 十六进制哈希。
// HashPassword creates a SHA256 hex hash of the password.
func HashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

// 以下为内部辅助函数 / Internal helpers below.

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// base64URLDecode 解码无填充的 URL-safe Base64。
// base64URLDecode decodes unpadded URL-safe Base64.
func base64URLDecode(s string) ([]byte, error) {
	// Add padding
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// hmacSHA256 计算 HMAC-SHA256 签名。
// hmacSHA256 computes an HMAC-SHA256 signature.
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// extractJSONValue 从 JSON 字符串中提取指定键的值（避免引入完整 JSON 解析依赖）。
// extractJSONValue extracts a key's value from a JSON string (avoids a full JSON parser).
func extractJSONValue(json string, key string) string {
	search := `"` + key + `":"`
	idx := strings.Index(json, search)
	if idx < 0 {
		// Try number value
		search = `"` + key + `":`
		idx = strings.Index(json, search)
		if idx < 0 {
			return ""
		}
		idx += len(search)
		end := strings.IndexAny(json[idx:], ",\n\r }")
		if end < 0 {
			return json[idx:]
		}
		val := strings.TrimSpace(json[idx : idx+end])
		return val
	}
	idx += len(search)
	end := strings.IndexByte(json[idx:], '"')
	if end < 0 {
		return ""
	}
	return json[idx : idx+end]
}

// parseInt64 解析字符串开头的十进制整数。
// parseInt64 parses a leading decimal integer from a string.
func parseInt64(s string) int64 {
	var n int64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int64(c-'0')
		} else {
			break
		}
	}
	return n
}
