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

// Settings holds application configuration
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

// GetSettings returns the application settings
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

// GetJWTSecret returns the JWT secret
func GetJWTSecret() string {
	return GetSettings().WebJWTSecret
}

// generateJWTSecret creates a random JWT secret
func generateJWTSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// JWTClaims represents JWT token claims (matching original binary format)
type JWTClaims struct {
	TokenType string `json:"token_type"`
	UserID    string `json:"user_id"`
	RoleID    string `json:"role_id"`
	Username  string `json:"username"`
	Exp       int64  `json:"exp"`
	Iat       int64  `json:"iat"`
}

// Role definitions matching original binary
const (
	RoleSuperAdmin = "super"
	RoleAdmin      = "admin"
	RoleUser       = "user"
)

// Role permissions map defines what each role can access
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

// GetRoleID returns the role ID for a role value
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

// GetRoleName returns the role name for a role ID
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

// HasPermission checks if a role can access a given path
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

// UserInfoResponse matches the original binary's /api/getUserInfo format
type UserInfoResponse struct {
	Code    int      `json:"code"`
	Message string   `json:"message"`
	Type    string   `json:"type"`
	Result  UserInfo `json:"result"`
}

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

type RoleInfoResp struct {
	RoleName string `json:"roleName"`
	Value    string `json:"value"`
}

// GenerateToken creates a new JWT token
func GenerateToken(username string) (string, error) {
	return GenerateTokenWithRoles(username, "1", "1")
}

// GenerateTokenWithRoles creates a JWT token with RBAC claims matching original binary
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

// ValidateToken validates a JWT token and returns the username, role ID, and user ID
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

// ValidateTokenWithRole validates a JWT token and returns claims including role info
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

// CheckPassword verifies a password against the stored hash
// Supports plaintext passwords and bcrypt-like hashes
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

// HashPassword creates a hash of the password
func HashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

// helpers

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

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

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

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
