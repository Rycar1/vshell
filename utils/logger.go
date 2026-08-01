// Package utils 提供日志、配置、认证与通知等通用工具。
// Package utils provides common utilities: logging, configuration, auth, and notifications.
package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// 日志级别：遵循 syslog 风格（0 最严重，7 最详细）。
// Log levels: syslog-style scale (0 most severe, 7 most verbose).
const (
	LevelEmergency     = 0 // 紧急 / emergency
	LevelAlert         = 1 // 警报 / alert
	LevelCritical      = 2 // 严重 / critical
	LevelError         = 3 // 错误 / error
	LevelWarning       = 4 // 警告 / warning
	LevelNotice        = 5 // 提示 / notice
	LevelInformational = 6 // 信息 / informational
	LevelDebug         = 7 // 调试 / debug
)

var (
	loggerMu        sync.RWMutex       // 保护日志配置的读写锁 / guards logger configuration
	configuredLevel           = LevelDebug // 当前生效的日志级别 / current effective log level
	configuredOut   io.Writer = os.Stderr // 当前日志输出目标 / current log output target
)

// LoggerCloser 返回给调用方，用于在退出时关闭日志文件。
// LoggerCloser is returned to the caller to close the log file on exit.
type LoggerCloser interface {
	io.Closer
}

// loggerCloser 封装日志文件句柄，实现 LoggerCloser。
// loggerCloser wraps the log file handle, implementing LoggerCloser.
type loggerCloser struct {
	file *os.File
}

// Close 关闭日志文件。
// Close closes the log file.
func (c *loggerCloser) Close() error {
	if c == nil || c.file == nil {
		return nil
	}
	return c.file.Close()
}

// levelWriter 是日志输出适配器，保证读取配置时并发安全。
// levelWriter adapts the log output writer with concurrency-safe config reads.
type levelWriter struct {
	writer io.Writer
}

// Write 将日志字节写入底层输出。
// Write forwards log bytes to the underlying writer.
func (w *levelWriter) Write(p []byte) (int, error) {
	loggerMu.RLock()
	out := w.writer
	loggerMu.RUnlock()
	if out == nil {
		return len(p), nil
	}
	return out.Write(p)
}

// Sync 若底层输出支持则执行同步刷新。
// Sync flushes the underlying writer if it supports it.
func (w *levelWriter) Sync() error {
	loggerMu.RLock()
	out := w.writer
	loggerMu.RUnlock()
	if s, ok := out.(interface{ Sync() error }); ok {
		return s.Sync()
	}
	return nil
}

// ConfigureLogger 依据原版 setting.conf 应用 log_level 与 log_path。
// 日志级别遵循配置文件中的 syslog 风格刻度：0=Emergency ... 7=Debug，level <= 配置级别时输出。
// ConfigureLogger applies log_level and log_path from the original setting.conf.
// log_level follows the syslog-style scale documented in the config file:
// 0=Emergency ... 7=Debug. A message is emitted when level <= configured level.
func ConfigureLogger(cfg *FullSettings) (LoggerCloser, error) {
	if cfg == nil {
		cfg = defaultFullSettings()
	}

	level := cfg.LogLevel
	if level < LevelEmergency {
		level = LevelEmergency
	}
	if level > LevelDebug {
		level = LevelDebug
	}

	var out io.Writer = os.Stderr
	var file *os.File
	if cfg.LogPath != "" {
		if dir := filepath.Dir(cfg.LogPath); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("create log directory: %w", err)
			}
		}
		f, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		file = f
		out = f
	}

	loggerMu.Lock()
	configuredLevel = level
	configuredOut = out
	loggerMu.Unlock()

	log.SetOutput(&levelWriter{writer: out})
	log.SetFlags(log.LstdFlags)

	return &loggerCloser{file: file}, nil
}

// logAt 按级别过滤后输出日志。
// logAt emits a log message after filtering by level.
func logAt(level int, format string, args ...interface{}) {
	loggerMu.RLock()
	allowed := level <= configuredLevel
	loggerMu.RUnlock()
	if !allowed {
		return
	}
	log.Printf(format, args...)
}

// 以下为各级别的便捷输出函数 / Convenience log functions per level.
func LogEmergency(format string, args ...interface{}) { logAt(LevelEmergency, format, args...) }
func LogAlert(format string, args ...interface{})     { logAt(LevelAlert, format, args...) }
func LogCritical(format string, args ...interface{})  { logAt(LevelCritical, format, args...) }
func LogError(format string, args ...interface{})     { logAt(LevelError, format, args...) }
func LogWarning(format string, args ...interface{})   { logAt(LevelWarning, format, args...) }
func LogNotice(format string, args ...interface{})    { logAt(LevelNotice, format, args...) }
func LogInfo(format string, args ...interface{})      { logAt(LevelInformational, format, args...) }
func LogDebug(format string, args ...interface{})     { logAt(LevelDebug, format, args...) }
