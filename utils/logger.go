package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

const (
	LevelEmergency     = 0
	LevelAlert         = 1
	LevelCritical      = 2
	LevelError         = 3
	LevelWarning       = 4
	LevelNotice        = 5
	LevelInformational = 6
	LevelDebug         = 7
)

var (
	loggerMu        sync.RWMutex
	configuredLevel           = LevelDebug
	configuredOut   io.Writer = os.Stderr
)

type LoggerCloser interface {
	io.Closer
}

type loggerCloser struct {
	file *os.File
}

func (c *loggerCloser) Close() error {
	if c == nil || c.file == nil {
		return nil
	}
	return c.file.Close()
}

type levelWriter struct {
	writer io.Writer
}

func (w *levelWriter) Write(p []byte) (int, error) {
	loggerMu.RLock()
	out := w.writer
	loggerMu.RUnlock()
	if out == nil {
		return len(p), nil
	}
	return out.Write(p)
}

func (w *levelWriter) Sync() error {
	loggerMu.RLock()
	out := w.writer
	loggerMu.RUnlock()
	if s, ok := out.(interface{ Sync() error }); ok {
		return s.Sync()
	}
	return nil
}

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

func logAt(level int, format string, args ...interface{}) {
	loggerMu.RLock()
	allowed := level <= configuredLevel
	loggerMu.RUnlock()
	if !allowed {
		return
	}
	log.Printf(format, args...)
}

func LogEmergency(format string, args ...interface{}) { logAt(LevelEmergency, format, args...) }
func LogAlert(format string, args ...interface{})     { logAt(LevelAlert, format, args...) }
func LogCritical(format string, args ...interface{})  { logAt(LevelCritical, format, args...) }
func LogError(format string, args ...interface{})     { logAt(LevelError, format, args...) }
func LogWarning(format string, args ...interface{})   { logAt(LevelWarning, format, args...) }
func LogNotice(format string, args ...interface{})    { logAt(LevelNotice, format, args...) }
func LogInfo(format string, args ...interface{})      { logAt(LevelInformational, format, args...) }
func LogDebug(format string, args ...interface{})     { logAt(LevelDebug, format, args...) }
