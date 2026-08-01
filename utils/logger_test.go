package utils

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfiguredLoggerFiltersMessagesBelowConfiguredLevel(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "vshell.log")

	closer, err := ConfigureLogger(&FullSettings{LogLevel: LevelWarning, LogPath: logPath})
	if err != nil {
		t.Fatalf("ConfigureLogger: %v", err)
	}
	defer closer.Close()
	defer log.SetOutput(os.Stderr)

	LogNotice("notice should be filtered")
	LogError("error should be written")
	log.Writer().(interface{ Sync() error }).Sync()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	text := string(data)
	if strings.Contains(text, "notice should be filtered") {
		t.Fatalf("notice log was not filtered: %q", text)
	}
	if !strings.Contains(text, "error should be written") {
		t.Fatalf("error log missing: %q", text)
	}
}

func TestConfiguredLoggerCreatesLogPathDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "logs", "server.log")

	closer, err := ConfigureLogger(&FullSettings{LogLevel: LevelDebug, LogPath: logPath})
	if err != nil {
		t.Fatalf("ConfigureLogger: %v", err)
	}
	defer closer.Close()
	defer log.SetOutput(os.Stderr)

	LogDebug("debug file output")
	log.Writer().(interface{ Sync() error }).Sync()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "debug file output") {
		t.Fatalf("debug log missing from file: %q", string(data))
	}
}
