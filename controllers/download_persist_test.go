package controllers

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPersistDownloadToServer verifies a completed "download" task's base64
// result is decoded and written to the server's local path (the
// DownloadToServer contract that previously never persisted anything).
func TestPersistDownloadToServer(t *testing.T) {
	dir := t.TempDir()
	localPath := filepath.Join(dir, "sub", "pulled.bin")
	payload := []byte("hello from agent")

	registerDownload(999, &downloadTarget{kind: "server", path: localPath, createdAt: time.Now()})
	persistDownloadResult(999, base64.StdEncoding.EncodeToString(payload), "completed")

	data, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatalf("file not written: %v", err)
	}
	if string(data) != string(payload) {
		t.Fatalf("content = %q, want %q", data, payload)
	}

	// A non-completed status must not write anything.
	noWrite := filepath.Join(dir, "nope.bin")
	registerDownload(998, &downloadTarget{kind: "server", path: noWrite, createdAt: time.Now()})
	persistDownloadResult(998, base64.StdEncoding.EncodeToString(payload), "failed")
	if _, err := os.Stat(noWrite); !os.IsNotExist(err) {
		t.Fatal("failed task must not persist a file")
	}

	// Unknown command IDs are ignored.
	persistDownloadResult(997, base64.StdEncoding.EncodeToString(payload), "completed")
}
