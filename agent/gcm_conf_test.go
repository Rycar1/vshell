package main

import (
	"encoding/hex"
	"os"
	"testing"
)

// Verify the 334B conf frame (same-run gdb capture, binary dump ct334.bin)
// decrypts to the conf register JSON with the recovered AES-256-GCM key.
func TestGCMConfFrame334(t *testing.T) {
	ct, err := os.ReadFile("../.re/ct334.bin")
	if err != nil {
		t.Skipf("ct334.bin not present: %v", err)
	}
	if len(ct) != 334 {
		t.Fatalf("ct len %d, want 334", len(ct))
	}
	pt, err := decryptFrame(ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	t.Logf("conf PT: %q", pt[:50])
	if len(pt) != 306 {
		t.Fatalf("PT len %d, want 306", len(pt))
	}
	if string(pt[:5]) != "conf\x2a" {
		t.Fatalf("PT head mismatch: %q", pt[:16])
	}
	// PT must contain the conf JSON fields
	if !containsStr(string(pt), `"Id":0,"IsConnect":false,"VerifyKey":""`) {
		t.Fatalf("conf JSON fields missing: %q", pt[:80])
	}
	t.Logf("hex PT head: %s", hex.EncodeToString(pt[:24]))
}

func containsStr(s, sub string) bool {
	return len(sub) > 0 && (len(s) >= len(sub)) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
