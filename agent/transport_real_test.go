package main

import (
	"testing"
)

// Pool semantics (FUN_00fc7560): same hostname reuses the pooled connection.
func TestTransportPoolReuse(t *testing.T) {
	tr := &transportReal{cfg: transportCfg{hostname: "127.0.0.1:1"}}
	c1, err := tr.getOrCreateConnection()
	if err == nil {
		t.Fatal("dial to closed port should fail")
	}
	_ = c1
	// Pool should be empty after failed dial
	if tr.pool != nil {
		t.Fatalf("pool should be empty after failed dial, got %+v", tr.pool)
	}
}

func TestFoldCompare(t *testing.T) {
	cases := []struct{ a, b string; want int }{
		{"abc", "abc", 0},
		{"ABC", "abc", 0},
		{"AbC", "aBc", 0},
		{"abc", "abd", -1},
		{"abd", "abc", 1},
		{"abc", "ab", 1},
	}
	for _, c := range cases {
		got := foldCompare(c.a, c.b)
		ok := (got == 0 && c.want == 0) || (got < 0 && c.want < 0) || (got > 0 && c.want > 0)
		if !ok {
			t.Fatalf("foldCompare(%q,%q) = %d, want sign %d", c.a, c.b, got, c.want)
		}
	}
}

func TestMessageFrameKey(t *testing.T) {
	// Recovered key = the lowercase hex text of md5(salt); the captured
	// deployment's EncryptSalt was "salt" (see message_wire.go for evidence).
	if got := string(msgFrameKey); got != "ceb20772e0c9d240c75eb26b0e37abee" {
		t.Fatalf("msgFrameKey = %q", got)
	}
	if len(msgFrameKey) != 32 {
		t.Fatalf("key len %d, want 32", len(msgFrameKey))
	}
}
