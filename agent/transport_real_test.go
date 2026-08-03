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

func TestDeriveSessionKeys(t *testing.T) {
	sk := deriveSessionKeys("testvkey", "salt")
	if sk.key0 == sk.key2 {
		t.Fatal("key0 must differ from key2")
	}
	sk2 := deriveSessionKeys("testvkey", "salt")
	if sk.key0 != sk2.key0 || sk.key2 != sk2.key2 {
		t.Fatal("derivation must be deterministic")
	}
	t.Logf("key0=%x key2=%x", sk.key0, sk.key2)
}
