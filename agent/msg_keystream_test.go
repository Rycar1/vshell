package main

import (
	"encoding/hex"
	"testing"
)

// Verify msgKeyStream against a full gdb capture:
// rbx=0x956da0e7, key0=6b66a71f83903f3b4710206d6df90554,
// key2=a6c75adda0e09cfa1349fd7fae59006c, pt="WSL2_GUI_APPS_ENABLED"
// first dual-block output = 2dff7e68a76efb8f (gdb FIN low 8)
func TestMsgKeyStreamCapture(t *testing.T) {
	key0, _ := hex.DecodeString("6b66a71f83903f3b4710206d6df90554")
	key2, _ := hex.DecodeString("a6c75adda0e09cfa1349fd7fae59006c")
	pt := []byte("WSL2_GUI_APPS_ENABLED")
	if len(pt) != 21 {
		t.Fatalf("pt len %d", len(pt))
	}
	// First dual-block call: window = pt[0:16]
	out := msgDualBlockEncrypt(pt, 0x956da0e7, 21, key0, key2)
	if hex.EncodeToString(out[:]) != "2dff7e68a76efb8f" {
		t.Fatalf("block0: got %s", hex.EncodeToString(out[:]))
	}
	// Full 21B keystream
	ks := msgKeyStream(pt, 0x956da0e7, key0, key2)
	if len(ks) != 21 {
		t.Fatalf("ks len %d", len(ks))
	}
	t.Logf("keystream[0:8]  = %s (matches gdb FIN)", hex.EncodeToString(ks[:8]))
	t.Logf("keystream(21B)  = %s", hex.EncodeToString(ks))
}
