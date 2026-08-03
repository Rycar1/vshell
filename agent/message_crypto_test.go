package main

import (
	"encoding/hex"
	"testing"
)

// Verify Go implementation against C-verified gdb captures.
func TestMsgBlockEncryptQuad(t *testing.T) {
	// QUAD capture: rbx=0x22d6520508b, key=a3df943ae1b74fb371c58cff2c991a1b
	// input = key (first block), expected out = 7f4dee1c2a080eb1 (gdb FIN low 8)
	key, _ := hex.DecodeString("a3df943ae1b74fb371c58cff2c991a1b")
	got := msgBlockEncrypt(key, 0x22d6520508b, key)
	exp := "7f4dee1c2a080eb1"
	if hex.EncodeToString(got[:]) != exp {
		t.Fatalf("quad: got %s want %s", hex.EncodeToString(got[:]), exp)
	}
}

func TestMsgBlockEncryptVar(t *testing.T) {
	// aesenc_var capture: input=e1e857ff05449ee040e15986296cc452
	// state=497fdab3c6669c5d2db6fd3074eaf70c -> FIN=5f5c2b73014e072f27898edeeab14939
	// This tests the 3x self-keyed chain with a known state.
	// Reconstruct: x1 = input XOR state; but msgBlockEncrypt computes its own state.
	// Direct chain test: simulate with state as key (round 1 input = x1).
	input, _ := hex.DecodeString("e1e857ff05449ee040e15986296cc452")
	state, _ := hex.DecodeString("497fdab3c6669c5d2db6fd3074eaf70c")
	var x1 [16]byte
	for i := 0; i < 16; i++ {
		x1[i] = input[i] ^ state[i]
	}
	x1 = aesRound(x1, x1)
	x1 = aesRound(x1, x1)
	x1 = aesRound(x1, x1)
	got := hex.EncodeToString(x1[:])
	want := "5f5c2b73014e072f27898edeeab14939"
	if got != want {
		t.Fatalf("3x chain: got %s want %s", got, want)
	}
}

func TestMsgDualBlockEncrypt(t *testing.T) {
	// Same-run capture: rbx=0x99ef22fc, key0=fbab53e46c9bdfbacf15442e994e8864
	// key2=7005f0daf94c9f93c460659701d884e3, in="Anatolian_Hieroglyphs"
	// FIN low 8 = b1b5a467fd784088 (verified by C AES-NI)
	key0, _ := hex.DecodeString("fbab53e46c9bdfbacf15442e994e8864")
	key2, _ := hex.DecodeString("7005f0daf94c9f93c460659701d884e3")
	input := []byte("Anatolian_Hieroglyphs")
	if len(input) != 21 {
		t.Fatalf("input len %d want 21", len(input))
	}
	got := msgDualBlockEncrypt(input, 0x99ef22fc, 21, key0, key2)
	if hex.EncodeToString(got[:]) != "b1b5a467fd784088" {
		t.Fatalf("dual: got %s", hex.EncodeToString(got[:]))
	}
}
