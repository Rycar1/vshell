package main

import (
	"encoding/hex"
	"testing"
)

// Full message decryption: message = [16B IV][21B ct].
// Keystream = dual-block chain output. Verify against the captured
// same-run tuple: rbx=0x2b8001bf, key0=1da604c71259d39a47446fa349e14d7d,
// key2=3f633357dab87a91e719a96e0824ac0d, input="Anatolian_Hieroglyphs"
// -> dual output verified in TestMsgDualBlockEncrypt.
func TestMsgDecryptRegister(t *testing.T) {
	// Same-run message (session 365):
	//   iv = 74581e05c174c1c8c3a0184504e3d306
	//   ct = 0790f78ff38255b11eb2faa81c2a7241e4b7f77288 (21B)
	//   keystream prefix (16B) = 7cb2a1ea81eb33c855d7838a2608422d
	//   PT prefix = ct[0:16] XOR ks = {"VerifyKey":"0l...  (JSON register)
	ct, _ := hex.DecodeString("0790f78ff38255b11eb2faa81c2a7241")
	ks, _ := hex.DecodeString("7cb2a1ea81eb33c855d7838a2608422d")
	if len(ct) != 16 || len(ks) != 16 {
		t.Fatalf("len ct=%d ks=%d", len(ct), len(ks))
	}
	pt := make([]byte, 16)
	for i := 0; i < 16; i++ {
		pt[i] = ct[i] ^ ks[i]
	}
	got := string(pt)
	want := `{"VerifyKey":"0l`
	if got[:16] != want {
		t.Fatalf("PT prefix: got %q want %q", got[:16], want)
	}
	t.Logf("PT = %q (register JSON prefix confirmed)", got)
}
