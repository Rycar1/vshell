package c2engine

import "testing"

// TestAgentFrameRoundTrip verifies the 24-byte typed-field wire format
// (aligned to FUN_0100d160): Append writes the record, Bytes serializes it
// in the exact field layout, ParseAgentFrame round-trips it.
func TestAgentFrameRoundTrip(t *testing.T) {
	f := NewAgentFrame(4)
	f.Append(FrameListRow, 1, 2, 3, 4)
	f.Append(FrameAck, 0x1020304, 0x5040302, 0x7060504, 0x102030405060708)
	if f.Len() != 2 {
		t.Fatalf("Len = %d, want 2", f.Len())
	}
	b := f.Bytes()
	if len(b) != 2*24 {
		t.Fatalf("Bytes len = %d, want 48", len(b))
	}
	// field 0 layout: kind@0, flags@1, w@2, a@4, b@8, c@0xc, d@0x10
	if b[0] != FrameListRow {
		t.Fatalf("kind byte = %#x, want %#x", b[0], FrameListRow)
	}
	got := ParseAgentFrame(b)
	if len(got) != 2 {
		t.Fatalf("parsed %d fields, want 2", len(got))
	}
	if got[0].Kind != FrameListRow || got[0].A != 1 || got[0].B != 2 || got[0].C != 3 || got[0].D != 4 {
		t.Fatalf("field0 mismatch: %+v", got[0])
	}
	if got[1].D != 0x102030405060708 {
		t.Fatalf("field1 D = %#x, want 0x102030405060708", got[1].D)
	}
	// growth path (cap 4 -> 8)
	g := NewAgentFrame(2)
	for i := range 6 {
		g.Append(FramePing, uint32(i), 0, 0, 0)
	}
	if g.Len() != 6 {
		t.Fatalf("grown Len = %d, want 6", g.Len())
	}
}
