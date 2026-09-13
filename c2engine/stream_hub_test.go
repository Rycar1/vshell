package c2engine

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"io"
	"sync"
	"testing"
)

// fakeViewer records everything published to it.
type fakeViewer struct {
	mu       sync.Mutex
	texts    [][]byte
	binaries [][]byte
	closed   bool
}

func (f *fakeViewer) SendBinary(d []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.binaries = append(f.binaries, append([]byte(nil), d...))
	return nil
}

func (f *fakeViewer) SendText(d []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.texts = append(f.texts, append([]byte(nil), d...))
	return nil
}

func (f *fakeViewer) SendJSON(interface{}) error { return nil }
func (f *fakeViewer) Close() error               { f.closed = true; return nil }

func (f *fakeViewer) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.texts), len(f.binaries)
}

// Terminal output from an agent reaches every registered terminal viewer as
// raw (decoded) shell bytes, and only viewers of that client.
func TestTerminalOutputRelaysToViewer(t *testing.T) {
	SetResultForwardHook(nil)
	v := &fakeViewer{}
	other := &fakeViewer{}
	RegisterViewer(StreamTerminal, 7, v)
	RegisterViewer(StreamTerminal, 8, other)
	defer UnregisterViewer(StreamTerminal, 7, v)
	defer UnregisterViewer(StreamTerminal, 8, other)

	payload := base64.StdEncoding.EncodeToString([]byte("hello\r\n"))
	if !forwardStreamingResult(7, terminalResultPrefix+payload) {
		t.Fatal("terminal result not treated as streaming")
	}

	if n, _ := v.counts(); n != 1 {
		t.Fatalf("terminal viewer got %d text frames, want 1", n)
	}
	if got := string(v.texts[0]); got != "hello\r\n" {
		t.Fatalf("relayed output = %q, want %q", got, "hello\r\n")
	}
	if n, _ := other.counts(); n != 0 {
		t.Fatalf("viewer of another client got %d frames, want 0", n)
	}
}

// Screen frames arrive zlib-compressed, matching what the SPA inflates before
// handing the bytes to <img>.
func TestScreenFrameRelaysZlibCompressed(t *testing.T) {
	v := &fakeViewer{}
	RegisterViewer(StreamScreen, 3, v)
	defer UnregisterViewer(StreamScreen, 3, v)

	img := bytes.Repeat([]byte{0xFF, 0xD8, 0xFF, 0xE0}, 64) // JPEG-ish payload
	result := screenResultPrefix + "png:1:" + base64.StdEncoding.EncodeToString(img)
	if !forwardStreamingResult(3, result) {
		t.Fatal("screen result not treated as streaming")
	}

	_, n := v.counts()
	if n != 1 {
		t.Fatalf("screen viewer got %d binary frames, want 1", n)
	}
	frame := v.binaries[0]
	zr, err := zlib.NewReader(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("frame is not zlib: %v", err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("inflate: %v", err)
	}
	if !bytes.Equal(got, img) {
		t.Fatalf("inflated frame mismatch: %d bytes", len(got))
	}
}

// A frame with no viewers yet is not an error and must not be stored as a task
// result (forwardStreamingResult reports it as consumed).
func TestStreamingResultConsumedWithoutViewers(t *testing.T) {
	RegisterViewer(StreamTerminal, 11, &fakeViewer{})
	if !IsStreamingResult(terminalResultPrefix + "aGk=") {
		t.Fatal("IsStreamingResult = false")
	}
	if !forwardStreamingResult(11, "screen_frame:png:2:aGk=") {
		t.Fatal("screen frame not consumed without a screen viewer")
	}
}

// Sessions bind a viewer to the agent task carrying its traffic.
func TestStreamSessionRoundTrip(t *testing.T) {
	v := &fakeViewer{}
	SetStreamSession(StreamScreen, 21, &StreamSession{Viewer: v, ClientID: 21, TaskID: 99})
	if id := StreamSessionTaskID(StreamScreen, 21); id != 99 {
		t.Fatalf("StreamSessionTaskID = %d, want 99", id)
	}
	ClearStreamSession(StreamScreen, 21)
	if id := StreamSessionTaskID(StreamScreen, 21); id != 0 {
		t.Fatalf("StreamSessionTaskID after clear = %d, want 0", id)
	}
}

// Viewer registration is counted per (kind, client).
func TestViewerCountPerKind(t *testing.T) {
	a, b := &fakeViewer{}, &fakeViewer{}
	RegisterViewer(StreamTerminal, 31, a)
	RegisterViewer(StreamTerminal, 31, b)
	RegisterViewer(StreamScreen, 31, a)
	defer func() {
		UnregisterViewer(StreamTerminal, 31, a)
		UnregisterViewer(StreamTerminal, 31, b)
		UnregisterViewer(StreamScreen, 31, a)
	}()
	if n := ViewerCount(StreamTerminal, 31); n != 2 {
		t.Fatalf("terminal viewers = %d, want 2", n)
	}
	if n := ViewerCount(StreamScreen, 31); n != 1 {
		t.Fatalf("screen viewers = %d, want 1", n)
	}
	UnregisterViewer(StreamTerminal, 31, a)
	UnregisterViewer(StreamTerminal, 31, b)
	if n := ViewerCount(StreamTerminal, 31); n != 0 {
		t.Fatalf("terminal viewers after unregister = %d, want 0", n)
	}
}

// The agent emits screen_frame:<format>:<index>:<quality>:<base64>; the frame
// must still be decoded from the trailing base64 field.
func TestScreenFrameParsesQualityField(t *testing.T) {
	v := &fakeViewer{}
	RegisterViewer(StreamScreen, 41, v)
	defer UnregisterViewer(StreamScreen, 41, v)

	img := []byte("JPEGDATA")
	result := screenResultPrefix + "png:7:60:" + base64.StdEncoding.EncodeToString(img)
	if !forwardStreamingResult(41, result) {
		t.Fatal("screen result with quality field not streaming")
	}
	_, n := v.counts()
	if n != 1 {
		t.Fatalf("binary frames = %d, want 1", n)
	}
	zr, err := zlib.NewReader(bytes.NewReader(v.binaries[0]))
	if err != nil {
		t.Fatalf("not zlib: %v", err)
	}
	got, _ := io.ReadAll(zr)
	if string(got) != string(img) {
		t.Fatalf("inflated = %q, want %q", got, img)
	}
}
