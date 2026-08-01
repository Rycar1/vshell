package c2engine

import "testing"

func TestIsStreamingResult(t *testing.T) {
	streaming := []string{
		"terminal_output:aGVsbG8=",
		"screen_frame:png:1:aGVsbG8=",
	}
	notStreaming := []string{
		"hello world",
		"",
		"terminal",
		"screen",
	}
	for _, s := range streaming {
		if !IsStreamingResult(s) {
			t.Errorf("IsStreamingResult(%q) = false, want true", s)
		}
	}
	for _, s := range notStreaming {
		if IsStreamingResult(s) {
			t.Errorf("IsStreamingResult(%q) = true, want false", s)
		}
	}
}

func TestForwardStreamingResultInvokesHook(t *testing.T) {
	var gotClient int64 = -1
	var gotResult string
	SetResultForwardHook(func(clientID int64, result string) {
		gotClient = clientID
		gotResult = result
	})
	defer SetResultForwardHook(nil)

	if !forwardStreamingResult(42, "terminal_output:aGk=") {
		t.Fatal("forwardStreamingResult(terminal_output) = false, want true")
	}
	if gotClient != 42 || gotResult != "terminal_output:aGk=" {
		t.Fatalf("hook got (%d, %q), want (42, terminal_output:aGk=)", gotClient, gotResult)
	}

	// Non-streaming results must not invoke the hook.
	gotClient = -1
	gotResult = ""
	if forwardStreamingResult(42, "plain result") {
		t.Fatal("forwardStreamingResult(plain) = true, want false")
	}
	if gotClient != -1 {
		t.Fatalf("hook invoked for plain result: %d", gotClient)
	}
}
