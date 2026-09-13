package controllers

import (
	"encoding/json"
	"testing"
)

// The original `ls` handler (0x18e4d80) accepts only agent reply lines whose
// TAB-split field count is exactly 4, truncates the trailing "/" that marks a
// directory, parses field[1] as a base-10 size, and keeps field[2]/field[3] as
// the time and mode text.
func TestParseLsReplyPanelShape(t *testing.T) {
	reply := "docs/\t4096\t2024-05-01 12:00:00\tdrwxr-xr-x\n" +
		"report.tar.gz\t1048576\t2024-05-02 08:30:00\t-rw-r--r--\n"

	items := parseLsReply(reply)
	if len(items) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(items), items)
	}

	dir := items[0]
	if dir.Name != "docs" || !dir.IsDir {
		t.Errorf("dir entry = %+v, want name docs with isDir true", dir)
	}
	if dir.Size != 4096 || dir.Time != "2024-05-01 12:00:00" || dir.Mode != "drwxr-xr-x" {
		t.Errorf("dir fields = %+v", dir)
	}

	file := items[1]
	if file.Name != "report.tar.gz" || file.IsDir {
		t.Errorf("file entry = %+v, want name report.tar.gz with isDir false", file)
	}
	if file.Size != 1048576 || file.Mode != "-rw-r--r--" {
		t.Errorf("file fields = %+v", file)
	}

	// The panel reads "name"/"time"/"mode"/"size" plus "isDir" off each row.
	raw, err := json.Marshal(items[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"name", "time", "mode", "size", "isDir"} {
		if _, ok := m[key]; !ok {
			t.Errorf("entry JSON %s is missing key %q", raw, key)
		}
	}
}

// Lines whose field count is not 4 are dropped (the original's CMP RBX,0x4
// guard), blank lines included.
func TestParseLsReplyDropsMalformedLines(t *testing.T) {
	reply := "onlyone\n" +
		"two\tfields\n" +
		"a\tb\tc\n" +
		"good\t1\t2024-01-01\t-rw-\n" +
		"five\t1\t2\t3\t4\n" +
		"\n"

	items := parseLsReply(reply)
	if len(items) != 1 || items[0].Name != "good" {
		t.Fatalf("items = %+v, want only the 4-field line", items)
	}
}

// A size that is not a number leaves Size at 0 rather than failing the line
// (FUN_004b1280 returns 0 on a parse error).
func TestParseLsReplyUnparsableSize(t *testing.T) {
	items := parseLsReply("big.bin\t-\t2024-01-01\t-rw-\n")
	if len(items) != 1 || items[0].Size != 0 {
		t.Fatalf("items = %+v, want one entry with size 0", items)
	}
}

// FUN_018e5740 compares by field ("name"/"time"/"size") under order
// "ascend"/"descend"; any other field/order leaves the reply order alone.
func TestSortListEntries(t *testing.T) {
	base := func() []listEntry {
		return []listEntry{
			{Name: "b", Size: 2, Time: "2024-01-02"},
			{Name: "a", Size: 30, Time: "2024-01-03"},
			{Name: "c", Size: 1, Time: "2024-01-01"},
		}
	}()
	names := func(es []listEntry) string {
		out := ""
		for _, e := range es {
			out += e.Name
		}
		return out
	}

	cases := []struct {
		field, order, want string
	}{
		{"name", "ascend", "abc"},
		{"name", "descend", "cba"},
		{"size", "ascend", "cba"},  // 1(c), 2(b), 30(a)
		{"size", "descend", "abc"}, // reversed
		{"time", "ascend", "cba"},  // 01-01(c), 01-02(b), 01-03(a)
		{"time", "descend", "abc"},
		{"", "", "bac"},             // no field/order -> untouched
		{"name", "sideways", "bac"}, // unknown order -> untouched
		{"owner", "ascend", "bac"},  // unknown field -> no comparison
	}
	for _, tc := range cases {
		es := append([]listEntry(nil), base...)
		sortListEntries(es, tc.field, tc.order)
		if got := names(es); got != tc.want {
			t.Errorf("sort(%q,%q) = %s, want %s", tc.field, tc.order, got, tc.want)
		}
	}
}

// engineListDir runs `ls <path>` through the task queue and maps the answer to
// the panel's {total, items} shape. A client that is not connected fails the
// command, which yields an empty list rather than an error to the panel.
func TestEngineListDirUnreachableClient(t *testing.T) {
	items, total := engineListDir(4242, "/tmp", "name", "ascend")
	if total != 0 || len(items) != 0 {
		t.Fatalf("items=%+v total=%d, want empty list", items, total)
	}
}

// downloadTasks is keyed per client by the panel's task id; the entry point
// stores the joined path the original builds with FUN_0044a940.
func TestEngineDownloadToServerRegistersTask(t *testing.T) {
	delete(downloadTasks, 1)
	taskID := engineDownloadToServer(4242, "/var/log", "app.log")
	task, ok := downloadTasks[taskID]
	if !ok {
		t.Fatalf("task %d not registered", taskID)
	}
	defer delete(downloadTasks, taskID)
	if task.ClientID != 4242 || task.Path != "/var/log/app.log" {
		t.Fatalf("task = %+v, want client 4242 path /var/log/app.log", task)
	}
}

// The file manager must keep returning the panel's list shape; guard the
// response keys against an accidental rename.
func TestEngineListDirResponseKeys(t *testing.T) {
	items := parseLsReply("x\t1\t2024-01-01\t-rw-\n")
	payload := map[string]interface{}{"total": int64(len(items)), "items": items}
	raw, _ := json.Marshal(payload)
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["total"].(float64); !ok {
		t.Errorf("total missing from %s", raw)
	}
	if arr, ok := m["items"].([]interface{}); !ok || len(arr) != 1 {
		t.Errorf("items = %v, want a one-element array", m["items"])
	}
}
