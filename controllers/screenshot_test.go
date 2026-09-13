package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web/context"

	"vshell/c2engine"
)

// newControllerFor wires a specific controller to a recorder the way beego's
// router does (api_test.go's newTestController covers ApiBaseController only).
func newControllerFor(ctrl *ScreenshotController, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	ctrl.Controller.Ctx = context.NewContext()
	ctrl.Controller.Data = make(map[interface{}]interface{})
	ctrl.Controller.Ctx.Reset(rec, req)
	return rec
}

// The screenshot page consumes Get()'s result as a bare base64 string
// (`data:image/jpeg;base64,<result>`), so the body must be the image data —
// not a JSON envelope.
func TestScreenshotGetReturnsRawBase64(t *testing.T) {
	initEngineStorage(t)

	client, err := c2engine.GetEngine().NewClient("shot-vkey", "http", "127.0.0.1:1",
		"127.0.0.1", "u", "h", "windows", "agent")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	client.Status = true

	want := "iVBORw0KGgoAAAANSUhEUg=="

	// Stand in for the agent: answer the queued screenshot task.
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			for _, task := range c2engine.GetEngine().GetPendingTasks(client.ID) {
				_ = c2engine.GetEngine().UpdateTask(task.ID, want, "completed")
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	ctrl := &ScreenshotController{}
	req := httptest.NewRequest(http.MethodGet,
		"/api/screenshot/get?id="+itoa(int(client.ID))+"&quality=normal", nil)
	rec := newControllerFor(ctrl, req)
	ctrl.Get()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	got := rec.Body.String()
	if got != want {
		t.Fatalf("body = %q, want raw base64 %q", got, want)
	}
	if json.Valid([]byte(got)) {
		t.Fatalf("body looks like JSON (%q), the SPA expects bare base64", got)
	}
}

// A missing client is reported as an error envelope; no task is queued for it.
// The HTTP status stays 200 — JsonErr leaves the status alone, matching the
// original binary's convention (errors ride in "code", the SPA checks that).
func TestScreenshotGetReportsClosedClient(t *testing.T) {
	initEngineStorage(t)

	ctrl := &ScreenshotController{}
	req := httptest.NewRequest(http.MethodGet, "/api/screenshot/get?id=777", nil)
	rec := newControllerFor(ctrl, req)
	ctrl.Get()

	body := rec.Body.String()
	if !strings.Contains(body, `"code":-1`) || !strings.Contains(body, "client is close") {
		t.Fatalf("body = %q, want an error envelope for a closed client", body)
	}
	if n := len(c2engine.GetEngine().GetPendingTasks(777)); n != 0 {
		t.Fatalf("queued %d tasks for a closed client, want 0", n)
	}
}
