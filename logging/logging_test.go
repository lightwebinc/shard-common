package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseFormat(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Format
	}{
		{"json", FormatJSON},
		{"JSON", FormatJSON},
		{" json ", FormatJSON},
		{"text", FormatText},
		{"", FormatText},
		{"garbage", FormatText},
	} {
		if got := ParseFormat(tc.in); got != tc.want {
			t.Errorf("ParseFormat(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseLevel(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"INFO", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"", slog.LevelInfo},
		{"nonsense", slog.LevelInfo},
	} {
		if got := ParseLevel(tc.in); got != tc.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestInitJSONIdentityAttrs(t *testing.T) {
	var buf bytes.Buffer
	lvl := Init(Options{
		Service:    "shard-proxy",
		InstanceID: "node-1",
		Version:    "v9.9.9",
		Level:      slog.LevelInfo,
		Format:     FormatJSON,
		Output:     &buf,
	})
	if lvl.Level() != slog.LevelInfo {
		t.Fatalf("level = %v, want info", lvl.Level())
	}
	slog.Info("hello", "k", "v")

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("output not JSON: %v (%q)", err, buf.String())
	}
	for k, want := range map[string]string{
		"service.name":        "shard-proxy",
		"service.instance.id": "node-1",
		"service.version":     "v9.9.9",
		"msg":                 "hello",
		"k":                   "v",
	} {
		if got, _ := rec[k].(string); got != want {
			t.Errorf("field %q = %q, want %q", k, got, want)
		}
	}
}

func TestInitRespectsLevelAndRuntimeChange(t *testing.T) {
	var buf bytes.Buffer
	lvl := Init(Options{Service: "s", InstanceID: "i", Version: "v", Level: slog.LevelInfo, Format: FormatJSON, Output: &buf})

	slog.Debug("suppressed")
	if buf.Len() != 0 {
		t.Fatalf("debug emitted at info level: %q", buf.String())
	}
	lvl.Set(slog.LevelDebug)
	slog.Debug("now visible")
	if !strings.Contains(buf.String(), "now visible") {
		t.Fatalf("debug not emitted after level raise: %q", buf.String())
	}
}

func TestInitInstanceFallback(t *testing.T) {
	var buf bytes.Buffer
	Init(Options{Service: "s", Version: "v", Format: FormatJSON, Output: &buf})
	slog.Info("x")
	var rec map[string]any
	_ = json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec)
	if got, _ := rec["service.instance.id"].(string); got == "" {
		t.Error("expected hostname fallback for empty InstanceID")
	}
}

func TestLevelHandler(t *testing.T) {
	lvl := &slog.LevelVar{}
	lvl.Set(slog.LevelInfo)
	h := LevelHandler(lvl)

	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodGet, "/loglevel", nil))
	if rr.Body.String() != "INFO" {
		t.Errorf("GET = %q, want INFO", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPost, "/loglevel?level=debug", nil))
	if lvl.Level() != slog.LevelDebug {
		t.Errorf("level after POST = %v, want debug", lvl.Level())
	}

	rr = httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPost, "/loglevel", nil))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("POST without level = %d, want 400", rr.Code)
	}

	rr = httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodDelete, "/loglevel", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE = %d, want 405", rr.Code)
	}
}

func TestThrottle(t *testing.T) {
	tn := time.Unix(0, 0)
	th := NewThrottle(time.Minute)
	th.now = func() time.Time { return tn }

	if emit, sup := th.Allow("k"); !emit || sup != 0 {
		t.Fatalf("first Allow = (%v,%d), want (true,0)", emit, sup)
	}
	for i := 0; i < 5; i++ {
		if emit, _ := th.Allow("k"); emit {
			t.Fatalf("Allow within window emitted on occurrence %d", i)
		}
	}
	// Distinct key emits immediately.
	if emit, _ := th.Allow("other"); !emit {
		t.Fatal("distinct key did not emit")
	}
	// Advance past window: emit again, reporting suppressed count.
	tn = tn.Add(2 * time.Minute)
	if emit, sup := th.Allow("k"); !emit || sup != 5 {
		t.Fatalf("post-window Allow = (%v,%d), want (true,5)", emit, sup)
	}
}
