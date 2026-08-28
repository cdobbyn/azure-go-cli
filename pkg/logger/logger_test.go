package logger

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// Login routes logs to stdout so PowerShell doesn't render them as errors.
// That only works if SetOutput actually rebuilds the handler.
func TestSetOutputRedirectsRecords(t *testing.T) {
	original := Output
	t.Cleanup(func() { SetOutput(original) })

	var buf bytes.Buffer
	SetOutput(&buf)
	Info("retrieving tenants")

	if !strings.Contains(buf.String(), "retrieving tenants") {
		t.Fatalf("SetOutput did not redirect the record, got %q", buf.String())
	}
}

func TestSetOutputKeepsLevel(t *testing.T) {
	original := Output
	t.Cleanup(func() {
		SetLogLevel(slog.LevelInfo)
		SetOutput(original)
	})

	SetLogLevel(slog.LevelDebug)

	var buf bytes.Buffer
	SetOutput(&buf)
	Debug("still debugging")

	if !strings.Contains(buf.String(), "still debugging") {
		t.Fatalf("SetOutput reset the level back to Info, got %q", buf.String())
	}
}
