package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/log"
)

var (
	// logger is the default slog logger instance
	logger *slog.Logger
	// Output is the writer for log messages (defaults to stderr)
	Output io.Writer = os.Stderr
	// level is the level the handler was last built with, so that changing the
	// output writer doesn't silently reset it.
	level = slog.LevelInfo
)

func init() {
	// Initialize with default logger (Info level)
	SetLogLevel(slog.LevelInfo)
}

// SetLogLevel sets the logging level
func SetLogLevel(l slog.Level) {
	level = l
	rebuild()
}

// SetOutput routes log records to w.
//
// Stderr is the right default: most commands print JSON to stdout, and mixing
// progress lines into it would break any parser downstream. Purely interactive
// commands that emit no machine-readable output call this with os.Stdout,
// because PowerShell renders anything a native command writes to stderr as a
// NativeCommandError - so ordinary progress reads as a failure.
func SetOutput(w io.Writer) {
	Output = w
	rebuild()
}

func rebuild() {
	handler := slog.NewTextHandler(Output, &slog.HandlerOptions{
		Level: level,
	})
	logger = slog.New(handler)
}

// EnableDebug enables debug logging for both our logger and Azure SDK
func EnableDebug() {
	SetLogLevel(slog.LevelDebug)

	// Enable Azure SDK logging
	log.SetListener(func(event log.Event, message string) {
		logger.Debug("Azure SDK event", "event", event, "message", message)
	})

	// Set which Azure SDK events to log
	log.SetEvents(
		log.EventRequest,
		log.EventResponse,
		log.EventRetryPolicy,
	)
}

// DisableDebug disables debug logging (sets to Info level)
func DisableDebug() {
	SetLogLevel(slog.LevelInfo)
	log.SetListener(nil)
}

// Debug logs a debug message
func Debug(format string, args ...interface{}) {
	logger.Debug(fmt.Sprintf(format, args...))
}

// Info logs an informational message
func Info(format string, args ...interface{}) {
	logger.Info(fmt.Sprintf(format, args...))
}

// Warning logs a warning message
func Warning(format string, args ...interface{}) {
	logger.Warn(fmt.Sprintf(format, args...))
}

// Warn is an alias for Warning
func Warn(format string, args ...interface{}) {
	Warning(format, args...)
}

// Error logs an error message
func Error(format string, args ...interface{}) {
	logger.Error(fmt.Sprintf(format, args...))
}

// Print writes directly to stdout (for user-facing messages like prompts)
// This bypasses logging and is always shown
func Print(format string, args ...interface{}) {
	fmt.Fprintf(os.Stdout, format, args...)
}

// Println writes directly to stdout with newline (for user-facing messages)
func Println(format string, args ...interface{}) {
	fmt.Fprintf(os.Stdout, format+"\n", args...)
}
