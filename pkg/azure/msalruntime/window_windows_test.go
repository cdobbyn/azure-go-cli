//go:build windows

package msalruntime

import "testing"

// A window the broker can pump has to belong to this process, and it has to
// shut down cleanly - Close blocks on the pump goroutine, so a pump that never
// exits hangs this test rather than passing it.
func TestPumpWindowIsOwnedByThisProcess(t *testing.T) {
	w, err := newPumpWindow()
	if err != nil {
		t.Fatalf("newPumpWindow: %v", err)
	}
	defer w.Close()

	if w.hwnd == 0 {
		t.Fatal("newPumpWindow returned a zero handle")
	}
	if !windowIsOurs(w.hwnd) {
		t.Error("pump window is not owned by this process")
	}
}

func TestPumpWindowCloseIsIdempotent(t *testing.T) {
	w, err := newPumpWindow()
	if err != nil {
		t.Fatalf("newPumpWindow: %v", err)
	}
	w.Close()
	w.Close() // must not panic, block, or double-post to a dead window
}

func TestWindowIsOursRejectsZero(t *testing.T) {
	if windowIsOurs(0) {
		t.Error("windowIsOurs(0) = true, want false")
	}
}
