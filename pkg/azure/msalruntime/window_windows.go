//go:build windows

package msalruntime

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The broker parents its sign-in dialog to the window handle we pass it, and
// drives that dialog from the owning thread's message queue. A console window
// only works when this process owns it.
//
// Under a ConPTY host - Windows Terminal, VS Code, an AVD RemoteApp - the
// window GetConsoleWindow reports belongs to the terminal process, not to us.
// The dialog still appears and sign-in still succeeds, but the completion
// never reaches our callback and SignInInteractively blocks until the 10
// minute timeout. The same binary under a classic conhost works, which is why
// this looks like a PowerShell bug and is not one.
//
// When the console window is not ours, we make a window that is: a hidden
// top-level window on a dedicated thread running a message pump. The user sees
// nothing extra; the broker gets a queue that belongs to this process.

var (
	procRegisterClassExW         = user32.NewProc("RegisterClassExW")
	procUnregisterClassW         = user32.NewProc("UnregisterClassW")
	procCreateWindowExW          = user32.NewProc("CreateWindowExW")
	procDestroyWindow            = user32.NewProc("DestroyWindow")
	procDefWindowProcW           = user32.NewProc("DefWindowProcW")
	procGetMessageW              = user32.NewProc("GetMessageW")
	procTranslateMessage         = user32.NewProc("TranslateMessage")
	procDispatchMessageW         = user32.NewProc("DispatchMessageW")
	procPostMessageW             = user32.NewProc("PostMessageW")
	procPostQuitMessage          = user32.NewProc("PostQuitMessage")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
	procGetModuleHandleW         = kernel32.NewProc("GetModuleHandleW")
)

const (
	wmDestroy = 0x0002
	wmClose   = 0x0010

	wsOverlapped = 0x00000000
)

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       windows.Handle
}

type msgW struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      struct{ x, y int32 }
}

// windowProc is created once: windows.NewCallback has a hard process-wide
// limit on how many callbacks a program may create.
var windowProc = windows.NewCallback(func(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	if msg == wmDestroy {
		callRet(procPostQuitMessage, 0)
		return 0
	}
	return callRet(procDefWindowProcW, hwnd, uintptr(msg), wParam, lParam)
})

const pumpWindowClass = "AzGoCliBrokerParent"

var registerClassOnce struct {
	sync.Once
	err error
}

func registerPumpClass() error {
	registerClassOnce.Do(func() {
		name, err := windows.UTF16PtrFromString(pumpWindowClass)
		if err != nil {
			registerClassOnce.err = err
			return
		}
		instance := callRet(procGetModuleHandleW, 0)
		class := wndClassExW{
			lpfnWndProc:   windowProc,
			hInstance:     windows.Handle(instance),
			lpszClassName: name,
		}
		class.cbSize = uint32(unsafe.Sizeof(class))
		if atom := callRet(procRegisterClassExW, uintptr(unsafe.Pointer(&class))); atom == 0 {
			registerClassOnce.err = fmt.Errorf("msalruntime: RegisterClassExW: %w", windows.GetLastError())
		}
		runtime.KeepAlive(name)
	})
	return registerClassOnce.err
}

// pumpWindow is a hidden window whose messages are pumped by the thread that
// created it. Close it when the sign-in that needed it is finished.
type pumpWindow struct {
	hwnd uintptr
	done chan struct{}
}

// newPumpWindow creates the window and starts pumping. The pump owns an OS
// thread for its whole life: a window's messages can only be dispatched by the
// thread that created it, and Go moves goroutines between threads freely.
func newPumpWindow() (*pumpWindow, error) {
	if err := registerPumpClass(); err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(pumpWindowClass)
	if err != nil {
		return nil, err
	}

	created := make(chan uintptr, 1)
	failed := make(chan error, 1)
	w := &pumpWindow{done: make(chan struct{})}

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(w.done)

		hwnd := callRet(procCreateWindowExW,
			0,                             // dwExStyle
			uintptr(unsafe.Pointer(name)), // lpClassName
			uintptr(unsafe.Pointer(name)), // lpWindowName
			wsOverlapped,                  // dwStyle, without WS_VISIBLE
			0, 0, 0, 0,                    // x, y, width, height
			0, 0, // hWndParent, hMenu
			callRet(procGetModuleHandleW, 0), // hInstance
			0,                                // lpParam
		)
		runtime.KeepAlive(name)
		if hwnd == 0 {
			failed <- fmt.Errorf("msalruntime: CreateWindowExW: %w", windows.GetLastError())
			return
		}
		created <- hwnd

		var msg msgW
		for {
			// GetMessageW returns 0 at WM_QUIT and -1 on error. Either ends the
			// pump; leaving the loop running on an error would spin forever.
			r := callRet(procGetMessageW, uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
			if r == 0 || int32(r) == -1 {
				return
			}
			callRet(procTranslateMessage, uintptr(unsafe.Pointer(&msg)))
			callRet(procDispatchMessageW, uintptr(unsafe.Pointer(&msg)))
		}
	}()

	select {
	case hwnd := <-created:
		w.hwnd = hwnd
		return w, nil
	case err := <-failed:
		return nil, err
	}
}

// Close destroys the window and waits for its pump to stop. WM_CLOSE is posted
// rather than sent because DestroyWindow must run on the owning thread.
func (w *pumpWindow) Close() {
	if w == nil || w.hwnd == 0 {
		return
	}
	callRet(procPostMessageW, w.hwnd, wmClose, 0, 0)
	<-w.done
	w.hwnd = 0
}

// windowIsOurs reports whether hwnd belongs to this process. A window owned by
// a terminal host cannot pump the broker's messages for us.
func windowIsOurs(hwnd uintptr) bool {
	if hwnd == 0 {
		return false
	}
	var pid uint32
	callRet(procGetWindowThreadProcessId, hwnd, uintptr(unsafe.Pointer(&pid)))
	return pid != 0 && pid == uint32(windows.GetCurrentProcessId())
}
