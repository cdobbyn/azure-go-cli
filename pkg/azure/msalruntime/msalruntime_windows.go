//go:build windows

package msalruntime

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cdobbyn/azure-go-cli/pkg/logger"
	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

// defaultRedirectURI is the redirect the broker requires for interactive
// sign-in. WAM doesn't actually navigate to it, but the app registration must
// list it. Same value MSAL Python's broker uses.
const defaultRedirectURI = "https://login.microsoftonline.com/common/oauth2/nativeclient"

// cancelDrainTimeout bounds how long we wait for the completion callback of an
// operation we just canceled, so a wedged broker can't block the caller
// forever after its context is done.
const cancelDrainTimeout = 30 * time.Second

// defaultOperationTimeout bounds an operation whose context can never be done
// (context.Background, as the login command passes). Without it a wedged
// broker blocks the caller forever and the cancel path below is unreachable.
// Generous, because it also covers a user typing a password and doing MFA.
const defaultOperationTimeout = 10 * time.Minute

// --- async completion registry -------------------------------------------

// MSALRuntime hands the callbackData argument back verbatim on a thread it
// owns, so we pass a small integer key into this registry rather than a Go
// pointer.
type pending struct {
	ch        chan uintptr
	mu        sync.Mutex
	abandoned bool
}

var (
	regMu    sync.Mutex
	regSeq   uintptr
	registry = map[uintptr]*pending{}
)

func register() (uintptr, *pending) {
	p := &pending{ch: make(chan uintptr, 1)}
	regMu.Lock()
	defer regMu.Unlock()
	regSeq++
	registry[regSeq] = p
	return regSeq, p
}

func unregister(key uintptr) {
	regMu.Lock()
	delete(registry, key)
	regMu.Unlock()
}

// deliver runs on an MSALRuntime-owned thread. It does no work beyond handing
// the result handle to the waiting goroutine, and releases the handle itself
// if nobody is left to receive it.
func deliver(key, result uintptr, releaseResult func(uintptr)) {
	regMu.Lock()
	p := registry[key]
	delete(registry, key)
	regMu.Unlock()
	if p == nil {
		releaseResult(result)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.abandoned {
		releaseResult(result)
		return
	}
	p.ch <- result
}

// abandon drops a waiter: it removes the registry entry and marks the waiter
// gone, so a late callback releases the result handle instead of leaking it,
// and drains anything a callback already delivered.
func abandon(key uintptr, p *pending, releaseResult func(uintptr)) {
	unregister(key)
	p.mu.Lock()
	p.abandoned = true
	p.mu.Unlock()
	select {
	case h := <-p.ch:
		releaseResult(h)
	default:
	}
}

// windows.NewCallback has a hard process-wide limit, so there is exactly one
// callback per callback shape, created once.
var (
	authResultCallback = windows.NewCallback(func(result uintptr, callbackData uintptr) uintptr {
		deliver(callbackData&0xffffffff, result, releaseAuthResult)
		return 0
	})
	readAccountCallback = windows.NewCallback(func(result uintptr, callbackData uintptr) uintptr {
		deliver(callbackData&0xffffffff, result, releaseReadAccountResult)
		return 0
	})
)

func releaseAuthResult(h uintptr)        { discard(release(procReleaseAuthResult, h)) }
func releaseReadAccountResult(h uintptr) { discard(release(procReleaseReadAccountResult, h)) }
func releaseAccount(h uintptr)           { discard(release(procReleaseAccount, h)) }

// await starts an async operation and blocks until its completion callback
// fires or ctx is done.
func await(ctx context.Context, releaseResult func(uintptr), start func(callbackData uintptr, async *asyncHandle) errorHandle) (uintptr, error) {
	if ctx.Done() == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultOperationTimeout)
		defer cancel()
	}

	key, p := register()
	var async asyncHandle
	startErr := start(key, &async)
	// Armed before the error check: a failing call may still have written the
	// async handle, and it has to be released either way.
	if async != 0 {
		defer func() { discard(release(procReleaseAsyncHandle, uintptr(async))) }()
	}
	if err := toError(startErr); err != nil {
		// The callback can race a returned error; abandon drains whatever it
		// delivered instead of dropping a live result handle on the floor.
		abandon(key, p, releaseResult)
		return 0, err
	}

	select {
	case h := <-p.ch:
		if h == 0 {
			return 0, errors.New("msalruntime: broker returned an invalid result handle")
		}
		return h, nil
	case <-ctx.Done():
		if async != 0 {
			// Unlike MSALRUNTIME_ReleaseAsyncHandle, which takes the handle by
			// value, MSALRUNTIME_CancelAsyncOperation takes a pointer to it:
			// Microsoft's own binding declares it
			// `MSALRUNTIME_CancelAsyncOperation(AsyncHandle asyncHandle)`
			// against `MSALRUNTIME_ReleaseAsyncHandle(long asyncHandle)`, and
			// a JNA handle object marshals as the address of its handle
			// buffer. The completion callback still fires afterwards.
			discard(errorHandle(callRet(procCancelAsyncOperation, uintptr(unsafe.Pointer(&async)))))
		}
		select {
		case h := <-p.ch:
			releaseResult(h)
		case <-time.After(cancelDrainTimeout):
			abandon(key, p, releaseResult)
		}
		return 0, ctx.Err()
	}
}

// --- auth parameters ------------------------------------------------------

type authParams struct {
	h authParamsHandle
}

func newAuthParams(clientID, authority string, scopes []string) (*authParams, error) {
	cid, err := utf16Ptr(clientID)
	if err != nil {
		return nil, err
	}
	auth, err := utf16Ptr(authority)
	if err != nil {
		return nil, err
	}
	var h authParamsHandle
	r := callRet(procCreateAuthParameters,
		uintptr(unsafe.Pointer(cid)), uintptr(unsafe.Pointer(auth)), uintptr(unsafe.Pointer(&h)))
	runtime.KeepAlive(cid)
	runtime.KeepAlive(auth)
	if err := toError(errorHandle(r)); err != nil {
		return nil, err
	}
	if h == 0 {
		return nil, errors.New("msalruntime: broker returned an invalid auth parameters handle")
	}
	ap := &authParams{h: h}

	// Scopes are mandatory immediately after creation.
	if err := ap.setString(procSetRequestedScopes, strings.Join(scopes, " ")); err != nil {
		ap.release()
		return nil, err
	}
	return ap, nil
}

func (ap *authParams) setString(p *windows.LazyProc, value string) error {
	v, err := utf16Ptr(value)
	if err != nil {
		return err
	}
	r := callRet(p, uintptr(ap.h), uintptr(unsafe.Pointer(v)))
	runtime.KeepAlive(v)
	return toError(errorHandle(r))
}

func (ap *authParams) release() { discard(release(procReleaseAuthParameters, uintptr(ap.h))) }

// --- parent window --------------------------------------------------------

var (
	user32               = windows.NewLazySystemDLL("user32.dll")
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procGetAncestor      = user32.NewProc("GetAncestor")
	procGetDesktopWindow = user32.NewProc("GetDesktopWindow")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
)

// resolveParentWindow returns a window for the broker to parent its dialog to,
// plus a cleanup to run once the sign-in is over.
//
// The console window is used only when this process owns it. Under a ConPTY
// host it belongs to the terminal, and a dialog parented there never delivers
// its completion to us - see window_windows.go. In that case we pump our own
// hidden window instead.
func resolveParentWindow(hwnd uintptr) (uintptr, func()) {
	noop := func() {}
	if hwnd != 0 {
		return hwnd, noop
	}
	if console := callRet(procGetConsoleWindow); windowIsOurs(console) {
		const gaRootOwner = 3
		if owner := callRet(procGetAncestor, console, gaRootOwner); windowIsOurs(owner) {
			return owner, noop
		}
		return console, noop
	}
	if w, err := newPumpWindow(); err == nil {
		return w.hwnd, w.Close
	} else {
		// Falling back to the desktop window keeps the old behaviour rather
		// than failing a sign-in outright. It may still stall, so say why.
		logger.Debug("No console window of ours and no pump window (%v), parenting to the desktop", err)
	}
	return callRet(procGetDesktopWindow), noop
}

// --- public API -----------------------------------------------------------

// SignInInteractively signs a user in through the broker's UI and returns the
// resulting token. parentHWND may be 0, in which case the console (or
// desktop) window is used.
func SignInInteractively(ctx context.Context, authority, clientID string, scopes []string, parentHWND uintptr) (*AuthResult, error) {
	if err := Startup(); err != nil {
		return nil, err
	}
	ap, err := newAuthParams(clientID, authority, scopes)
	if err != nil {
		return nil, err
	}
	defer ap.release()
	if err := ap.setString(procSetRedirectUri, defaultRedirectURI); err != nil {
		return nil, err
	}

	correlationID, err := utf16Ptr(uuid.NewString())
	if err != nil {
		return nil, err
	}
	accountHint, err := utf16Ptr("")
	if err != nil {
		return nil, err
	}
	hwnd, closeWindow := resolveParentWindow(parentHWND)
	if hwnd == 0 {
		return nil, errors.New("msalruntime: no parent window handle available for interactive sign-in")
	}
	defer closeWindow()

	h, err := await(ctx, releaseAuthResult, func(callbackData uintptr, async *asyncHandle) errorHandle {
		r := callRet(procSignInInteractivelyAsync, hwnd, uintptr(ap.h),
			uintptr(unsafe.Pointer(correlationID)), uintptr(unsafe.Pointer(accountHint)),
			authResultCallback, callbackData, uintptr(unsafe.Pointer(async)))
		runtime.KeepAlive(correlationID)
		runtime.KeepAlive(accountHint)
		return errorHandle(r)
	})
	if err != nil {
		return nil, err
	}
	defer releaseAuthResult(h)
	return parseAuthResult(authResultHandle(h))
}

// AcquireTokenSilently gets a token for an account already known to the
// broker, without any UI. On a StatusInteractionRequired error the caller
// should fall back to SignInInteractively.
func AcquireTokenSilently(ctx context.Context, account *Account, authority, clientID string, scopes []string) (*AuthResult, error) {
	if err := Startup(); err != nil {
		return nil, err
	}
	if account == nil || account.handle == 0 {
		return nil, errors.New("msalruntime: account has no broker handle")
	}
	ap, err := newAuthParams(clientID, authority, scopes)
	if err != nil {
		return nil, err
	}
	defer ap.release()

	correlationID, err := utf16Ptr(uuid.NewString())
	if err != nil {
		return nil, err
	}

	h, err := await(ctx, releaseAuthResult, func(callbackData uintptr, async *asyncHandle) errorHandle {
		r := callRet(procAcquireTokenSilentlyAsync, uintptr(ap.h),
			uintptr(unsafe.Pointer(correlationID)), account.handle,
			authResultCallback, callbackData, uintptr(unsafe.Pointer(async)))
		runtime.KeepAlive(correlationID)
		return errorHandle(r)
	})
	if err != nil {
		return nil, err
	}
	defer releaseAuthResult(h)
	return parseAuthResult(authResultHandle(h))
}

// ReadAccountByID looks up a cached broker account. The returned Account owns
// a native handle and must be closed.
func ReadAccountByID(ctx context.Context, accountID string) (*Account, error) {
	if err := Startup(); err != nil {
		return nil, err
	}
	id, err := utf16Ptr(accountID)
	if err != nil {
		return nil, err
	}
	correlationID, err := utf16Ptr(uuid.NewString())
	if err != nil {
		return nil, err
	}

	h, err := await(ctx, releaseReadAccountResult, func(callbackData uintptr, async *asyncHandle) errorHandle {
		r := callRet(procReadAccountByIdAsync,
			uintptr(unsafe.Pointer(id)), uintptr(unsafe.Pointer(correlationID)),
			readAccountCallback, callbackData, uintptr(unsafe.Pointer(async)))
		runtime.KeepAlive(id)
		runtime.KeepAlive(correlationID)
		return errorHandle(r)
	})
	if err != nil {
		return nil, err
	}
	defer releaseReadAccountResult(h)

	// The outer call reports whether the getter worked; the handle it fills
	// carries the actual lookup failure.
	var inner errorHandle
	if err := toError(errorHandle(callRet(procGetReadAccountError, h, uintptr(unsafe.Pointer(&inner))))); err != nil {
		return nil, err
	}
	if err := toError(inner); err != nil {
		return nil, err
	}

	var ah accountHandle
	if err := toError(errorHandle(callRet(procGetReadAccount, h, uintptr(unsafe.Pointer(&ah))))); err != nil {
		return nil, err
	}
	if ah == 0 {
		return nil, errors.New("msalruntime: broker returned an invalid account handle")
	}
	return newAccount(ah), nil
}

// Close releases the account's native handle.
func (a *Account) Close() {
	if a == nil || a.handle == 0 {
		return
	}
	releaseAccount(a.handle)
	a.handle = 0
}

func newAccount(h accountHandle) *Account {
	a := &Account{handle: uintptr(h)}
	a.ID = readString(func(buf *uint16, size *int32) errorHandle {
		return errorHandle(callRet(procGetAccountId, uintptr(h), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(size))))
	})
	a.ClientInfo = readString(func(buf *uint16, size *int32) errorHandle {
		return errorHandle(callRet(procGetClientInfo, uintptr(h), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(size))))
	})
	a.HomeAccountID = homeAccountIDFromClientInfo(a.ClientInfo)
	return a
}

func parseAuthResult(h authResultHandle) (*AuthResult, error) {
	var inner errorHandle
	if err := toError(errorHandle(callRet(procGetError, uintptr(h), uintptr(unsafe.Pointer(&inner))))); err != nil {
		return nil, err
	}
	if err := toError(inner); err != nil {
		return nil, err
	}

	var isPop int32
	if err := toError(errorHandle(callRet(procIsPopAuthorization, uintptr(h), uintptr(unsafe.Pointer(&isPop))))); err != nil {
		return nil, err
	}

	res := &AuthResult{}
	if isPop == 1 {
		// Proof-of-possession tokens only come back inside the authorization
		// header, formatted "pop {signed access token}".
		header := readString(func(buf *uint16, size *int32) errorHandle {
			return errorHandle(callRet(procGetAuthorizationHeader, uintptr(h), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(size))))
		})
		_, token, ok := strings.Cut(header, " ")
		if !ok {
			return nil, fmt.Errorf("msalruntime: malformed authorization header from broker")
		}
		res.AccessToken = token
	} else {
		res.AccessToken = readString(func(buf *uint16, size *int32) errorHandle {
			return errorHandle(callRet(procGetAccessToken, uintptr(h), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(size))))
		})
	}
	if res.AccessToken == "" {
		return nil, errors.New("msalruntime: broker returned an empty access token")
	}
	res.ExpiresOn = accessTokenExpiry(res.AccessToken)
	res.IDToken = readString(func(buf *uint16, size *int32) errorHandle {
		return errorHandle(callRet(procGetRawIdToken, uintptr(h), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(size))))
	})

	var ah accountHandle
	if err := toError(errorHandle(callRet(procGetAccount, uintptr(h), uintptr(unsafe.Pointer(&ah))))); err != nil {
		return nil, err
	}
	if ah != 0 {
		account := newAccount(ah)
		defer account.Close()
		res.AccountID = account.ID
		res.HomeAccountID = account.HomeAccountID
	}
	return res, nil
}
