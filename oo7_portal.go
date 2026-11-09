//go:build linux && !keyring_nooo7

package keyring

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	oo7PortalBusName          = "org.freedesktop.portal.Desktop"
	oo7PortalPath             = "/org/freedesktop/portal/desktop"
	oo7PortalSecretInterface  = "org.freedesktop.portal.Secret"
	oo7PortalRequestInterface = "org.freedesktop.portal.Request"
	oo7PortalResponseSignal   = oo7PortalRequestInterface + ".Response"
	oo7PortalReadTimeout      = 10 * time.Second
)

// oo7PortalTimeout bounds the wait for the portal's Response. The portal may
// have to unlock the login keyring first, which can prompt the user.
const oo7PortalTimeout = 2 * time.Minute

// oo7PortalSecret is the portal retrieval used by the backend; tests replace
// it, since a real portal only answers identifiable applications.
var oo7PortalSecret = oo7RetrievePortalSecret

// oo7RetrievePortalSecret asks the Secret portal
// (org.freedesktop.portal.Secret.RetrieveSecret) for this application's
// secret. The portal writes it to a pipe we hand over and announces completion
// with a Response signal on a Request object.
func oo7RetrievePortalSecret() ([]byte, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, fmt.Errorf("oo7: cannot reach the Secret portal: %w", err)
	}
	if !conn.SupportsUnixFDs() {
		return nil, errors.New("oo7: cannot reach the Secret portal: the session bus does not support fd passing")
	}

	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	token := "keyring" + hex.EncodeToString(rnd[:])
	sender := strings.ReplaceAll(strings.TrimPrefix(conn.Names()[0], ":"), ".", "_")
	requestPath := dbus.ObjectPath(fmt.Sprintf("%s/request/%s/%s", oo7PortalPath, sender, token))

	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	defer conn.RemoveSignal(signals)
	match := []dbus.MatchOption{
		dbus.WithMatchInterface(oo7PortalRequestInterface),
		dbus.WithMatchMember("Response"),
		dbus.WithMatchObjectPath(requestPath),
	}
	if err := conn.AddMatchSignal(match...); err != nil {
		return nil, fmt.Errorf("oo7: cannot reach the Secret portal: %w", err)
	}
	defer func() { _ = conn.RemoveMatchSignal(match...) }()

	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()

	call := conn.Object(oo7PortalBusName, oo7PortalPath).Call(
		oo7PortalSecretInterface+".RetrieveSecret", 0,
		dbus.UnixFD(w.Fd()),
		map[string]dbus.Variant{"handle_token": dbus.MakeVariant(token)},
	)
	_ = w.Close()
	if call.Err != nil {
		return nil, fmt.Errorf("oo7: cannot reach the Secret portal: %w", call.Err)
	}
	var handle dbus.ObjectPath
	if err := call.Store(&handle); err != nil {
		return nil, err
	}
	if handle != requestPath {
		return nil, fmt.Errorf("oo7: the Secret portal answered on %s, expected %s", handle, requestPath)
	}

	type readResult struct {
		data []byte
		err  error
	}
	readDone := make(chan readResult, 1)
	go func() {
		data, err := io.ReadAll(r)
		readDone <- readResult{data: data, err: err}
	}()

	timeout := time.NewTimer(oo7PortalTimeout)
	defer timeout.Stop()
	for responded := false; !responded; {
		select {
		case sig, ok := <-signals:
			if !ok {
				return nil, errors.New("oo7: the session bus connection was closed")
			}
			if sig.Name != oo7PortalResponseSignal || sig.Path != requestPath || len(sig.Body) == 0 {
				continue
			}
			code, _ := sig.Body[0].(uint32)
			switch code {
			case 0:
				responded = true
			case 1:
				return nil, errors.New("oo7: the Secret portal request was cancelled")
			default:
				return nil, fmt.Errorf("oo7: the Secret portal refused the request (response %d); it only serves applications it can identify, such as sandboxed ones", code)
			}
		case <-timeout.C:
			return nil, fmt.Errorf("oo7: timed out after %s waiting for the Secret portal", oo7PortalTimeout)
		}
	}

	select {
	case res := <-readDone:
		if res.err != nil {
			return nil, res.err
		}
		if len(res.data) == 0 {
			return nil, errors.New("oo7: the Secret portal returned an empty secret")
		}
		return res.data, nil
	case <-time.After(oo7PortalReadTimeout):
		return nil, errors.New("oo7: timed out reading the secret from the Secret portal")
	}
}
