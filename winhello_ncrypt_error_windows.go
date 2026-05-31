//go:build windows
// +build windows

package keyring

import (
	"errors"
	"fmt"
	"syscall"
)

const winHelloNCryptSetupHint = " - Please ensure Windows Hello is set up correctly and a PIN or biometric authentication method is configured!"

type ncryptHandle uintptr

const (
	winHelloNCryptRSAAlgorithm     = "RSA"
	winHelloNCryptSoftwareProvider = "Microsoft Software Key Storage Provider"

	winHelloNCryptLengthProperty                    = "Length"
	winHelloNCryptKeyUsageProperty                  = "Key Usage"
	winHelloNCryptNgcCacheTypeProperty              = "NgcCacheType"
	winHelloNCryptNgcCacheTypeLegacyProperty        = "NgcCacheTypeProperty"
	winHelloNCryptPinCacheIsGestureRequiredProperty = "PinCacheIsGestureRequired"
	winHelloNCryptUseContextProperty                = "Use Context"
	winHelloNCryptWindowHandleProperty              = "HWND Handle"

	winHelloNCryptPadPKCS1Flag = 0x00000002
	winHelloNCryptSilentFlag   = 0x00000040 // Used only for a security test - silent mode may never allow accessing the key

	winHelloNCryptAllowDecryptFlag          = 0x00000001
	winHelloNCryptAllowSigningFlag          = 0x00000002
	winHelloNCryptNgcCacheTypeAuthMandatory = 0x00000001
)

const (
	errWinHelloNCryptBadKeyset        syscall.Errno = 0x80090016
	errWinHelloNCryptNoKey            syscall.Errno = 0x8009000d
	errWinHelloNCryptNotFound         syscall.Errno = 0x80090011
	errWinHelloNCryptNotSupported     syscall.Errno = 0x80090029
	errWinHelloNCryptDeviceNotReady   syscall.Errno = 0x80090030
	errWinHelloNCryptUserCancelled    syscall.Errno = 0x80090036
	errWinHelloNCryptInvalidParameter syscall.Errno = 0x80090027
	errWinHelloWin32InvalidParameter  syscall.Errno = 87
)

func winHelloNCryptError(status uintptr) error {
	if status == 0 {
		return nil
	}

	err := syscall.Errno(status)
	if isWinHelloNCryptSetupRequired(err) {
		return fmt.Errorf("%w%s", err, winHelloNCryptSetupHint)
	}

	return err
}

func isWinHelloNCryptKeyNotFound(err error) bool {
	return errors.Is(err, errWinHelloNCryptBadKeyset) ||
		errors.Is(err, errWinHelloNCryptNoKey) ||
		errors.Is(err, errWinHelloNCryptNotFound)
}

func isWinHelloNCryptInvalidParameter(err error) bool {
	return errors.Is(err, errWinHelloNCryptInvalidParameter) ||
		errors.Is(err, errWinHelloWin32InvalidParameter)
}

func isWinHelloNCryptUserCancelled(err error) bool {
	return errors.Is(err, errWinHelloNCryptUserCancelled)
}

func isWinHelloNCryptSetupRequired(err error) bool {
	return errors.Is(err, errWinHelloNCryptNotSupported) ||
		errors.Is(err, errWinHelloNCryptDeviceNotReady)
}
