//go:build windows
// +build windows

package keyring

import (
	"errors"
	"fmt"
	"os/user"
	"strings"
)

const (
	winHelloPassportKeyNameDomain    = "ByteNess"
	winHelloPassportKeyNameNamespace = "keyring-winhello"
)

var (
	errWinHelloPassportLogicalName = errors.New("winhello logical key name is required")
	errWinHelloPassportCurrentUser = errors.New("winhello current user SID is unavailable")
)

func winHelloPassportKeyName(logicalName string) (string, error) {
	if err := validateWinHelloPassportLogicalName(logicalName); err != nil {
		return "", err
	}

	currentUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("%w: %w", errWinHelloPassportCurrentUser, err)
	}
	if currentUser.Uid == "" {
		return "", errWinHelloPassportCurrentUser
	}

	return fmt.Sprintf(
		"%s//%s/%s/%s",
		currentUser.Uid,
		winHelloPassportKeyNameDomain,
		winHelloPassportKeyNameNamespace,
		logicalName,
	), nil
}

func validateWinHelloPassportLogicalName(logicalName string) error {
	if strings.TrimSpace(logicalName) == "" {
		return errWinHelloPassportLogicalName
	}
	if strings.ContainsAny(logicalName, `/\\`) {
		return fmt.Errorf("%w: %q contains path separator", errWinHelloPassportLogicalName, logicalName)
	}

	return nil
}
