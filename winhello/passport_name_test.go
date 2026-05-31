//go:build windows
// +build windows

package winhello

import (
	"errors"
	"os/user"
	"strings"
	"testing"
)

func TestWinHelloPassportKeyName(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current() failed: %v", err)
	}
	if currentUser.Uid == "" {
		t.Fatal("current user SID is empty")
	}

	logicalName := "keyring-winhello-v1"
	keyName, err := winHelloPassportKeyName(logicalName)
	if err != nil {
		t.Fatalf("winHelloPassportKeyName() failed: %v", err)
	}

	wantPrefix := currentUser.Uid + "//" + winHelloPassportKeyNameDomain + "/" + winHelloPassportKeyNameNamespace + "/"
	if !strings.HasPrefix(keyName, wantPrefix) {
		t.Fatalf("key name prefix = %q, want prefix %q", keyName, wantPrefix)
	}
	if !strings.HasSuffix(keyName, "/"+logicalName) {
		t.Fatalf("key name suffix = %q, want logical name %q", keyName, logicalName)
	}
}

func TestWinHelloPassportKeyNameRejectsInvalidLogicalName(t *testing.T) {
	testCases := []struct {
		name        string
		logicalName string
	}{
		{name: "empty", logicalName: ""},
		{name: "whitespace", logicalName: "  \t  "},
		{name: "forward slash", logicalName: "bad/name"},
		{name: "backslash", logicalName: `bad\name`},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := winHelloPassportKeyName(testCase.logicalName)
			if !errors.Is(err, errWinHelloPassportLogicalName) {
				t.Fatalf("error = %v, want %v", err, errWinHelloPassportLogicalName)
			}
		})
	}
}
