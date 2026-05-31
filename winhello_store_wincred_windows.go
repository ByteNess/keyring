//go:build windows
// +build windows

package keyring

import (
	"bytes"
	"errors"
	"sort"
	"strings"

	"github.com/danieljoos/wincred"
)

const winHelloWinCredPrefix = "keyring-winhello"

// winHelloWinCredStore stores encrypted envelopes in Windows Credential
// Manager under a prefix that is separate from the plaintext wincred backend.
type winHelloWinCredStore struct {
	serviceName string
}

type winHelloWinCredCredential interface {
	Write() error
	Delete() error
	Blob() []byte
	SetBlob(data []byte)
	TargetName() string
}

type winHelloWinCredListEntry interface {
	TargetName() string
}

type winHelloGenericCredentialAdapter struct {
	credential *wincred.GenericCredential
}

type winHelloListEntryAdapter struct {
	targetName string
}

var (
	winHelloGetGenericCredentialFunc = func(target string) (winHelloWinCredCredential, error) {
		cred, err := wincred.GetGenericCredential(target)
		if err != nil {
			return nil, err
		}

		return &winHelloGenericCredentialAdapter{credential: cred}, nil
	}
	winHelloNewGenericCredentialFunc = func(target string) winHelloWinCredCredential {
		cred := wincred.NewGenericCredential(target)
		cred.Persist = wincred.PersistLocalMachine
		return &winHelloGenericCredentialAdapter{credential: cred}
	}
	winHelloListCredentialsFunc = func() ([]winHelloWinCredListEntry, error) {
		creds, err := wincred.List()
		if err != nil {
			return nil, err
		}

		results := make([]winHelloWinCredListEntry, 0, len(creds))
		for _, cred := range creds {
			results = append(results, &winHelloListEntryAdapter{targetName: cred.TargetName})
		}

		return results, nil
	}
)

func newWinHelloWinCredStore(serviceName string) *winHelloWinCredStore {
	if serviceName == "" {
		serviceName = "default"
	}

	return &winHelloWinCredStore{serviceName: serviceName}
}

func (a *winHelloGenericCredentialAdapter) Write() error {
	return a.credential.Write()
}

func (a *winHelloGenericCredentialAdapter) Delete() error {
	return a.credential.Delete()
}

func (a *winHelloGenericCredentialAdapter) Blob() []byte {
	return a.credential.CredentialBlob
}

func (a *winHelloGenericCredentialAdapter) SetBlob(data []byte) {
	a.credential.CredentialBlob = data
}

func (a *winHelloGenericCredentialAdapter) TargetName() string {
	return a.credential.TargetName
}

func (a *winHelloListEntryAdapter) TargetName() string {
	return a.targetName
}

func (s *winHelloWinCredStore) Read(key string) ([]byte, error) {
	cred, err := winHelloGetGenericCredentialFunc(s.credentialName(key))
	if err != nil {
		if errors.Is(err, elementNotFoundError) {
			return nil, ErrKeyNotFound
		}

		return nil, err
	}

	return bytes.Clone(cred.Blob()), nil
}

func (s *winHelloWinCredStore) Write(key string, data []byte) error {
	cred := winHelloNewGenericCredentialFunc(s.credentialName(key))
	cred.SetBlob(bytes.Clone(data))
	return cred.Write()
}

func (s *winHelloWinCredStore) Delete(key string) error {
	cred, err := winHelloGetGenericCredentialFunc(s.credentialName(key))
	if err != nil {
		if errors.Is(err, elementNotFoundError) {
			return ErrKeyNotFound
		}

		return err
	}

	// Prevent raw error from Delete() from leaking out of the store in case of a race condition where the credential is deleted between our Get and Delete calls
	if err := cred.Delete(); err != nil {
		if errors.Is(err, elementNotFoundError) {
			return ErrKeyNotFound
		}

		return err
	}

	return nil
}

func (s *winHelloWinCredStore) Keys() ([]string, error) {
	creds, err := winHelloListCredentialsFunc()
	if err != nil {
		return nil, err
	}

	prefix := s.credentialName("")
	results := make([]string, 0, len(creds))
	for _, cred := range creds {
		if strings.HasPrefix(cred.TargetName(), prefix) {
			results = append(results, strings.TrimPrefix(cred.TargetName(), prefix))
		}
	}
	sort.Strings(results)

	return results, nil
}

func (s *winHelloWinCredStore) credentialName(key string) string {
	return winHelloWinCredPrefix + ":" + s.serviceName + ":" + key
}
