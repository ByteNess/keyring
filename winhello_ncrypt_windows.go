//go:build windows
// +build windows

package keyring

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	// Docs: https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/
	winHelloNCryptDLL = syscall.NewLazyDLL("ncrypt.dll")

	procWinHelloNCryptOpenStorageProvider = winHelloNCryptDLL.NewProc("NCryptOpenStorageProvider")
	procWinHelloNCryptOpenKey             = winHelloNCryptDLL.NewProc("NCryptOpenKey")
	procWinHelloNCryptCreatePersistedKey  = winHelloNCryptDLL.NewProc("NCryptCreatePersistedKey")
	procWinHelloNCryptSetProperty         = winHelloNCryptDLL.NewProc("NCryptSetProperty")
	procWinHelloNCryptFinalizeKey         = winHelloNCryptDLL.NewProc("NCryptFinalizeKey")
	procWinHelloNCryptEncrypt             = winHelloNCryptDLL.NewProc("NCryptEncrypt")
	procWinHelloNCryptDecrypt             = winHelloNCryptDLL.NewProc("NCryptDecrypt")
	procWinHelloNCryptDeleteKey           = winHelloNCryptDLL.NewProc("NCryptDeleteKey")
	procWinHelloNCryptFreeObject          = winHelloNCryptDLL.NewProc("NCryptFreeObject")
)

func winHelloNCryptOpenStorageProvider(providerName string) (ncryptHandle, error) {
	providerNameUTF16, err := syscall.UTF16PtrFromString(providerName)
	if err != nil {
		return 0, fmt.Errorf("encode provider name: %w", err)
	}

	var provider ncryptHandle
	if err := winHelloNCryptCall(
		procWinHelloNCryptOpenStorageProvider,
		uintptr(unsafe.Pointer(&provider)),
		uintptr(unsafe.Pointer(providerNameUTF16)),
		0,
	); err != nil {
		return 0, err
	}

	return provider, nil
}

func winHelloNCryptOpenKey(provider ncryptHandle, keyName string, legacyKeySpec uint32, flags uint32) (ncryptHandle, error) {
	keyNameUTF16, err := syscall.UTF16PtrFromString(keyName)
	if err != nil {
		return 0, fmt.Errorf("encode key name: %w", err)
	}

	var key ncryptHandle
	if err := winHelloNCryptCall(
		procWinHelloNCryptOpenKey,
		uintptr(provider),
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(keyNameUTF16)),
		uintptr(legacyKeySpec),
		uintptr(flags),
	); err != nil {
		return 0, err
	}

	return key, nil
}

func winHelloNCryptCreatePersistedKey(provider ncryptHandle, algorithm string, keyName string, legacyKeySpec uint32, flags uint32) (ncryptHandle, error) {
	algorithmUTF16, err := syscall.UTF16PtrFromString(algorithm)
	if err != nil {
		return 0, fmt.Errorf("encode algorithm %q: %w", algorithm, err)
	}
	keyNameUTF16, err := syscall.UTF16PtrFromString(keyName)
	if err != nil {
		return 0, fmt.Errorf("encode key name: %w", err)
	}

	var key ncryptHandle
	if err := winHelloNCryptCall(
		procWinHelloNCryptCreatePersistedKey,
		uintptr(provider),
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(algorithmUTF16)),
		uintptr(unsafe.Pointer(keyNameUTF16)),
		uintptr(legacyKeySpec),
		uintptr(flags),
	); err != nil {
		return 0, err
	}

	return key, nil
}

func winHelloNCryptSetProperty(handle ncryptHandle, property string, value []byte, flags uint32) error {
	propertyUTF16, err := syscall.UTF16PtrFromString(property)
	if err != nil {
		return fmt.Errorf("encode property %q: %w", property, err)
	}

	var valuePtr uintptr
	if len(value) > 0 {
		valuePtr = uintptr(unsafe.Pointer(&value[0]))
	}

	if err := winHelloNCryptCall(
		procWinHelloNCryptSetProperty,
		uintptr(handle),
		uintptr(unsafe.Pointer(propertyUTF16)),
		valuePtr,
		uintptr(uint32(len(value))),
		uintptr(flags),
	); err != nil {
		return fmt.Errorf("set property %q: %w", property, err)
	}

	return nil
}

func winHelloNCryptSetUint32Property(handle ncryptHandle, property string, value uint32, flags uint32) error {
	valueBytes := unsafe.Slice((*byte)(unsafe.Pointer(&value)), int(unsafe.Sizeof(value)))
	return winHelloNCryptSetProperty(handle, property, valueBytes, flags)
}

func winHelloNCryptFinalizeKey(key ncryptHandle, flags uint32) error {
	return winHelloNCryptCall(procWinHelloNCryptFinalizeKey, uintptr(key), uintptr(flags))
}

func winHelloNCryptEncrypt(key ncryptHandle, plaintext []byte, paddingInfo unsafe.Pointer, flags uint32) ([]byte, error) {
	return winHelloNCryptCrypt(procWinHelloNCryptEncrypt, key, plaintext, paddingInfo, flags)
}

func winHelloNCryptDecrypt(key ncryptHandle, ciphertext []byte, paddingInfo unsafe.Pointer, flags uint32) ([]byte, error) {
	return winHelloNCryptCrypt(procWinHelloNCryptDecrypt, key, ciphertext, paddingInfo, flags)
}

func winHelloNCryptDeleteKey(key ncryptHandle, flags uint32) error {
	return winHelloNCryptCall(procWinHelloNCryptDeleteKey, uintptr(key), uintptr(flags))
}

func winHelloNCryptFreeObject(handle ncryptHandle) error {
	if handle == 0 {
		return nil
	}

	return winHelloNCryptCall(procWinHelloNCryptFreeObject, uintptr(handle))
}

func winHelloNCryptCall(proc *syscall.LazyProc, args ...uintptr) error {
	status, _, _ := proc.Call(args...)
	return winHelloNCryptError(status)
}

func winHelloNCryptCrypt(proc *syscall.LazyProc, key ncryptHandle, input []byte, paddingInfo unsafe.Pointer, flags uint32) ([]byte, error) {
	var outputLen uint32
	if err := winHelloNCryptCall(
		proc,
		uintptr(key),
		uintptr(unsafe.Pointer(winHelloSlicePtr(input))),
		uintptr(uint32(len(input))),
		uintptr(paddingInfo),
		0,
		0,
		uintptr(unsafe.Pointer(&outputLen)),
		uintptr(flags),
	); err != nil {
		return nil, err
	}

	output := make([]byte, outputLen)
	if err := winHelloNCryptCall(
		proc,
		uintptr(key),
		uintptr(unsafe.Pointer(winHelloSlicePtr(input))),
		uintptr(uint32(len(input))),
		uintptr(paddingInfo),
		uintptr(unsafe.Pointer(winHelloSlicePtr(output))),
		uintptr(uint32(len(output))),
		uintptr(unsafe.Pointer(&outputLen)),
		uintptr(flags),
	); err != nil {
		return nil, err
	}

	return output[:outputLen], nil
}

func winHelloSlicePtr(data []byte) *byte {
	if len(data) == 0 {
		return nil
	}

	return &data[0]
}
