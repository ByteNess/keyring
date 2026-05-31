//go:build windows
// +build windows

package winhello

import "syscall"

var (
	winHelloUser32DLL = syscall.NewLazyDLL("user32.dll")
	winHelloKernelDLL = syscall.NewLazyDLL("kernel32.dll")

	procWinHelloGetForegroundWindow = winHelloUser32DLL.NewProc("GetForegroundWindow")
	procWinHelloIsWindowVisible     = winHelloUser32DLL.NewProc("IsWindowVisible")
	procWinHelloGetConsoleWindow    = winHelloKernelDLL.NewProc("GetConsoleWindow")

	winHelloParentHWNDFunc = winHelloParentHWND
)

// winHelloParentHWND chooses a best-effort parent for Windows Hello prompts.
// Prefer a visible console window for CLI callers, then fall back to the
// current foreground window. Returning 0 leaves prompt ownership to NCrypt.
func winHelloParentHWND() uintptr {
	if hwnd := visibleConsoleWindow(); hwnd != 0 {
		return hwnd
	}

	return foregroundWindow()
}

func visibleConsoleWindow() uintptr {
	hwnd, _, _ := procWinHelloGetConsoleWindow.Call()
	if hwnd == 0 || !winHelloIsWindowVisible(hwnd) {
		return 0
	}

	return hwnd
}

func foregroundWindow() uintptr {
	hwnd, _, _ := procWinHelloGetForegroundWindow.Call()
	return hwnd
}

func winHelloIsWindowVisible(hwnd uintptr) bool {
	visible, _, _ := procWinHelloIsWindowVisible.Call(hwnd)
	return visible != 0
}
