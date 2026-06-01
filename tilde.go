package keyring

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// tildePrefixes are the tilde+separator combinations that trigger home-dir expansion.
// On Windows both ~\ (native) and ~/ (common in config files) are accepted;
// on other platforms only ~/ (the native separator) is recognised.
var tildePrefixes = func() []string {
	native := string([]rune{'~', filepath.Separator})
	if runtime.GOOS == "windows" {
		return []string{native, "~/"}
	}
	return []string{native}
}()

// ExpandTilde will expand tilde (~/ and/or ~\ depending on OS) for the user home directory.
func ExpandTilde(dir string) (string, error) {
	for _, prefix := range tildePrefixes {
		if strings.HasPrefix(dir, prefix) {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			dir = strings.Replace(dir, "~", homeDir, 1)
			debugf("Expanded file dir to %s", dir)
			break
		}
	}
	return dir, nil
}
