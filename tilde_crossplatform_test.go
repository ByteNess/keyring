package keyring

import (
	"runtime"
	"strings"
	"testing"
)

func TestExpandTildeForwardSlash(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	actual, err := ExpandTilde("~/one/two")
	if err != nil {
		t.Fatal(err)
	}
	// strings.Replace preserves the caller's separator; Windows path APIs accept
	// forward slashes, so we compare against the same substitution the function does.
	expected := strings.Replace("~/one/two", "~", home, 1)
	if actual != expected {
		t.Fatalf("got %s, want %s", actual, expected)
	}
}

// TestExpandTildeBackslash verifies that ~\path expands on Windows, where
// backslash is a path separator. The test is skipped on other platforms where
// backslash is a valid filename character, not a separator.
func TestExpandTildeBackslash(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("backslash path separator only meaningful on Windows")
	}

	home := t.TempDir()
	t.Setenv("USERPROFILE", home)

	actual, err := ExpandTilde(`~\one\two`)
	if err != nil {
		t.Fatal(err)
	}
	expected := strings.Replace(`~\one\two`, "~", home, 1)
	if actual != expected {
		t.Fatalf("got %s, want %s", actual, expected)
	}
}

func TestExpandTildeNoExpansion(t *testing.T) {
	cases := []string{"~one/two", "one/two~", "one/two", "~"}
	if runtime.GOOS != "windows" {
		// On non-Windows platforms backslash is a valid filename character,
		// not a path separator, so ~\foo must not be expanded.
		cases = append(cases, `~\one\two`)
	}
	for _, c := range cases {
		actual, err := ExpandTilde(c)
		if err != nil {
			t.Fatal(err)
		}
		if actual != c {
			t.Fatalf("input %q: got %q, want no expansion", c, actual)
		}
	}
}
