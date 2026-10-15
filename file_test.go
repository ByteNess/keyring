//go:build !keyring_nofile

package keyring

import (
	"os"
	"testing"

	"github.com/byteness/percent"
)

func TestFileKeyringSetWhenEmpty(t *testing.T) {
	k := &fileKeyring{
		dir:          os.TempDir(),
		passwordFunc: FixedStringPrompt("no more secrets"),
	}
	item := Item{Key: "llamas", Data: []byte("llamas are great")}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	foundItem, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(foundItem.Data) != "llamas are great" {
		t.Fatalf("Value stored was not the value retrieved: %q", foundItem.Data)
	}

	if foundItem.Key != "llamas" {
		t.Fatalf("Key wasn't persisted: %q", foundItem.Key)
	}
}

func TestFileKeyringGetWithSlashes(t *testing.T) {
	k := &fileKeyring{
		dir:          os.TempDir(),
		passwordFunc: FixedStringPrompt("no more secrets"),
	}

	item := Item{Key: "https://aws-sso-portal.awsapps.com/start", Data: []byte("https://aws-sso-portal.awsapps.com/start")}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	if err := k.Remove(item.Key); err != nil {
		t.Fatal(err)
	}
}

func TestFilenameWithBadChars(t *testing.T) {
	a := `abc/.././123`
	e := filenameEscape(a)
	if e != `abc%2F..%2F.%2F123` {
		t.Fatalf("Unexpected result from filenameEscape: %s", e)
	}

	b := filenameUnescape(e)
	if b != a {
		t.Fatal("Unexpected filenameEscape")
	}
}

func TestFilenameEscapeOnWindows(t *testing.T) {
	for key, want := range map[string]string{
		"oidc:https://example.awsapps.com/start": "oidc%3Ahttps%3A%2F%2Fexample.awsapps.com%2Fstart",
		`a<b>c"d|e?f*g\h`:                        "a%3Cb%3Ec%22d%7Ce%3Ff%2Ag%5Ch",
		"tab\there":                              "tab%09here",
	} {
		got := percent.Encode(key, filenameUnsafeChars("windows"))
		if got != want {
			t.Errorf("escape(%q) = %q, want %q", key, got, want)
		}
		if back := filenameUnescape(got); back != key {
			t.Errorf("unescape(%q) = %q, want %q", got, back, key)
		}
	}
}

// File names written before on other platforms must not change.
func TestFilenameEscapeElsewhereUnchanged(t *testing.T) {
	got := percent.Encode("oidc:https://example.awsapps.com/start", filenameUnsafeChars("linux"))
	if want := "oidc:https:%2F%2Fexample.awsapps.com%2Fstart"; got != want {
		t.Errorf("escape = %q, want %q", got, want)
	}
}

func TestFileKeyringKeysWithWindowsReservedChars(t *testing.T) {
	k := &fileKeyring{
		dir:          t.TempDir(),
		passwordFunc: FixedStringPrompt("no more secrets"),
	}

	for _, key := range []string{"oidc:https://example.awsapps.com/start", `a<b>c"d|e?f*g\h`} {
		if err := k.Set(Item{Key: key, Data: []byte("data")}); err != nil {
			t.Fatalf("Set(%q): %v", key, err)
		}
		item, err := k.Get(key)
		if err != nil || string(item.Data) != "data" {
			t.Fatalf("Get(%q) = %q, %v", key, item.Data, err)
		}
		keys, err := k.Keys()
		if err != nil || len(keys) != 1 || keys[0] != key {
			t.Fatalf("Keys() = %q, %v, want [%q]", keys, err, key)
		}
		if err := k.Remove(key); err != nil {
			t.Fatalf("Remove(%q): %v", key, err)
		}
	}
}
