//go:build !keyring_noprotonpass

package keyring

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/byteness/keyring/internal/protonpass"
)

// TestProtonPassIntegration exercises the full read path against the real Proton
// Pass API. It is opt-in (like the 1Password live tests): it only runs when
// PROTON_PASS_INTEGRATION=1, and needs a PAT granted access to one known item.
//
// Setup (personal account, read-only):
//
//	pass-cli personal-access-token access grant --role viewer --item-title "<title>" ...
//	export PROTON_PASS_INTEGRATION=1
//	export PROTON_PASS_PERSONAL_ACCESS_TOKEN='pst_...::...'
//	export PROTON_PASS_SHARE_ID='<recipient share id>'
//	export PROTON_PASS_TEST_ITEM_TITLE='<title>'
//	export PROTON_PASS_TEST_ITEM_NOTE='<expected note>'   # optional
//	go test -run TestProtonPassIntegration -v ./...
//	# afterwards: pass-cli personal-access-token access revoke ...
func TestProtonPassIntegration(t *testing.T) {
	if os.Getenv("PROTON_PASS_INTEGRATION") != "1" {
		t.Skip("set PROTON_PASS_INTEGRATION=1 (plus PAT + share id) to run the live read-path test")
	}
	pat := os.Getenv(ProtonPassEnvPAT)
	shareID := os.Getenv(ProtonPassEnvShareID)
	wantTitle := os.Getenv("PROTON_PASS_TEST_ITEM_TITLE")
	if pat == "" || shareID == "" || wantTitle == "" {
		t.Fatalf("need %s, %s, and PROTON_PASS_TEST_ITEM_TITLE set", ProtonPassEnvPAT, ProtonPassEnvShareID)
	}

	// Empty prefix: every item title is a key verbatim, so an arbitrary granted
	// item (not created by aws-vault) round-trips.
	k := ProtonPassKeyring{
		Client:          protonpass.New(os.Getenv(ProtonPassEnvAPIBase)),
		ShareID:         shareID,
		ItemTitlePrefix: "",
		pat:             pat,
	}

	keys, err := k.Keys()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	t.Logf("decrypted %d item title(s)", len(keys))
	if !slices.Contains(keys, wantTitle) {
		t.Fatalf("Keys did not include the granted item title %q; got %v", wantTitle, keys)
	}

	item, err := k.Get(wantTitle)
	if err != nil {
		t.Fatalf("Get(%q): %v", wantTitle, err)
	}
	if want := os.Getenv("PROTON_PASS_TEST_ITEM_NOTE"); want != "" && string(item.Data) != want {
		t.Fatalf("Get(%q) note = %q, want %q", wantTitle, item.Data, want)
	}

	if _, err := k.Get("definitely-not-a-real-title-zzz"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get(missing) err = %v, want ErrKeyNotFound", err)
	}
}

// TestProtonPassIntegrationWrite round-trips the write path against the real Proton
// Pass API: create -> Keys -> Get -> update -> Remove. It is the generalized P0.5
// roundtrip_smoke.
//
// DANGER: this CREATES and DELETES items in the configured vault. Run it ONLY
// against a disposable test account / vault, never a personal one. It is doubly
// gated: PROTON_PASS_INTEGRATION_WRITE=1 plus a writable PAT. The item key is
// uniquely randomized and the test removes it (including via t.Cleanup on failure),
// but a misconfigured share id could still touch real data — point it at a throwaway.
//
//	pass-cli personal-access-token access grant --role editor --vault-name "<throwaway>" ...
//	export PROTON_PASS_INTEGRATION_WRITE=1
//	export PROTON_PASS_PERSONAL_ACCESS_TOKEN='pst_...::...'
//	export PROTON_PASS_SHARE_ID='<writable share id>'
//	go test -run TestProtonPassIntegrationWrite -v ./...
func TestProtonPassIntegrationWrite(t *testing.T) {
	if os.Getenv("PROTON_PASS_INTEGRATION_WRITE") != "1" {
		t.Skip("set PROTON_PASS_INTEGRATION_WRITE=1 (disposable account only) to run the live write round-trip")
	}
	pat := os.Getenv(ProtonPassEnvPAT)
	shareID := os.Getenv(ProtonPassEnvShareID)
	if pat == "" || shareID == "" {
		t.Fatalf("need %s and %s set", ProtonPassEnvPAT, ProtonPassEnvShareID)
	}

	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	key := "it-write-" + hex.EncodeToString(buf)

	k := ProtonPassKeyring{
		Client:          protonpass.New(os.Getenv(ProtonPassEnvAPIBase)),
		ShareID:         shareID,
		ItemTitlePrefix: ProtonPassDefaultItemTitlePrefix,
		pat:             pat,
	}

	// Best-effort cleanup even if an assertion fails mid-test.
	t.Cleanup(func() {
		if err := k.Remove(key); err != nil && !errors.Is(err, ErrKeyNotFound) {
			t.Logf("cleanup Remove(%q): %v", key, err)
		}
	})

	const blob = `{"AccessKeyID":"AKIAINTEGRATION","SecretAccessKey":"s3cr3t"}`
	if err := k.Set(Item{Key: key, Data: []byte(blob)}); err != nil {
		t.Fatalf("Set(create): %v", err)
	}

	keys, err := k.Keys()
	if err != nil {
		t.Fatalf("Keys after create: %v", err)
	}
	if !slices.Contains(keys, key) {
		t.Fatalf("Keys did not include the created key %q; got %v", key, keys)
	}

	got, err := k.Get(key)
	if err != nil {
		t.Fatalf("Get after create: %v", err)
	}
	if string(got.Data) != blob {
		t.Fatalf("Get(%q) = %q, want %q", key, got.Data, blob)
	}

	// Update in place via a second Set, then confirm the new value.
	const updated = `{"AccessKeyID":"AKIAUPDATED","SecretAccessKey":"n3w"}`
	if err := k.Set(Item{Key: key, Data: []byte(updated)}); err != nil {
		t.Fatalf("Set(update): %v", err)
	}
	got, err = k.Get(key)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if string(got.Data) != updated {
		t.Fatalf("Get(%q) after update = %q, want %q", key, got.Data, updated)
	}

	if err := k.Remove(key); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := k.Get(key); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get after Remove err = %v, want ErrKeyNotFound", err)
	}
}

// TestProtonPassIntegrationUpdateRemove confirms the update + delete path against an
// EXISTING item. It exists for accounts/PATs where whole-vault grants (needed to
// create) are not permitted but a per-item editor grant is, so the create-based
// round-trip above cannot run.
//
// DANGER: it OVERWRITES then PERMANENTLY DELETES the named item — point it ONLY at a
// throwaway item. Gated by PROTON_PASS_INTEGRATION_WRITE=1.
//
//	export PROTON_PASS_INTEGRATION_WRITE=1
//	export PROTON_PASS_PERSONAL_ACCESS_TOKEN='pst_...::...'
//	export PROTON_PASS_SHARE_ID='<recipient share id from a per-item editor grant>'
//	export PROTON_PASS_TEST_ITEM_TITLE='<throwaway item title>'
//	go test -run TestProtonPassIntegrationUpdateRemove -v ./...
func TestProtonPassIntegrationUpdateRemove(t *testing.T) {
	if os.Getenv("PROTON_PASS_INTEGRATION_WRITE") != "1" {
		t.Skip("set PROTON_PASS_INTEGRATION_WRITE=1 (throwaway item only) to run the live update/delete test")
	}
	pat := os.Getenv(ProtonPassEnvPAT)
	shareID := os.Getenv(ProtonPassEnvShareID)
	title := os.Getenv("PROTON_PASS_TEST_ITEM_TITLE")
	if pat == "" || shareID == "" || title == "" {
		t.Fatalf("need %s, %s, and PROTON_PASS_TEST_ITEM_TITLE set", ProtonPassEnvPAT, ProtonPassEnvShareID)
	}

	// Empty prefix: the item title is the key verbatim.
	k := ProtonPassKeyring{
		Client:          protonpass.New(os.Getenv(ProtonPassEnvAPIBase)),
		ShareID:         shareID,
		ItemTitlePrefix: "",
		pat:             pat,
	}

	// The target item must already exist and be readable (the per-item grant).
	if _, err := k.Get(title); err != nil {
		t.Fatalf("Get(%q) before update: %v (is the per-item editor grant in place?)", title, err)
	}

	// Update in place — exercises Set's update branch (reuses the existing item key).
	const updated = `{"phase3":"update-confirm"}`
	if err := k.Set(Item{Key: title, Data: []byte(updated)}); err != nil {
		t.Fatalf("Set(update) on %q: %v", title, err)
	}
	got, err := k.Get(title)
	if err != nil {
		t.Fatalf("Get(%q) after update: %v", title, err)
	}
	if string(got.Data) != updated {
		t.Fatalf("Get(%q) after update = %q, want %q", title, got.Data, updated)
	}

	// Permanent delete.
	if err := k.Remove(title); err != nil {
		t.Fatalf("Remove(%q): %v", title, err)
	}
	if _, err := k.Get(title); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get(%q) after Remove err = %v, want ErrKeyNotFound", title, err)
	}
}
