//go:build !keyring_noprotonpass

package keyring

import (
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
