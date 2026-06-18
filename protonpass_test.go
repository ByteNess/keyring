//go:build !keyring_noprotonpass

package keyring

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/byteness/keyring/internal/protonpass"
)

// mockProtonAPI is an injectable protonpass.API for backend tests.
type mockProtonAPI struct {
	auth      func(ctx context.Context, pat string) (*protonpass.Session, error)
	shares    func(ctx context.Context, s *protonpass.Session) ([]protonpass.Share, error)
	items     func(ctx context.Context, s *protonpass.Session, shareID string) ([]protonpass.ItemRevision, error)
	shareKeys func(ctx context.Context, s *protonpass.Session, shareID string) ([]protonpass.ShareKey, error)
}

func (m mockProtonAPI) Authenticate(ctx context.Context, pat string) (*protonpass.Session, error) {
	return m.auth(ctx, pat)
}

func (m mockProtonAPI) ListShares(ctx context.Context, s *protonpass.Session) ([]protonpass.Share, error) {
	return m.shares(ctx, s)
}

func (m mockProtonAPI) ListItems(ctx context.Context, s *protonpass.Session, shareID string) ([]protonpass.ItemRevision, error) {
	return m.items(ctx, s, shareID)
}

func (m mockProtonAPI) GetShareKeys(ctx context.Context, s *protonpass.Session, shareID string) ([]protonpass.ShareKey, error) {
	if m.shareKeys != nil {
		return m.shareKeys(ctx, s, shareID)
	}
	return nil, nil
}

func TestNewProtonPassKeyring(t *testing.T) {
	t.Setenv(ProtonPassEnvShareID, "")

	if _, err := NewProtonPassKeyring(&Config{}); !errors.Is(err, ErrProtonPassNoShareID) {
		t.Fatalf("missing share id: got %v, want ErrProtonPassNoShareID", err)
	}

	k, err := NewProtonPassKeyring(&Config{ProtonPassShareID: "share1"})
	if err != nil {
		t.Fatalf("NewProtonPassKeyring: %v", err)
	}
	if k.ShareID != "share1" {
		t.Errorf("ShareID = %q, want share1", k.ShareID)
	}
	if k.ItemTitlePrefix != ProtonPassDefaultItemTitlePrefix {
		t.Errorf("ItemTitlePrefix = %q, want default %q", k.ItemTitlePrefix, ProtonPassDefaultItemTitlePrefix)
	}

	// Share ID falls back to the environment.
	t.Setenv(ProtonPassEnvShareID, "envshare")
	envK, err := NewProtonPassKeyring(&Config{})
	if err != nil {
		t.Fatalf("NewProtonPassKeyring (env): %v", err)
	}
	if envK.ShareID != "envshare" {
		t.Errorf("ShareID from env = %q, want envshare", envK.ShareID)
	}
}

func TestProtonPassRegistered(t *testing.T) {
	if !slices.Contains(AvailableBackends(), ProtonPassBackend) {
		t.Fatal("proton-pass backend not registered in AvailableBackends()")
	}
}

func TestOpenProtonPass(t *testing.T) {
	t.Setenv(ProtonPassEnvShareID, "")

	// Good config: the opener builds a *ProtonPassKeyring.
	kr, err := Open(Config{
		AllowedBackends:   []BackendType{ProtonPassBackend},
		ProtonPassShareID: "share1",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, ok := kr.(*ProtonPassKeyring); !ok {
		t.Fatalf("Open returned %T, want *ProtonPassKeyring", kr)
	}

	// Missing required config: the opener errors, so Open finds no usable backend.
	if _, err := Open(Config{AllowedBackends: []BackendType{ProtonPassBackend}}); !errors.Is(err, ErrNoAvailImpl) {
		t.Fatalf("Open with bad config: got %v, want ErrNoAvailImpl", err)
	}
}

func TestProtonPassResolvePAT(t *testing.T) {
	t.Run("config wins over env", func(t *testing.T) {
		t.Setenv(ProtonPassEnvPAT, "pst_env::k")
		got, err := ProtonPassKeyring{pat: "pst_cfg::k"}.resolvePAT()
		if err != nil || got != "pst_cfg::k" {
			t.Fatalf("resolvePAT = %q, %v; want config value", got, err)
		}
	})
	t.Run("env fallback", func(t *testing.T) {
		t.Setenv(ProtonPassEnvPAT, "pst_env::k")
		got, err := ProtonPassKeyring{}.resolvePAT()
		if err != nil || got != "pst_env::k" {
			t.Fatalf("resolvePAT = %q, %v; want env value", got, err)
		}
	})
	t.Run("prompt fallback", func(t *testing.T) {
		t.Setenv(ProtonPassEnvPAT, "")
		k := ProtonPassKeyring{tokenFunc: func(string) (string, error) { return "pst_prompt::k", nil }}
		got, err := k.resolvePAT()
		if err != nil || got != "pst_prompt::k" {
			t.Fatalf("resolvePAT = %q, %v; want prompt value", got, err)
		}
	})
}

func TestProtonPassWriteNotImplemented(t *testing.T) {
	k := ProtonPassKeyring{ShareID: "target"}
	if err := k.Set(Item{Key: "k"}); !errors.Is(err, ErrProtonPassNotImplemented) {
		t.Errorf("Set err = %v, want ErrProtonPassNotImplemented", err)
	}
	if err := k.Remove("k"); !errors.Is(err, ErrProtonPassNotImplemented) {
		t.Errorf("Remove err = %v, want ErrProtonPassNotImplemented", err)
	}
}

// vaultFixture is a fully-encrypted Proton Pass vault (one share-key rotation and a
// set of items) so backend tests exercise the real symmetric decryption chain:
// PAT enc-key -> share key -> item key -> content -> protobuf.
type vaultFixture struct {
	pat       string
	shareKeys []protonpass.ShareKey
	revisions []protonpass.ItemRevision
}

// encodeItemProto encodes Item{ metadata=1: Metadata{ name=1, note=2 } } the way a
// real Proton Pass item is laid out (field numbers from item-v1.proto).
func encodeItemProto(name, note string) []byte {
	var meta []byte
	meta = protowire.AppendTag(meta, 1, protowire.BytesType)
	meta = protowire.AppendBytes(meta, []byte(name))
	meta = protowire.AppendTag(meta, 2, protowire.BytesType)
	meta = protowire.AppendBytes(meta, []byte(note))

	var item []byte
	item = protowire.AppendTag(item, 1, protowire.BytesType)
	item = protowire.AppendBytes(item, meta)
	return item
}

// buildVaultFixture builds the encrypted vault for the given titled notes. The PAT
// "::<key>" half decodes to the AES enc-key that wraps the share key.
func buildVaultFixture(t *testing.T, titledNotes map[string]string) vaultFixture {
	t.Helper()
	encKey := bytes.Repeat([]byte{0xa7}, 32)
	pat := "pst_token::" + base64.RawURLEncoding.EncodeToString(encKey)
	shareKeyRaw := bytes.Repeat([]byte{0x5a}, 32)

	var nonceCounter byte
	seal := func(key, plain []byte, tag string) string {
		nonceCounter++
		nonce := make([]byte, 12)
		nonce[0] = nonceCounter
		blob, err := protonpass.EncryptAESGCM(key, plain, nonce, tag)
		if err != nil {
			t.Fatalf("seal %q: %v", tag, err)
		}
		return base64.StdEncoding.EncodeToString(blob)
	}

	fx := vaultFixture{
		pat:       pat,
		shareKeys: []protonpass.ShareKey{{KeyRotation: 1, Key: seal(encKey, shareKeyRaw, protonpass.TagShareKey)}},
	}

	id := 0
	for title, note := range titledNotes {
		id++
		itemKeyRaw := bytes.Repeat([]byte{byte(0x30 + id)}, 32)
		fx.revisions = append(fx.revisions, protonpass.ItemRevision{
			ItemID:               "item" + title,
			Revision:             1,
			KeyRotation:          1,
			ContentFormatVersion: 6,
			ItemKey:              seal(shareKeyRaw, itemKeyRaw, protonpass.TagItemKey),
			Content:              seal(itemKeyRaw, encodeItemProto(title, note), protonpass.TagItemContent),
		})
	}
	return fx
}

// newFixtureKeyring wires a fixture into a keyring with the given prefix, recording
// the API call order into calls.
func newFixtureKeyring(fx vaultFixture, prefix string, calls *[]string) ProtonPassKeyring {
	record := func(name string) { *calls = append(*calls, name) }
	return ProtonPassKeyring{
		Client: mockProtonAPI{
			auth: func(_ context.Context, _ string) (*protonpass.Session, error) {
				record("auth")
				return &protonpass.Session{UID: "u", AccessToken: "a"}, nil
			},
			shares: func(_ context.Context, _ *protonpass.Session) ([]protonpass.Share, error) {
				record("shares")
				return []protonpass.Share{{ShareID: "target"}}, nil
			},
			shareKeys: func(_ context.Context, _ *protonpass.Session, _ string) ([]protonpass.ShareKey, error) {
				record("shareKeys")
				return fx.shareKeys, nil
			},
			items: func(_ context.Context, _ *protonpass.Session, shareID string) ([]protonpass.ItemRevision, error) {
				record("items")
				if shareID != "target" {
					return nil, errors.New("unexpected share id")
				}
				return fx.revisions, nil
			},
		},
		ShareID:         "target",
		ItemTitlePrefix: prefix,
		pat:             fx.pat,
	}
}

func TestProtonPassKeyringReadPath(t *testing.T) {
	fx := buildVaultFixture(t, map[string]string{
		"aws-vault/dev":  `{"AccessKeyID":"AKIADEV"}`,
		"aws-vault/prod": `{"AccessKeyID":"AKIAPROD"}`,
		"someone-else":   "not an aws-vault item", // wrong prefix -> filtered out
	})
	var calls []string
	k := newFixtureKeyring(fx, ProtonPassDefaultItemTitlePrefix, &calls)

	keys, err := k.Keys()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if want := []string{"dev", "prod"}; !slices.Equal(keys, want) {
		t.Fatalf("Keys = %v, want %v (sorted, prefix-stripped, foreign items dropped)", keys, want)
	}
	wantOrder := []string{"auth", "shares", "shareKeys", "items"}
	if !slices.Equal(calls, wantOrder) {
		t.Fatalf("call order = %v, want %v", calls, wantOrder)
	}

	got, err := k.Get("prod")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got.Data) != `{"AccessKeyID":"AKIAPROD"}` || got.Key != "prod" {
		t.Fatalf("Get(prod) = %+v", got)
	}

	if _, err := k.Get("missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get(missing) err = %v, want ErrKeyNotFound", err)
	}
}

func TestProtonPassKeyringReadPathNoPrefix(t *testing.T) {
	// With an empty prefix every item title is a key verbatim.
	fx := buildVaultFixture(t, map[string]string{"raw-title": "blob"})
	var calls []string
	k := newFixtureKeyring(fx, "", &calls)

	keys, err := k.Keys()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if !slices.Equal(keys, []string{"raw-title"}) {
		t.Fatalf("Keys = %v, want [raw-title]", keys)
	}
	got, err := k.Get("raw-title")
	if err != nil || string(got.Data) != "blob" {
		t.Fatalf("Get(raw-title) = %+v, %v", got, err)
	}
}

func TestProtonPassOpenContent(t *testing.T) {
	shareKey := bytes.Repeat([]byte{0x5a}, 32)
	proto := encodeItemProto("title", "blob")
	seal := func(key, plain []byte, tag string, n byte) string {
		nonce := make([]byte, 12)
		nonce[0] = n
		b, err := protonpass.EncryptAESGCM(key, plain, nonce, tag)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	k := ProtonPassKeyring{}

	// Newer item: a per-item key wraps the content.
	itemKey := bytes.Repeat([]byte{0x31}, 32)
	withKey := protonpass.ItemRevision{
		ItemKey: seal(shareKey, itemKey, protonpass.TagItemKey, 1),
		Content: seal(itemKey, proto, protonpass.TagItemContent, 2),
	}
	got, err := k.openContent(shareKey, withKey)
	if err != nil {
		t.Fatalf("with item key: %v", err)
	}
	if meta, _ := protonpass.ParseItemMetadata(got); meta.Name != "title" || meta.Note != "blob" {
		t.Fatalf("with item key: %+v", meta)
	}

	// Older item: no ItemKey, content opened with the share key directly.
	noKey := protonpass.ItemRevision{Content: seal(shareKey, proto, protonpass.TagItemContent, 3)}
	gotOld, err := k.openContent(shareKey, noKey)
	if err != nil {
		t.Fatalf("no item key: %v", err)
	}
	if meta, _ := protonpass.ParseItemMetadata(gotOld); meta.Name != "title" {
		t.Fatalf("no item key: %+v", meta)
	}
}

func TestProtonPassItemTitleRoundTrip(t *testing.T) {
	k := ProtonPassKeyring{ItemTitlePrefix: "aws-vault"}
	if got := k.itemTitle("dev"); got != "aws-vault/dev" {
		t.Errorf("itemTitle = %q", got)
	}
	if key, ok := k.keyFromTitle("aws-vault/dev"); !ok || key != "dev" {
		t.Errorf("keyFromTitle = %q, %v", key, ok)
	}
	if _, ok := k.keyFromTitle("other/dev"); ok {
		t.Error("keyFromTitle must reject a foreign prefix")
	}
}

func TestProtonPassKeyringShareNotAccessible(t *testing.T) {
	k := ProtonPassKeyring{
		Client: mockProtonAPI{
			auth: func(_ context.Context, _ string) (*protonpass.Session, error) {
				return &protonpass.Session{UID: "u"}, nil
			},
			shares: func(_ context.Context, _ *protonpass.Session) ([]protonpass.Share, error) {
				return []protonpass.Share{{ShareID: "someone-elses-vault"}}, nil
			},
			items: func(_ context.Context, _ *protonpass.Session, _ string) ([]protonpass.ItemRevision, error) {
				t.Error("ListItems must not be called when the share is inaccessible")
				return nil, nil
			},
		},
		ShareID: "target",
		pat:     "pst_x::AAAA",
	}

	if _, err := k.Keys(); !errors.Is(err, ErrProtonPassShareNotAccessible) {
		t.Fatalf("Keys err = %v, want ErrProtonPassShareNotAccessible", err)
	}
}

func TestProtonPassKeyringNoPAT(t *testing.T) {
	t.Setenv(ProtonPassEnvPAT, "")
	k := ProtonPassKeyring{
		Client:  mockProtonAPI{auth: func(_ context.Context, _ string) (*protonpass.Session, error) { return nil, nil }},
		ShareID: "target",
	}
	if _, err := k.Keys(); !errors.Is(err, ErrProtonPassNoPAT) {
		t.Fatalf("Keys err = %v, want ErrProtonPassNoPAT", err)
	}
}

func TestProtonPassKeyringGetMetadata(t *testing.T) {
	k := ProtonPassKeyring{ShareID: "target"}
	if _, err := k.GetMetadata("x"); !errors.Is(err, ErrMetadataNeedsCredentials) {
		t.Fatalf("GetMetadata err = %v, want ErrMetadataNeedsCredentials", err)
	}
}
