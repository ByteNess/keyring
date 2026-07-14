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
	create    func(ctx context.Context, s *protonpass.Session, shareID string, req protonpass.CreateItemRequest) (*protonpass.ItemRevision, error)
	update    func(ctx context.Context, s *protonpass.Session, shareID, itemID string, req protonpass.UpdateItemRequest) (*protonpass.ItemRevision, error)
	del       func(ctx context.Context, s *protonpass.Session, shareID, itemID string, revision int) error
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

func (m mockProtonAPI) CreateItem(ctx context.Context, s *protonpass.Session, shareID string, req protonpass.CreateItemRequest) (*protonpass.ItemRevision, error) {
	if m.create != nil {
		return m.create(ctx, s, shareID, req)
	}
	return nil, errors.New("CreateItem not stubbed")
}

func (m mockProtonAPI) UpdateItem(ctx context.Context, s *protonpass.Session, shareID, itemID string, req protonpass.UpdateItemRequest) (*protonpass.ItemRevision, error) {
	if m.update != nil {
		return m.update(ctx, s, shareID, itemID, req)
	}
	return nil, errors.New("UpdateItem not stubbed")
}

func (m mockProtonAPI) DeleteItem(ctx context.Context, s *protonpass.Session, shareID, itemID string, revision int) error {
	if m.del != nil {
		return m.del(ctx, s, shareID, itemID, revision)
	}
	return errors.New("DeleteItem not stubbed")
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

// fixtureShareKey and fixtureItemKey mirror the constants buildVaultFixture seals
// with, so write tests can decrypt the captured request bodies.
func fixtureShareKey() []byte      { return bytes.Repeat([]byte{0x5a}, 32) }
func fixtureItemKey(id int) []byte { return bytes.Repeat([]byte{byte(0x30 + id)}, 32) }

// readMock returns a mock wired to serve the fixture's read path; write hooks are
// left nil for the test to set.
func readMock(fx vaultFixture) *mockProtonAPI {
	return &mockProtonAPI{
		auth: func(context.Context, string) (*protonpass.Session, error) {
			return &protonpass.Session{UID: "u", AccessToken: "a"}, nil
		},
		shares: func(context.Context, *protonpass.Session) ([]protonpass.Share, error) {
			return []protonpass.Share{{ShareID: "target", ContentKeyRotation: 1}}, nil
		},
		shareKeys: func(context.Context, *protonpass.Session, string) ([]protonpass.ShareKey, error) {
			return fx.shareKeys, nil
		},
		items: func(context.Context, *protonpass.Session, string) ([]protonpass.ItemRevision, error) {
			return fx.revisions, nil
		},
	}
}

func TestProtonPassSetCreate(t *testing.T) {
	fx := buildVaultFixture(t, nil) // empty vault: Set must create
	m := readMock(fx)
	var gotReq protonpass.CreateItemRequest
	var createCalls int
	m.create = func(_ context.Context, _ *protonpass.Session, shareID string, req protonpass.CreateItemRequest) (*protonpass.ItemRevision, error) {
		createCalls++
		if shareID != "target" {
			t.Errorf("create share id = %q, want target", shareID)
		}
		gotReq = req
		return &protonpass.ItemRevision{ItemID: "new", Revision: 1}, nil
	}
	m.update = func(context.Context, *protonpass.Session, string, string, protonpass.UpdateItemRequest) (*protonpass.ItemRevision, error) {
		t.Error("Set on a missing key must create, not update")
		return nil, nil
	}
	k := ProtonPassKeyring{Client: *m, ShareID: "target", ItemTitlePrefix: "aws-vault", pat: fx.pat}

	const blob = `{"AccessKeyID":"AKIA"}`
	if err := k.Set(Item{Key: "dev", Data: []byte(blob)}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if createCalls != 1 {
		t.Fatalf("create called %d times, want 1", createCalls)
	}
	if gotReq.KeyRotation != 1 {
		t.Errorf("create KeyRotation = %d, want 1 (current rotation)", gotReq.KeyRotation)
	}

	// The wrapped ItemKey unwraps with the share key; the content then decrypts to
	// the item-v1 protobuf carrying the prefixed title and the blob.
	itemKey, err := protonpass.OpenItemKey(fixtureShareKey(), gotReq.ItemKey)
	if err != nil {
		t.Fatalf("unwrap created ItemKey: %v", err)
	}
	plain, err := protonpass.OpenItemContent(itemKey, gotReq.Content)
	if err != nil {
		t.Fatalf("open created content: %v", err)
	}
	meta, err := protonpass.ParseItemMetadata(plain)
	if err != nil {
		t.Fatalf("parse created item: %v", err)
	}
	if meta.Name != "aws-vault/dev" || meta.Note != blob {
		t.Fatalf("created item = %+v, want name=aws-vault/dev note=%q", meta, blob)
	}
}

func TestProtonPassSetUpdate(t *testing.T) {
	fx := buildVaultFixture(t, map[string]string{"aws-vault/dev": "old-blob"})
	m := readMock(fx)
	var gotReq protonpass.UpdateItemRequest
	var gotItemID string
	var updateCalls int
	m.update = func(_ context.Context, _ *protonpass.Session, _ string, itemID string, req protonpass.UpdateItemRequest) (*protonpass.ItemRevision, error) {
		updateCalls++
		gotItemID, gotReq = itemID, req
		return &protonpass.ItemRevision{ItemID: itemID, Revision: req.LastRevision + 1}, nil
	}
	m.create = func(context.Context, *protonpass.Session, string, protonpass.CreateItemRequest) (*protonpass.ItemRevision, error) {
		t.Error("Set on an existing key must update, not create")
		return nil, nil
	}
	k := ProtonPassKeyring{Client: *m, ShareID: "target", ItemTitlePrefix: "aws-vault", pat: fx.pat}

	if err := k.Set(Item{Key: "dev", Data: []byte("new-blob")}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if updateCalls != 1 {
		t.Fatalf("update called %d times, want 1", updateCalls)
	}
	if gotItemID != "itemaws-vault/dev" {
		t.Errorf("update itemID = %q, want itemaws-vault/dev", gotItemID)
	}
	if gotReq.KeyRotation != 1 || gotReq.LastRevision != 1 {
		t.Errorf("update req = %+v, want KeyRotation=1 LastRevision=1", gotReq)
	}

	// Update re-encrypts under the existing per-item key (id 1), not a fresh one.
	plain, err := protonpass.OpenItemContent(fixtureItemKey(1), gotReq.Content)
	if err != nil {
		t.Fatalf("open updated content with existing item key: %v", err)
	}
	if meta, _ := protonpass.ParseItemMetadata(plain); meta.Note != "new-blob" {
		t.Fatalf("updated note = %q, want new-blob", meta.Note)
	}
}

func TestProtonPassRemove(t *testing.T) {
	fx := buildVaultFixture(t, map[string]string{"aws-vault/dev": "blob"})
	m := readMock(fx)
	var gotItemID string
	var gotRevision, delCalls int
	m.del = func(_ context.Context, _ *protonpass.Session, _ string, itemID string, revision int) error {
		delCalls++
		gotItemID, gotRevision = itemID, revision
		return nil
	}
	k := ProtonPassKeyring{Client: *m, ShareID: "target", ItemTitlePrefix: "aws-vault", pat: fx.pat}

	if err := k.Remove("dev"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if delCalls != 1 || gotItemID != "itemaws-vault/dev" || gotRevision != 1 {
		t.Fatalf("delete called %d times (itemID=%q rev=%d), want 1 (itemaws-vault/dev, 1)", delCalls, gotItemID, gotRevision)
	}

	// Removing an unknown key is ErrKeyNotFound and issues no delete.
	if err := k.Remove("missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Remove(missing) err = %v, want ErrKeyNotFound", err)
	}
	if delCalls != 1 {
		t.Fatalf("delete was called for a missing key (%d calls)", delCalls)
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
	got, gotKey, err := k.openContent(shareKey, withKey)
	if err != nil {
		t.Fatalf("with item key: %v", err)
	}
	if meta, _ := protonpass.ParseItemMetadata(got); meta.Name != "title" || meta.Note != "blob" {
		t.Fatalf("with item key: %+v", meta)
	}
	if !bytes.Equal(gotKey, itemKey) {
		t.Fatal("with item key: content key must be the per-item key")
	}

	// Older item: no ItemKey, content opened with the share key directly.
	noKey := protonpass.ItemRevision{Content: seal(shareKey, proto, protonpass.TagItemContent, 3)}
	gotOld, gotOldKey, err := k.openContent(shareKey, noKey)
	if err != nil {
		t.Fatalf("no item key: %v", err)
	}
	if meta, _ := protonpass.ParseItemMetadata(gotOld); meta.Name != "title" {
		t.Fatalf("no item key: %+v", meta)
	}
	if !bytes.Equal(gotOldKey, shareKey) {
		t.Fatal("no item key: content key must be the share key")
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

func TestFindItem(t *testing.T) {
	items := []decryptedItem{
		{key: "a", itemID: "1"},
		{key: "b", itemID: "2"},
		{key: "b", itemID: "3"},
	}

	if _, ok, err := findItem(items, "missing"); ok || err != nil {
		t.Fatalf("absent key: ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	got, ok, err := findItem(items, "a")
	if !ok || err != nil || got.itemID != "1" {
		t.Fatalf("unique key: itemID=%q ok=%v err=%v, want itemID=1 ok=true err=nil", got.itemID, ok, err)
	}

	if _, ok, err := findItem(items, "b"); ok || err == nil {
		t.Fatalf("duplicate key: ok=%v err=%v, want ok=false err!=nil", ok, err)
	}
}
