// Package protonpass is a minimal native-Go client for Proton Pass's internal HTTP
// API, used by the proton-pass keyring backend. It speaks the same wire protocol as
// the Proton Pass CLI, derived from observed traffic (clean-room): the PAT->session
// exchange (two POSTs) and the authenticated read endpoints (shares, items, share
// keys) here in client.go, the symmetric AES-GCM unwrap chain in crypto.go, and the
// item protobuf parse in proto.go.
package protonpass

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Proton API defaults. The app/SDK version headers gate access; these mirror the
// values the Proton Pass CLI sends and can be overridden via Config.
const (
	DefaultAPIBase     = "https://pass-api.proton.me"
	DefaultAppVersion  = "cli-pass@2.1.4"
	DefaultSDKVersions = "muon@2.5.0"
	DefaultOriginSDK   = "pass-cli@2.1.4"

	// ItemContentFormatVersion is the item-v1 content format version sent on
	// create/update. It matches the version the live API currently issues for
	// items; bump it if the server starts rejecting writes at this version.
	ItemContentFormatVersion = 6

	pathUnauthSession = "/auth/v4/sessions"
	pathPATExchange   = "/account/v4/personal-access-token/session"
	pathShares        = "/pass/v1/share"

	itemPageSize = 100
	maxItemPages = 50
	maxBodyBytes = 4 << 20
)

// API is the subset of the Proton Pass client the keyring backend depends on
// (kept small so the backend can mock it in tests).
type API interface {
	Authenticate(ctx context.Context, pat string) (*Session, error)
	ListShares(ctx context.Context, s *Session) ([]Share, error)
	ListItems(ctx context.Context, s *Session, shareID string) ([]ItemRevision, error)
	GetShareKeys(ctx context.Context, s *Session, shareID string) ([]ShareKey, error)
	CreateItem(ctx context.Context, s *Session, shareID string, req CreateItemRequest) (*ItemRevision, error)
	UpdateItem(ctx context.Context, s *Session, shareID, itemID string, req UpdateItemRequest) (*ItemRevision, error)
	DeleteItem(ctx context.Context, s *Session, shareID, itemID string, revision int) error
}

// Session is an authenticated Proton session: a UID plus bearer tokens.
type Session struct {
	UID          string
	AccessToken  string
	RefreshToken string

	// AccessExpiry is the access token's expiry as reported by the exchange.
	// Proton sends it as AccessExpirationTime; it is treated as Unix seconds
	// when it looks like a plausible future epoch and ignored otherwise (0 if
	// absent). The session-cache freshness check, not this client, decides how
	// to interpret it.
	AccessExpiry int64
}

// Share is one entry from GET /pass/v1/share (a vault the session can access).
// Content is the base64 vault metadata, AES-256-GCM encrypted under the share key
// (AAD "vaultcontent"); decryption is the backend's job (see OpenVaultContent).
type Share struct {
	ShareID              string `json:"ShareID"`
	VaultID              string `json:"VaultID"`
	TargetID             string `json:"TargetID"`
	TargetType           int    `json:"TargetType"`
	AddressID            string `json:"AddressID"`
	Content              string `json:"Content"`
	ContentFormatVersion int    `json:"ContentFormatVersion"`
	ContentKeyRotation   int    `json:"ContentKeyRotation"`
	Permission           int    `json:"Permission"`
	ShareRoleID          string `json:"ShareRoleID"`
	Owner                bool   `json:"Owner"`
	Primary              bool   `json:"Primary"`
	Shared               bool   `json:"Shared"`
	CreateTime           int64  `json:"CreateTime"`
}

// ShareKey is one entry from GET /pass/v1/share/{shareID}/key. For a PAT session
// Key is the base64 share key, AES-256-GCM enveloped with the PAT's "::<key>"
// (AAD "sharekey"); UserKeyID is unused on the PAT path. Decryption is the
// backend's job (see crypto.go OpenShareKey).
type ShareKey struct {
	KeyRotation int    `json:"KeyRotation"`
	Key         string `json:"Key"`
	UserKeyID   string `json:"UserKeyID"`
	CreateTime  int64  `json:"CreateTime"`
}

// ItemRevision is one entry from GET /pass/v1/share/{shareID}/item. Content is
// the base64 AES-256-GCM ciphertext (decrypts to a protobuf); ItemKey is the
// per-item key wrapped to the share key.
type ItemRevision struct {
	ItemID               string `json:"ItemID"`
	Revision             int    `json:"Revision"`
	Content              string `json:"Content"`
	ItemKey              string `json:"ItemKey"`
	ContentFormatVersion int    `json:"ContentFormatVersion"`
	KeyRotation          int    `json:"KeyRotation"`
	Flags                int    `json:"Flags"`
	CreateTime           int64  `json:"CreateTime"`
	ModifyTime           int64  `json:"ModifyTime"`
	RevisionTime         int64  `json:"RevisionTime"`
}

// CreateItemRequest is the body of POST /pass/v1/share/{shareID}/item. Content is
// the base64 AES-GCM item ciphertext; ItemKey is the per-item key wrapped to the
// share key. KeyRotation is the share-key rotation ItemKey is wrapped under.
type CreateItemRequest struct {
	KeyRotation          int    `json:"KeyRotation"`
	ContentFormatVersion int    `json:"ContentFormatVersion"`
	Content              string `json:"Content"`
	ItemKey              string `json:"ItemKey"`
}

// UpdateItemRequest is the body of PUT /pass/v1/share/{shareID}/item/{itemID}. The
// per-item key is unchanged on update, so only the re-encrypted Content is sent;
// LastRevision is the revision being replaced (optimistic concurrency).
type UpdateItemRequest struct {
	KeyRotation          int    `json:"KeyRotation"`
	LastRevision         int    `json:"LastRevision"`
	Content              string `json:"Content"`
	ContentFormatVersion int    `json:"ContentFormatVersion"`
}

// itemIDRevision identifies one item revision for trash/delete requests.
type itemIDRevision struct {
	ItemID   string `json:"ItemID"`
	Revision int    `json:"Revision"`
}

// deleteItemsRequest is the body of DELETE /pass/v1/share/{shareID}/item.
// SkipTrash=true deletes outright rather than moving to trash first.
type deleteItemsRequest struct {
	Items     []itemIDRevision `json:"Items"`
	SkipTrash bool             `json:"SkipTrash"`
}

// Client talks to the Proton Pass HTTP API over native net/http (HTTP/2, system
// trust roots). Proton pins server certs against its own clients, but that only
// affects the official clients; a standard Go client connects normally.
type Client struct {
	HTTP        *http.Client
	APIBase     string
	AppVersion  string
	SDKVersions string
	OriginSDK   string
}

// NormalizeAPIBase resolves an empty base to the default and trims a trailing
// slash, so callers and the session cache agree on one canonical form.
func NormalizeAPIBase(apiBase string) string {
	if apiBase == "" {
		apiBase = DefaultAPIBase
	}
	return strings.TrimRight(apiBase, "/")
}

// New returns a Client with Proton defaults; apiBase may be "" for the default.
func New(apiBase string) *Client {
	return &Client{
		HTTP:        &http.Client{Timeout: 30 * time.Second},
		APIBase:     NormalizeAPIBase(apiBase),
		AppVersion:  DefaultAppVersion,
		SDKVersions: DefaultSDKVersions,
		OriginSDK:   DefaultOriginSDK,
	}
}

var _ API = (*Client)(nil)

// APIError is a non-2xx response or a Proton error envelope ({Code, Error}).
type APIError struct {
	Status  int
	Code    int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("proton api: http %d, code %d: %s", e.Status, e.Code, e.Message)
}

// PATToken returns the "pst_<token>" half of a compound "pst_<token>::<key>" PAT.
// The "::<key>" half is the client-side vault-unwrap key and is never sent.
func PATToken(pat string) string {
	if i := strings.Index(pat, "::"); i >= 0 {
		return pat[:i]
	}
	return pat
}

// Authenticate performs the PAT -> session exchange: create an anonymous session,
// then exchange the PAT for an authenticated one.
func (c *Client) Authenticate(ctx context.Context, pat string) (*Session, error) {
	var unauth struct {
		UID         string `json:"UID"`
		AccessToken string `json:"AccessToken"`
	}
	if err := c.do(ctx, http.MethodPost, pathUnauthSession, nil, "", "", &unauth); err != nil {
		return nil, fmt.Errorf("create unauth session: %w", err)
	}
	if unauth.UID == "" || unauth.AccessToken == "" {
		return nil, fmt.Errorf("create unauth session: missing UID/AccessToken in response")
	}

	var exch struct {
		Session struct {
			SessionUID           string `json:"SessionUID"`
			AccessToken          string `json:"AccessToken"`
			RefreshToken         string `json:"RefreshToken"`
			AccessExpirationTime int64  `json:"AccessExpirationTime"`
		} `json:"Session"`
	}
	body := map[string]string{"Token": PATToken(pat)}
	if err := c.do(ctx, http.MethodPost, pathPATExchange, body, unauth.UID, unauth.AccessToken, &exch); err != nil {
		return nil, fmt.Errorf("exchange personal access token: %w", err)
	}
	if exch.Session.SessionUID == "" || exch.Session.AccessToken == "" {
		return nil, fmt.Errorf("exchange personal access token: missing session in response")
	}
	return &Session{
		UID:          exch.Session.SessionUID,
		AccessToken:  exch.Session.AccessToken,
		RefreshToken: exch.Session.RefreshToken,
		AccessExpiry: exch.Session.AccessExpirationTime,
	}, nil
}

// ListShares returns the vaults/shares the session can access.
func (c *Client) ListShares(ctx context.Context, s *Session) ([]Share, error) {
	var resp struct {
		Shares []Share `json:"Shares"`
		Total  int     `json:"Total"`
	}
	if err := c.do(ctx, http.MethodGet, pathShares, nil, s.UID, s.AccessToken, &resp); err != nil {
		return nil, fmt.Errorf("list shares: %w", err)
	}
	return resp.Shares, nil
}

// ListItems returns every item revision in a share, following pagination.
func (c *Client) ListItems(ctx context.Context, s *Session, shareID string) ([]ItemRevision, error) {
	var all []ItemRevision
	since := ""
	for page := 0; page < maxItemPages; page++ {
		path := fmt.Sprintf("%s/%s/item?PageSize=%d", pathShares, shareID, itemPageSize)
		if since != "" {
			path += "&Since=" + url.QueryEscape(since)
		}
		var resp struct {
			Items struct {
				LastToken     string         `json:"LastToken"`
				RevisionsData []ItemRevision `json:"RevisionsData"`
			} `json:"Items"`
		}
		if err := c.do(ctx, http.MethodGet, path, nil, s.UID, s.AccessToken, &resp); err != nil {
			return nil, fmt.Errorf("list items in share %q: %w", shareID, err)
		}
		all = append(all, resp.Items.RevisionsData...)
		if resp.Items.LastToken == "" || len(resp.Items.RevisionsData) == 0 {
			break
		}
		since = resp.Items.LastToken
	}
	return all, nil
}

// GetShareKeys returns the (still-encrypted) key rotations for a share.
func (c *Client) GetShareKeys(ctx context.Context, s *Session, shareID string) ([]ShareKey, error) {
	var resp struct {
		ShareKeys struct {
			Keys  []ShareKey `json:"Keys"`
			Total int        `json:"Total"`
		} `json:"ShareKeys"`
	}
	path := fmt.Sprintf("%s/%s/key?Page=0", pathShares, shareID)
	if err := c.do(ctx, http.MethodGet, path, nil, s.UID, s.AccessToken, &resp); err != nil {
		return nil, fmt.Errorf("get share keys for %q: %w", shareID, err)
	}
	return resp.ShareKeys.Keys, nil
}

// CreateItem creates a new item in the share and returns its new revision.
func (c *Client) CreateItem(ctx context.Context, s *Session, shareID string, req CreateItemRequest) (*ItemRevision, error) {
	if req.ContentFormatVersion == 0 {
		req.ContentFormatVersion = ItemContentFormatVersion
	}
	var resp struct {
		Item ItemRevision `json:"Item"`
	}
	path := fmt.Sprintf("%s/%s/item", pathShares, shareID)
	if err := c.do(ctx, http.MethodPost, path, req, s.UID, s.AccessToken, &resp); err != nil {
		return nil, fmt.Errorf("create item in share %q: %w", shareID, err)
	}
	return &resp.Item, nil
}

// UpdateItem replaces an item's content and returns its new revision.
func (c *Client) UpdateItem(ctx context.Context, s *Session, shareID, itemID string, req UpdateItemRequest) (*ItemRevision, error) {
	if req.ContentFormatVersion == 0 {
		req.ContentFormatVersion = ItemContentFormatVersion
	}
	var resp struct {
		Item ItemRevision `json:"Item"`
	}
	path := fmt.Sprintf("%s/%s/item/%s", pathShares, shareID, itemID)
	if err := c.do(ctx, http.MethodPut, path, req, s.UID, s.AccessToken, &resp); err != nil {
		return nil, fmt.Errorf("update item %q in share %q: %w", itemID, shareID, err)
	}
	return &resp.Item, nil
}

// DeleteItem permanently deletes an item (bypassing trash). revision is the
// item's current revision for the optimistic-concurrency check.
func (c *Client) DeleteItem(ctx context.Context, s *Session, shareID, itemID string, revision int) error {
	body := deleteItemsRequest{
		Items:     []itemIDRevision{{ItemID: itemID, Revision: revision}},
		SkipTrash: true,
	}
	path := fmt.Sprintf("%s/%s/item", pathShares, shareID)
	if err := c.do(ctx, http.MethodDelete, path, body, s.UID, s.AccessToken, nil); err != nil {
		return fmt.Errorf("delete item %q in share %q: %w", itemID, shareID, err)
	}
	return nil
}

// do builds and sends one request, applies the Proton headers, checks the
// {Code,Error} envelope, and decodes a 2xx body into out (if non-nil).
func (c *Client) do(ctx context.Context, method, path string, body any, uid, bearer string, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.APIBase+path, reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("x-pm-appversion", c.AppVersion)
	req.Header.Set("x-pm-sdk-versions", c.SDKVersions)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if uid != "" {
		req.Header.Set("x-pm-uid", uid)
		req.Header.Set("x-pm-origin-sdk", c.OriginSDK)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	var env struct {
		Code  int    `json:"Code"`
		Error string `json:"Error"`
	}
	_ = json.Unmarshal(raw, &env)
	if resp.StatusCode/100 != 2 || env.Error != "" {
		return &APIError{Status: resp.StatusCode, Code: env.Code, Message: env.Error}
	}

	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
