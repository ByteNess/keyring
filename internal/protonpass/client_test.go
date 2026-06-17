package protonpass

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testUnauthUID    = "unauth-uid-123"
	testUnauthAccess = "unauth.access.jwe"
	testSessionUID   = "session-uid-456"
	testAccess       = "auth.access.jwe"
	testRefresh      = "auth.refresh.jwe"
	testPAT          = "pst_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testShareID      = "share_AA__==" // base64url-ish with padding, like a real share id
)

func TestPATToken(t *testing.T) {
	want := "pst_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if got := PATToken(testPAT); got != want {
		t.Fatalf("PATToken kept the ::key half or mangled token: %q", got)
	}
	if got := PATToken("pst_nokey"); got != "pst_nokey" {
		t.Fatalf("PATToken should pass through a token without ::key, got %q", got)
	}
}

func newTestClient(t *testing.T, mux *http.ServeMux) *Client {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := New(srv.URL)
	c.HTTP = srv.Client()
	return c
}

func TestAuthenticate(t *testing.T) {
	var gotExchange *http.Request
	var gotBody string

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/v4/sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-pm-uid") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("unauth session request must be anonymous; got uid=%q auth=%q",
				r.Header.Get("x-pm-uid"), r.Header.Get("Authorization"))
		}
		writeJSON(w, map[string]any{"Code": 1000, "UID": testUnauthUID, "AccessToken": testUnauthAccess})
	})
	mux.HandleFunc("POST /account/v4/personal-access-token/session", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotExchange = r
		writeJSON(w, map[string]any{"Code": 1000, "Session": map[string]any{
			"SessionUID": testSessionUID, "AccessToken": testAccess, "RefreshToken": testRefresh,
		}})
	})

	c := newTestClient(t, mux)
	sess, err := c.Authenticate(context.Background(), testPAT)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.UID != testSessionUID || sess.AccessToken != testAccess || sess.RefreshToken != testRefresh {
		t.Fatalf("session not mapped from nested Session{SessionUID,...}: %+v", sess)
	}

	// the exchange must carry the unauth session creds + correct headers
	if got := gotExchange.Header.Get("x-pm-uid"); got != testUnauthUID {
		t.Errorf("exchange x-pm-uid = %q, want unauth UID %q", got, testUnauthUID)
	}
	if got := gotExchange.Header.Get("Authorization"); got != "Bearer "+testUnauthAccess {
		t.Errorf("exchange Authorization = %q, want bearer of unauth access token", got)
	}
	for h, want := range map[string]string{
		"x-pm-appversion":   DefaultAppVersion,
		"x-pm-sdk-versions": DefaultSDKVersions,
		"x-pm-origin-sdk":   DefaultOriginSDK,
		"Content-Type":      "application/json",
	} {
		if got := gotExchange.Header.Get(h); got != want {
			t.Errorf("exchange header %s = %q, want %q", h, got, want)
		}
	}

	// the body must send only the pst_ half, as {"Token": ...}
	var sent struct{ Token string }
	if err := json.Unmarshal([]byte(gotBody), &sent); err != nil {
		t.Fatalf("exchange body not JSON: %q", gotBody)
	}
	if sent.Token != PATToken(testPAT) {
		t.Errorf("exchange Token = %q, want pst_ half only (no ::key)", sent.Token)
	}
	if strings.Contains(gotBody, "::") {
		t.Errorf("exchange body leaked the ::key half: %q", gotBody)
	}
}

func TestListSharesAndItems(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /pass/v1/share", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testAccess || r.Header.Get("x-pm-uid") != testSessionUID {
			t.Errorf("authed GET missing session headers: uid=%q auth=%q",
				r.Header.Get("x-pm-uid"), r.Header.Get("Authorization"))
		}
		writeJSON(w, map[string]any{
			"Code": 1000, "Total": 1,
			"Shares": []map[string]any{{
				"ShareID": testShareID, "VaultID": "vault1", "TargetType": 1,
				"Content": "encrypted-vault-meta", "ContentKeyRotation": 1, "Primary": true,
			}},
		})
	})
	mux.HandleFunc("GET /pass/v1/share/{shareID}/item", func(w http.ResponseWriter, r *http.Request) {
		if got := r.PathValue("shareID"); got != testShareID {
			t.Errorf("item list share id = %q, want %q", got, testShareID)
		}
		writeJSON(w, map[string]any{
			"Code": 1000,
			"Items": map[string]any{
				"LastToken": "",
				"RevisionsData": []map[string]any{{
					"ItemID": "item1", "Revision": 3, "Content": "enc-item", "ItemKey": "wrapped-key",
					"ContentFormatVersion": 6, "KeyRotation": 1,
				}},
			},
		})
	})

	c := newTestClient(t, mux)
	sess := &Session{UID: testSessionUID, AccessToken: testAccess}

	shares, err := c.ListShares(context.Background(), sess)
	if err != nil {
		t.Fatalf("ListShares: %v", err)
	}
	if len(shares) != 1 || shares[0].ShareID != testShareID || !shares[0].Primary {
		t.Fatalf("unexpected shares: %+v", shares)
	}

	items, err := c.ListItems(context.Background(), sess, testShareID)
	if err != nil {
		t.Fatalf("ListItems: %v", err)
	}
	if len(items) != 1 || items[0].ItemID != "item1" || items[0].ContentFormatVersion != 6 {
		t.Fatalf("unexpected items: %+v", items)
	}
}

func TestAuthenticateRejection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/v4/sessions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"Code": 1000, "UID": testUnauthUID, "AccessToken": testUnauthAccess})
	})
	mux.HandleFunc("POST /account/v4/personal-access-token/session", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"Code": 2001, "Error": "Invalid or expired personal access token"})
	})

	c := newTestClient(t, mux)
	_, err := c.Authenticate(context.Background(), testPAT)
	if err == nil {
		t.Fatal("expected an error for a rejected PAT")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is not *APIError: %v", err)
	}
	if apiErr.Status != http.StatusBadRequest || !strings.Contains(apiErr.Message, "Invalid or expired") {
		t.Fatalf("APIError missing status/message: %+v", apiErr)
	}
}

func TestListItemsPagination(t *testing.T) {
	const cursor = "tok==" // contains '=' to exercise query escaping/round-trip
	var pages int

	mux := http.NewServeMux()
	mux.HandleFunc("GET /pass/v1/share/{shareID}/item", func(w http.ResponseWriter, r *http.Request) {
		pages++
		switch r.URL.Query().Get("Since") {
		case "":
			writeJSON(w, map[string]any{"Code": 1000, "Items": map[string]any{
				"LastToken": cursor, "RevisionsData": []map[string]any{{"ItemID": "item1"}},
			}})
		case cursor: // server sees the decoded cursor -> escaping round-tripped
			writeJSON(w, map[string]any{"Code": 1000, "Items": map[string]any{
				"LastToken": "", "RevisionsData": []map[string]any{{"ItemID": "item2"}},
			}})
		default:
			t.Errorf("page %d had unexpected Since=%q", pages, r.URL.Query().Get("Since"))
			writeJSON(w, map[string]any{"Code": 1000, "Items": map[string]any{}})
		}
	})

	c := newTestClient(t, mux)
	items, err := c.ListItems(context.Background(), &Session{UID: "u", AccessToken: "a"}, testShareID)
	if err != nil {
		t.Fatalf("ListItems: %v", err)
	}
	if pages != 2 {
		t.Errorf("expected 2 page requests, got %d", pages)
	}
	if len(items) != 2 || items[0].ItemID != "item1" || items[1].ItemID != "item2" {
		t.Fatalf("pagination did not accumulate both pages: %+v", items)
	}
}

func TestGetShareKeys(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /pass/v1/share/{shareID}/key", func(w http.ResponseWriter, r *http.Request) {
		if got := r.PathValue("shareID"); got != testShareID {
			t.Errorf("share keys path id = %q, want %q", got, testShareID)
		}
		if r.URL.Query().Get("Page") != "0" {
			t.Errorf("expected Page=0, got %q", r.URL.Query().Get("Page"))
		}
		writeJSON(w, map[string]any{
			"Code": 1000,
			"ShareKeys": map[string]any{
				"Total": 1,
				"Keys": []map[string]any{{
					"KeyRotation": 1, "Key": "base64-share-key", "UserKeyID": "uk1", "CreateTime": 123,
				}},
			},
		})
	})

	c := newTestClient(t, mux)
	keys, err := c.GetShareKeys(context.Background(), &Session{UID: testSessionUID, AccessToken: testAccess}, testShareID)
	if err != nil {
		t.Fatalf("GetShareKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].KeyRotation != 1 || keys[0].Key != "base64-share-key" || keys[0].UserKeyID != "uk1" {
		t.Fatalf("unexpected share keys: %+v", keys)
	}
}

func TestAuthenticateMalformed(t *testing.T) {
	tests := []struct {
		name             string
		unauth, exchange map[string]any
	}{
		{
			name:   "unauth session missing access token",
			unauth: map[string]any{"Code": 1000, "UID": testUnauthUID}, // no AccessToken
		},
		{
			name:     "exchange missing session",
			unauth:   map[string]any{"Code": 1000, "UID": testUnauthUID, "AccessToken": testUnauthAccess},
			exchange: map[string]any{"Code": 1000}, // no Session
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("POST /auth/v4/sessions", func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, tt.unauth)
			})
			mux.HandleFunc("POST /account/v4/personal-access-token/session", func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, tt.exchange)
			})
			c := newTestClient(t, mux)
			if _, err := c.Authenticate(context.Background(), testPAT); err == nil {
				t.Fatal("expected an error for a malformed response")
			}
		})
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
