// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	coreerrors "github.com/go-core-stack/core/errors"
)

// --- TokenResponseMappers unit tests ---

// Register with a trailing slash, lookup without (and reverse) must hit.
func TestTokenResponseMappers_RegisterAndLookup(t *testing.T) {
	m := NewTokenResponseMappers()
	called := false
	m.Register("https://slack.com/", func(raw []byte) (*TokenResponse, error) {
		called = true
		return &TokenResponse{AccessToken: "mapped"}, nil
	})

	// Lookup without trailing slash.
	fn := m.lookup("https://slack.com")
	if fn == nil {
		t.Fatal("expected mapper for https://slack.com (registered with trailing slash)")
	}
	resp, err := fn(nil)
	if err != nil || resp.AccessToken != "mapped" || !called {
		t.Errorf("mapper not invoked correctly: resp=%+v err=%v called=%v", resp, err, called)
	}

	// Register without trailing slash, lookup with.
	m2 := NewTokenResponseMappers()
	m2.Register("https://example.com", func(raw []byte) (*TokenResponse, error) {
		return &TokenResponse{AccessToken: "ex"}, nil
	})
	if fn2 := m2.lookup("https://example.com/"); fn2 == nil {
		t.Fatal("expected mapper for https://example.com/ (registered without slash)")
	}

	// Miss for unregistered server.
	if fn3 := m.lookup("https://other.com"); fn3 != nil {
		t.Error("expected nil for unregistered server")
	}
}

// Nil receiver on lookup returns nil; nil receiver on Register does not panic.
func TestTokenResponseMappers_NilSafe(t *testing.T) {
	var m *TokenResponseMappers
	if fn := m.lookup("https://slack.com"); fn != nil {
		t.Error("nil receiver lookup must return nil")
	}
	// Must not panic.
	m.Register("https://slack.com", func(raw []byte) (*TokenResponse, error) {
		return nil, nil
	})
}

// --- handleCallback mapper tests ---

// slackLikeResponse is a token-endpoint response where access_token is nested
// inside an authed_user object (like Slack's V2 OAuth).
const slackLikeResponse = `{
	"ok": true,
	"token_type": "Bearer",
	"authed_user": {
		"access_token": "xoxp-nested-token",
		"token_type": "user"
	}
}`

// slackMapper extracts the access_token from the authed_user object.
func slackMapper(raw []byte) (*TokenResponse, error) {
	var body struct {
		AuthedUser struct {
			AccessToken string `json:"access_token"`
		} `json:"authed_user"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	return &TokenResponse{AccessToken: body.AuthedUser.AccessToken}, nil
}

func TestHandleCallback_TokenResponseMapper_Applied(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer()
	pending := newFakePendingStore()
	seedPending(pending, "state-1", &PendingAuthState{
		ServerURL:    "https://api.example.com",
		AccountID:    "acct-1",
		ClientID:     "client-abc",
		CodeVerifier: "verifier-xyz",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       []string{"read"},
	})
	tokens := newFakeTokenWriter()

	do := func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(slackLikeResponse), nil
	}

	mappers := NewTokenResponseMappers()
	mappers.Register("https://api.example.com", slackMapper)

	entry, err := handleCallback(context.Background(), do, servers, pending, tokens, newFakeClientStore(), "state-1", "auth-code-1", mappers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.AccessToken != "xoxp-nested-token" {
		t.Errorf("AccessToken = %q, want xoxp-nested-token", entry.AccessToken)
	}
	if entry.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer (preserved from standard parse)", entry.TokenType)
	}
}

func TestHandleCallback_TokenResponseMapper_NotInvokedWhenAccessTokenPresent(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer()
	pending := newFakePendingStore()
	seedPending(pending, "state-1", &PendingAuthState{
		ServerURL:    "https://api.example.com",
		AccountID:    "acct-1",
		ClientID:     "client-abc",
		CodeVerifier: "verifier-xyz",
		RedirectURI:  "https://app.example.com/callback",
	})
	tokens := newFakeTokenWriter()

	// Standard response with a top-level access_token.
	do := func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(tokenResp), nil
	}

	mapperCalled := false
	mappers := NewTokenResponseMappers()
	mappers.Register("https://api.example.com", func(raw []byte) (*TokenResponse, error) {
		mapperCalled = true
		return &TokenResponse{AccessToken: "should-not-be-used"}, nil
	})

	entry, err := handleCallback(context.Background(), do, servers, pending, tokens, newFakeClientStore(), "state-1", "auth-code-1", mappers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mapperCalled {
		t.Error("mapper must not be invoked when standard response has access_token")
	}
	if entry.AccessToken != "at-123" {
		t.Errorf("AccessToken = %q, want at-123 from standard parse", entry.AccessToken)
	}
}

func TestHandleCallback_TokenResponseMapper_LookupMiss(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer()
	pending := newFakePendingStore()
	seedPending(pending, "state-1", &PendingAuthState{
		ServerURL:    "https://api.example.com",
		AccountID:    "acct-1",
		ClientID:     "client-abc",
		CodeVerifier: "verifier-xyz",
		RedirectURI:  "https://app.example.com/callback",
	})
	tokens := newFakeTokenWriter()

	// Response with no top-level access_token.
	do := func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(`{"token_type":"Bearer","expires_in":3600}`), nil
	}

	// Mapper registered for a DIFFERENT server URL.
	mappers := NewTokenResponseMappers()
	mappers.Register("https://other.example.com", slackMapper)

	_, err := handleCallback(context.Background(), do, servers, pending, tokens, newFakeClientStore(), "state-1", "auth-code-1", mappers)
	if err == nil {
		t.Fatal("expected error for missing access_token with no mapper match")
	}
	if !coreerrors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
	if !strings.Contains(err.Error(), "access_token") {
		t.Errorf("error should mention access_token: %v", err)
	}
}

func TestHandleCallback_TokenResponseMapper_ReturnsError(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer()
	pending := newFakePendingStore()
	seedPending(pending, "state-1", &PendingAuthState{
		ServerURL:    "https://api.example.com",
		AccountID:    "acct-1",
		ClientID:     "client-abc",
		CodeVerifier: "verifier-xyz",
		RedirectURI:  "https://app.example.com/callback",
	})
	tokens := newFakeTokenWriter()

	do := func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(`{"ok":false,"error":"invalid_auth"}`), nil
	}

	mappers := NewTokenResponseMappers()
	mappers.Register("https://api.example.com", func(raw []byte) (*TokenResponse, error) {
		return nil, errors.New("slack says invalid_auth")
	})

	_, err := handleCallback(context.Background(), do, servers, pending, tokens, newFakeClientStore(), "state-1", "auth-code-1", mappers)
	if err == nil {
		t.Fatal("expected error from mapper")
	}
	if !coreerrors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
	if !strings.Contains(err.Error(), "api.example.com") {
		t.Errorf("error should include server URL: %v", err)
	}
	if tokens.locates != 0 {
		t.Errorf("must not persist a token on mapper error; locates=%d", tokens.locates)
	}
}

// The mapper only sets AccessToken; token_type, expires_in, and scope from the
// standard parse must be preserved (field-by-field merge).
func TestHandleCallback_TokenResponseMapper_FieldByFieldMerge(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer()
	pending := newFakePendingStore()
	seedPending(pending, "state-1", &PendingAuthState{
		ServerURL:    "https://api.example.com",
		AccountID:    "acct-1",
		ClientID:     "client-abc",
		CodeVerifier: "verifier-xyz",
		RedirectURI:  "https://app.example.com/callback",
		Scopes:       []string{"read", "write"},
	})
	tokens := newFakeTokenWriter()

	// Server returns some fields top-level, but access_token is nested.
	do := func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(`{"token_type":"Bearer","expires_in":7200,"scope":"read write","authed_user":{"access_token":"xoxp-merged"}}`), nil
	}

	// Mapper only extracts access_token.
	mappers := NewTokenResponseMappers()
	mappers.Register("https://api.example.com", func(raw []byte) (*TokenResponse, error) {
		var body struct {
			AuthedUser struct {
				AccessToken string `json:"access_token"`
			} `json:"authed_user"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, err
		}
		return &TokenResponse{AccessToken: body.AuthedUser.AccessToken}, nil
	})

	entry, err := handleCallback(context.Background(), do, servers, pending, tokens, newFakeClientStore(), "state-1", "auth-code-1", mappers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.AccessToken != "xoxp-merged" {
		t.Errorf("AccessToken = %q, want xoxp-merged", entry.AccessToken)
	}
	// These must come from the standard JSON parse, not the mapper.
	if entry.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer (from standard parse)", entry.TokenType)
	}
	if entry.ExpiresAt == 0 {
		t.Error("ExpiresAt must be set from standard parse expires_in=7200")
	}
	if strings.Join(entry.Scopes, " ") != "read write" {
		t.Errorf("Scopes = %v, want [read write] (from standard parse)", entry.Scopes)
	}
}

// --- refreshTokenExchange mapper tests ---

func TestRefreshTokenExchange_TokenResponseMapper_Applied(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = revServer()
	clients := newFakeClientStore()
	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "client-abc"}

	do := func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(slackLikeResponse), nil
	}

	mappers := NewTokenResponseMappers()
	mappers.Register("https://api.example.com", slackMapper)

	prev := &TokenEntry{AccessToken: "old", RefreshToken: "rt-old", State: SessionActive}
	got, err := refreshTokenExchange(context.Background(), do, servers, clients, testTokenKey(), prev, mappers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AccessToken != "xoxp-nested-token" {
		t.Errorf("AccessToken = %q, want xoxp-nested-token", got.AccessToken)
	}
	if got.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer (preserved from standard parse)", got.TokenType)
	}
}

func TestRefreshTokenExchange_TokenResponseMapper_ErrorIsPermanent(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = revServer()
	clients := newFakeClientStore()
	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "client-abc"}

	// Return a response with no top-level access_token so the mapper fires.
	do := func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(`{"ok":false,"error":"invalid_auth"}`), nil
	}

	mappers := NewTokenResponseMappers()
	mappers.Register("https://api.example.com", func(raw []byte) (*TokenResponse, error) {
		return nil, errors.New("mapper failed")
	})

	prev := &TokenEntry{AccessToken: "old", RefreshToken: "rt-old", State: SessionActive}
	_, err := refreshTokenExchange(context.Background(), do, servers, clients, testTokenKey(), prev, mappers)
	if err == nil {
		t.Fatal("expected error from mapper on refresh path")
	}
	if !errors.Is(err, errPermanentRefresh) {
		t.Errorf("mapper error on refresh must be permanent, got %v", err)
	}
}

// jsonResponse is a test helper that builds a 200 OK HTTP response with the
// given JSON body. It is defined in authorization_test.go for the callback
// tests; this is a compile guard that the helper exists in this package.
var _ = jsonResponse

// statusResponse is a test helper that builds a non-JSON HTTP response with the
// given status code. Defined in the shared test helpers.
var _ = statusResponse

// Helper to build a simple JSON response for tests — mirrors the one in
// authorization_test.go but avoids redeclaration by referencing the shared one.
func mapperTestJSONResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}
