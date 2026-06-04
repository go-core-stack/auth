// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-core-stack/core/errors"
)

// TestEndToEndFlow drives the full OAuth client-library lifecycle through the
// package's own logic — discovery → registration → authorize → callback →
// get → refresh → revoke — against a single in-memory authorization/resource
// server (httptest, loopback only) and the shared in-memory table fakes. It is
// hermetic: no real network and no MongoDB.
//
// The public *OAuthManager methods are thin one-line delegations to these same
// internal helpers (token.go / discovery.go / registration.go / authorization.go),
// passing the manager's concrete *table.Table fields — which cannot be faked
// outside core/db (see manager_test.go). Wiring the helpers together here
// exercises every step the public API runs at runtime with real HTTP round-trips.
func TestEndToEndFlow(t *testing.T) {
	ctx := context.Background()

	// captured request artifacts, for end-to-end assertions
	var (
		gotAuthCode     string
		gotCodeVerifier string
		gotRefreshGrant bool
		revokedToken    string
		revokedHint     string
	)

	// srvURL is captured by the handler closures; it is only read at request
	// time, after the server has started and srvURL has been set below.
	var srvURL string

	mux := http.NewServeMux()

	// RFC 9728 protected-resource metadata: names the authorization server.
	mux.HandleFunc(WellKnownProtectedResource, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"resource":              srvURL,
			"authorization_servers": []string{srvURL},
			"scopes_supported":      []string{"read", "write"},
		})
	})

	// RFC 8414 authorization-server metadata: advertises every endpoint the flow
	// needs, all served by this same test server.
	mux.HandleFunc(WellKnownAuthorizationServer, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"issuer":                 srvURL,
			"authorization_endpoint": srvURL + "/authorize",
			"token_endpoint":         srvURL + "/token",
			"revocation_endpoint":    srvURL + "/revoke",
			"registration_endpoint":  srvURL + "/register",
			"grant_types_supported":  []string{"authorization_code", "refresh_token"},
		})
	})

	// RFC 7591 dynamic registration: issues a public client.
	mux.HandleFunc("/register", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{
			"client_id":     "e2e-client",
			"redirect_uris": []string{"https://consumer.example/callback"},
			"scope":         "read write",
		})
	})

	// Token endpoint: serves both the authorization-code exchange (callback) and
	// the refresh-token grant (forced refresh), returning distinct access tokens
	// so the refresh is observable.
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("token endpoint: parse form: %v", err)
		}
		switch r.Form.Get("grant_type") {
		case grantTypeAuthorizationCode:
			gotAuthCode = r.Form.Get("code")
			gotCodeVerifier = r.Form.Get("code_verifier")
			writeJSON(t, w, map[string]any{
				"access_token":  "access-1",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "refresh-1",
				"scope":         "read write",
				"id_token":      "id-1",
			})
		case grantTypeRefreshToken:
			gotRefreshGrant = true
			writeJSON(t, w, map[string]any{
				"access_token":  "access-2",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "refresh-2",
				"scope":         "read write",
			})
		default:
			http.Error(w, "unsupported grant_type", http.StatusBadRequest)
		}
	})

	// RFC 7009 revocation: records what was revoked and returns 200.
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("revocation endpoint: parse form: %v", err)
		}
		revokedToken = r.Form.Get("token")
		revokedHint = r.Form.Get("token_type_hint")
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL
	do := srv.Client().Do

	// Shared in-memory state and a config standing in for the manager's fields.
	servers := newFakeServerCache()
	clients := newFakeClientStore()
	pending := newFakePendingStore()
	tokens := newFakeTokenStore()
	regLocks := &fakeRegistrationLocks{}
	refLocks := &fakeLocker{}
	cfg := OAuthConfig{
		RedirectURI: "https://consumer.example/callback",
		Scopes:      []string{"read", "write"},
		ClientName:  "e2e-test-client",
	}

	// Closures mirroring how NewOAuthManager wires DiscoverServer (used by
	// registration) and refreshToken (used by the lifecycle refresh path) over
	// the shared fakes and HTTP doer.
	discover := func(ctx context.Context, serverURL string) (*ServerEntry, error) {
		return discoverServer(ctx, do, servers, serverURL)
	}
	refresh := func(ctx context.Context, key *TokenKey, entry *TokenEntry) (*TokenEntry, error) {
		return refreshTokenExchange(ctx, do, servers, clients, key, entry)
	}
	const accountID = "acct-1"

	// 1. Discovery — RFC 9728 → RFC 8414, cached into the server table.
	server, err := discoverServer(ctx, do, servers, srvURL)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	if server.TokenEndpoint != srvURL+"/token" || server.RegistrationEndpoint != srvURL+"/register" {
		t.Fatalf("discovery did not resolve endpoints: %+v", server)
	}

	// 2. Registration — RFC 7591 dynamic, persisted to the client table.
	client, err := registerDynamicClient(ctx, do, clients, regLocks, discover, cfg, RegisterClientOptions{ServerURL: srvURL})
	if err != nil {
		t.Fatalf("registration: %v", err)
	}
	if client.ClientID != "e2e-client" {
		t.Fatalf("registration client_id = %q", client.ClientID)
	}
	if !regLocks.released() {
		t.Error("registration lock must be released")
	}

	// 3. Authorize — PKCE params + persisted pending state.
	params, err := authorizationURL(ctx, servers, clients, pending, cfg, AuthorizeOptions{
		ServerURL: srvURL,
		AccountID: accountID,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if params.State == "" || params.CodeChallenge == "" || params.CodeChallengeMethod != CodeChallengeMethodS256 {
		t.Fatalf("authorize params incomplete: %+v", params)
	}
	if params.ClientID != "e2e-client" || params.Endpoint != srvURL+"/authorize" {
		t.Fatalf("authorize params not wired to discovery/registration: %+v", params)
	}

	// 4. Callback — exchange the code, persist the token, consume pending state.
	token, err := handleCallback(ctx, do, servers, pending, tokens, params.State, "auth-code-xyz")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if token.AccessToken != "access-1" || token.State != SessionActive {
		t.Fatalf("callback token = %+v", token)
	}
	if gotAuthCode != "auth-code-xyz" {
		t.Errorf("token endpoint saw code %q", gotAuthCode)
	}
	// PKCE end-to-end: the verifier presented at the exchange must hash to the
	// challenge handed out at authorize time.
	if codeChallengeS256(gotCodeVerifier) != params.CodeChallenge {
		t.Errorf("PKCE verifier does not match the issued challenge")
	}
	if _, err := pending.Find(ctx, &PendingAuthStateKey{State: params.State}); !errors.IsNotFound(err) {
		t.Errorf("pending state must be consumed after callback, got %v", err)
	}

	// 5a. GetToken — a healthy (1h) token is returned without a network call or
	// refresh-lock acquisition.
	got, err := getToken(ctx, tokens, refLocks, refresh, srvURL, "", accountID)
	if err != nil {
		t.Fatalf("get token: %v", err)
	}
	if got.AccessToken != "access-1" {
		t.Errorf("healthy GetToken = %q, want access-1", got.AccessToken)
	}
	if refLocks.acquired != 0 {
		t.Errorf("healthy GetToken must not acquire the refresh lock, acquired=%d", refLocks.acquired)
	}

	// 5b. RefreshToken — forced refresh via the refresh-token grant.
	refreshed, err := forceRefresh(ctx, tokens, refLocks, refresh, srvURL, "", accountID)
	if err != nil {
		t.Fatalf("forced refresh: %v", err)
	}
	if refreshed.AccessToken != "access-2" || refreshed.RefreshToken != "refresh-2" {
		t.Fatalf("forced refresh token = %+v", refreshed)
	}
	if !gotRefreshGrant {
		t.Error("token endpoint did not see a refresh_token grant")
	}
	if refLocks.acquired != 1 || refLocks.lock == nil || !refLocks.lock.closed {
		t.Errorf("forced refresh must acquire and release the refresh lock (acquired=%d)", refLocks.acquired)
	}

	// 6. Revoke — RFC 7009 at the server, local session marked revoked.
	if err := revokeToken(ctx, tokens, do, servers, clients, srvURL, "", accountID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revokedToken != "refresh-2" || revokedHint != tokenTypeHintRefresh {
		t.Errorf("revocation posted token=%q hint=%q, want the refresh token", revokedToken, revokedHint)
	}

	// 7. Session state + listing reflect the revoked, still-stored token.
	state, err := getSessionState(ctx, tokens, srvURL, "", accountID)
	if err != nil {
		t.Fatalf("session state: %v", err)
	}
	if state != SessionRevoked {
		t.Errorf("session state = %q, want revoked", state)
	}
	list, err := listTokens(ctx, tokens, srvURL, "")
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(list) != 1 || list[0].State != SessionRevoked {
		t.Errorf("listTokens = %+v, want one revoked token", list)
	}
}

// TestPendingStateTTLIndexes asserts the TTL index NewOAuthManager ensures on the
// pending_auth_states collection: a single index on createdAt expiring after
// PendingStateTTL. This is the hermetic check for the index whose creation in
// NewOAuthManager requires a live collection.
func TestPendingStateTTLIndexes(t *testing.T) {
	idx := pendingStateTTLIndexes()
	if len(idx) != 1 {
		t.Fatalf("expected exactly one index, got %d", len(idx))
	}
	def := idx[0]
	if def.TTL != PendingStateTTL {
		t.Errorf("TTL = %s, want %s", def.TTL, PendingStateTTL)
	}
	if len(def.Fields) != 1 || def.Fields[0].Field != "createdAt" {
		t.Errorf("TTL index must be on the createdAt field, got %+v", def.Fields)
	}
}

// writeJSON encodes v as a JSON HTTP response body for the in-memory server.
func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encode JSON response: %v", err)
	}
}

// compile-time guard: a single fakeTokenStore must satisfy both the lifecycle
// tokenStore and the callback tokenWriter, as the end-to-end flow relies on.
var (
	_ tokenStore  = (*fakeTokenStore)(nil)
	_ tokenWriter = (*fakeTokenStore)(nil)
)
