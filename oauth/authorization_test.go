// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-core-stack/core/errors"
)

// --- fakes ---

// fakePendingStore is an in-memory pendingStore recording access counts so tests
// can assert persistence and single-use deletion of pending authorization state.
type fakePendingStore struct {
	entries map[string]*PendingAuthState
	inserts int
	finds   int
	deletes int
}

func newFakePendingStore() *fakePendingStore {
	return &fakePendingStore{entries: map[string]*PendingAuthState{}}
}

func (p *fakePendingStore) Insert(_ context.Context, key *PendingAuthStateKey, entry *PendingAuthState) error {
	p.inserts++
	if _, ok := p.entries[key.State]; ok {
		return errors.Wrapf(errors.AlreadyExists, "pending state already exists for %s", key.State)
	}
	p.entries[key.State] = entry
	return nil
}

func (p *fakePendingStore) Find(_ context.Context, key *PendingAuthStateKey) (*PendingAuthState, error) {
	p.finds++
	e, ok := p.entries[key.State]
	if !ok {
		return nil, errors.Wrapf(errors.NotFound, "no pending state for %s", key.State)
	}
	return e, nil
}

func (p *fakePendingStore) DeleteKey(_ context.Context, key *PendingAuthStateKey) error {
	p.deletes++
	if _, ok := p.entries[key.State]; !ok {
		return errors.Wrapf(errors.NotFound, "no pending state for %s", key.State)
	}
	delete(p.entries, key.State)
	return nil
}

// fakeTokenWriter is an in-memory tokenWriter capturing the upserted token so a
// test can assert what was persisted and under which key.
type fakeTokenWriter struct {
	entries map[TokenKey]*TokenEntry
	locates int
}

func newFakeTokenWriter() *fakeTokenWriter {
	return &fakeTokenWriter{entries: map[TokenKey]*TokenEntry{}}
}

func (w *fakeTokenWriter) Locate(_ context.Context, key *TokenKey, entry *TokenEntry) error {
	w.locates++
	w.entries[*key] = entry
	return nil
}

// authServer returns a discovered server with both authorization and token
// endpoints populated.
func authServer() *ServerEntry {
	return &ServerEntry{
		AuthorizationEndpoint: "https://as.example.com/authorize",
		TokenEndpoint:         "https://as.example.com/token",
	}
}

const tokenResp = `{
	"access_token": "at-123",
	"token_type": "Bearer",
	"expires_in": 3600,
	"refresh_token": "rt-456",
	"scope": "read write",
	"id_token": "id-789"
}`

// --- AuthorizationURL tests ---

func TestAuthorizationURL_ParamsCorrectness(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer()
	clients := newFakeClientStore()
	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "client-abc"}
	pending := newFakePendingStore()

	params, err := authorizationURL(context.Background(), servers, clients, pending, testConfig(),
		AuthorizeOptions{
			ServerURL:   "https://api.example.com/",
			AccountID:   "acct-1",
			ExtraParams: map[string]string{"resource": "https://mcp.example.com"},
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if params.Endpoint != "https://as.example.com/authorize" {
		t.Errorf("Endpoint = %q", params.Endpoint)
	}
	if params.ClientID != "client-abc" {
		t.Errorf("ClientID = %q", params.ClientID)
	}
	if params.RedirectURI != "https://app.example.com/callback" {
		t.Errorf("RedirectURI = %q (should default from config)", params.RedirectURI)
	}
	if params.ResponseType != responseTypeCode {
		t.Errorf("ResponseType = %q, want %q", params.ResponseType, responseTypeCode)
	}
	if params.Scope != "read write" {
		t.Errorf("Scope = %q (should default from config)", params.Scope)
	}
	if params.CodeChallengeMethod != CodeChallengeMethodS256 {
		t.Errorf("CodeChallengeMethod = %q, want %q", params.CodeChallengeMethod, CodeChallengeMethodS256)
	}
	if params.State == "" {
		t.Error("State must be populated")
	}
	if params.CodeChallenge == "" {
		t.Error("CodeChallenge must be populated")
	}
	if params.ExtraParams["resource"] != "https://mcp.example.com" {
		t.Errorf("ExtraParams not passed through: %v", params.ExtraParams)
	}

	// pending state persisted under the returned state, keyed to the normalized
	// server URL, with the verifier stored.
	if pending.inserts != 1 {
		t.Errorf("expected 1 pending insert, got %d", pending.inserts)
	}
	ps := pending.entries[params.State]
	if ps == nil {
		t.Fatalf("pending state not persisted under state %q", params.State)
	}
	if ps.ServerURL != "https://api.example.com" {
		t.Errorf("pending ServerURL = %q (should be normalized)", ps.ServerURL)
	}
	if ps.AccountID != "acct-1" {
		t.Errorf("pending AccountID = %q", ps.AccountID)
	}
	// The initiating client is persisted so the callback exchanges the code
	// against the same client_id, even if the client is re-registered meanwhile.
	if ps.ClientID != "client-abc" {
		t.Errorf("pending ClientID = %q", ps.ClientID)
	}
	if ps.CodeVerifier == "" {
		t.Error("pending CodeVerifier must be set")
	}
	if ps.RedirectURI != "https://app.example.com/callback" {
		t.Errorf("pending RedirectURI = %q", ps.RedirectURI)
	}

	// The challenge must be the S256 transform of the stored verifier.
	sum := sha256.Sum256([]byte(ps.CodeVerifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if params.CodeChallenge != want {
		t.Errorf("CodeChallenge = %q, want S256(verifier) = %q", params.CodeChallenge, want)
	}
}

// Each call must mint a distinct verifier and state (crypto/rand).
func TestAuthorizationURL_UniquePerCall(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer()
	clients := newFakeClientStore()
	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "client-abc"}
	pending := newFakePendingStore()

	opts := AuthorizeOptions{ServerURL: "https://api.example.com", AccountID: "acct-1"}
	first, err := authorizationURL(context.Background(), servers, clients, pending, testConfig(), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := authorizationURL(context.Background(), servers, clients, pending, testConfig(), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if first.State == second.State {
		t.Error("state must differ between calls")
	}
	if first.CodeChallenge == second.CodeChallenge {
		t.Error("code challenge must differ between calls")
	}
}

func TestAuthorizationURL_RequiresRegisteredClient(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer()
	clients := newFakeClientStore() // empty
	pending := newFakePendingStore()

	_, err := authorizationURL(context.Background(), servers, clients, pending, testConfig(),
		AuthorizeOptions{ServerURL: "https://api.example.com", AccountID: "acct-1"})
	if err == nil {
		t.Fatal("expected error when no client is registered")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound, got %v", err)
	}
	if pending.inserts != 0 {
		t.Errorf("must not persist pending state without a client; inserts=%d", pending.inserts)
	}
}

func TestAuthorizationURL_RequiresDiscoveredServer(t *testing.T) {
	servers := newFakeServerCache() // empty
	clients := newFakeClientStore()
	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "client-abc"}
	pending := newFakePendingStore()

	_, err := authorizationURL(context.Background(), servers, clients, pending, testConfig(),
		AuthorizeOptions{ServerURL: "https://api.example.com", AccountID: "acct-1"})
	if err == nil {
		t.Fatal("expected error when server is not discovered")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound, got %v", err)
	}
}

func TestAuthorizationURL_RequiresAccountID(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer()
	clients := newFakeClientStore()
	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "client-abc"}
	pending := newFakePendingStore()

	_, err := authorizationURL(context.Background(), servers, clients, pending, testConfig(),
		AuthorizeOptions{ServerURL: "https://api.example.com"})
	if err == nil {
		t.Fatal("expected error when accountID is empty")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}

// Explicit options must override the config defaults.
func TestAuthorizationURL_OptionOverrides(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer()
	clients := newFakeClientStore()
	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "client-abc"}
	pending := newFakePendingStore()

	params, err := authorizationURL(context.Background(), servers, clients, pending, testConfig(),
		AuthorizeOptions{
			ServerURL:   "https://api.example.com",
			AccountID:   "acct-1",
			RedirectURI: "https://other/cb",
			Scopes:      []string{"openid", "email"},
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if params.RedirectURI != "https://other/cb" {
		t.Errorf("RedirectURI = %q, want override", params.RedirectURI)
	}
	if params.Scope != "openid email" {
		t.Errorf("Scope = %q, want override", params.Scope)
	}
}

// --- HandleCallback tests ---

// seedPending stores a pending state and returns its state key, mirroring what
// AuthorizationURL would have persisted.
func seedPending(p *fakePendingStore, state string, ps *PendingAuthState) {
	// Mirror AuthorizationURL, which always stamps a fresh CreatedAt; without
	// one the callback's TTL guard would treat the state as expired.
	if ps.CreatedAt.IsZero() {
		ps.CreatedAt = time.Now()
	}
	p.entries[state] = ps
}

func TestHandleCallback_SuccessfulExchange(t *testing.T) {
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

	var sentForm url.Values
	var sawCT string
	do := func(req *http.Request) (*http.Response, error) {
		sawCT = req.Header.Get("Content-Type")
		body, _ := io.ReadAll(req.Body)
		sentForm, _ = url.ParseQuery(string(body))
		return jsonResponse(tokenResp), nil
	}

	entry, err := handleCallback(context.Background(), do, servers, pending, tokens, newFakeClientStore(), "state-1", "auth-code-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// request shape
	if sawCT != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", sawCT)
	}
	if sentForm.Get("grant_type") != grantTypeAuthorizationCode {
		t.Errorf("grant_type = %q", sentForm.Get("grant_type"))
	}
	if sentForm.Get("code") != "auth-code-1" {
		t.Errorf("code = %q", sentForm.Get("code"))
	}
	if sentForm.Get("code_verifier") != "verifier-xyz" {
		t.Errorf("code_verifier = %q", sentForm.Get("code_verifier"))
	}
	// client_id comes from the pending state (the client that initiated the
	// flow), not from a fresh lookup of whatever is currently registered.
	if sentForm.Get("client_id") != "client-abc" {
		t.Errorf("client_id = %q", sentForm.Get("client_id"))
	}
	if sentForm.Get("redirect_uri") != "https://app.example.com/callback" {
		t.Errorf("redirect_uri = %q", sentForm.Get("redirect_uri"))
	}

	// returned token
	if entry.AccessToken != "at-123" {
		t.Errorf("AccessToken = %q", entry.AccessToken)
	}
	if entry.RefreshToken != "rt-456" {
		t.Errorf("RefreshToken = %q", entry.RefreshToken)
	}
	if entry.IDToken != "id-789" {
		t.Errorf("IDToken = %q", entry.IDToken)
	}
	if entry.TokenType != "Bearer" {
		t.Errorf("TokenType = %q", entry.TokenType)
	}
	if entry.State != SessionActive {
		t.Errorf("State = %q, want %q", entry.State, SessionActive)
	}
	if entry.ExpiresAt == 0 {
		t.Error("ExpiresAt should be derived from expires_in")
	}
	if strings.Join(entry.Scopes, ",") != "read,write" {
		t.Errorf("Scopes = %v", entry.Scopes)
	}

	// persisted under {serverURL, accountId}
	stored, ok := tokens.entries[TokenKey{ServerURL: "https://api.example.com", AccountID: "acct-1"}]
	if !ok || stored.AccessToken != "at-123" {
		t.Errorf("token not persisted under expected key; entries=%v", tokens.entries)
	}

	// pending state consumed
	if pending.deletes != 1 {
		t.Errorf("expected pending state deleted once, got %d", pending.deletes)
	}
	if _, exists := pending.entries["state-1"]; exists {
		t.Error("pending state must be deleted on success")
	}
}

func TestHandleCallback_UnknownState(t *testing.T) {
	servers := newFakeServerCache()
	pending := newFakePendingStore() // empty
	tokens := newFakeTokenWriter()

	do := func(req *http.Request) (*http.Response, error) {
		t.Fatalf("network call made for unknown state: %s", req.URL)
		return nil, nil
	}

	_, err := handleCallback(context.Background(), do, servers, pending, tokens, newFakeClientStore(), "missing", "code")
	if err == nil {
		t.Fatal("expected error for unknown/expired state")
	}
	if !errors.IsNotFound(err) {
		t.Errorf("expected NotFound, got %v", err)
	}
	if tokens.locates != 0 {
		t.Errorf("must not persist a token for unknown state; locates=%d", tokens.locates)
	}
}

func TestHandleCallback_EmptyStateOrCode(t *testing.T) {
	servers := newFakeServerCache()
	pending := newFakePendingStore()
	tokens := newFakeTokenWriter()
	do := func(req *http.Request) (*http.Response, error) {
		t.Fatalf("network call made for invalid input: %s", req.URL)
		return nil, nil
	}

	clients := newFakeClientStore()
	if _, err := handleCallback(context.Background(), do, servers, pending, tokens, clients, "", "code"); !errors.IsInvalidArgument(err) {
		t.Errorf("empty state: expected InvalidArgument, got %v", err)
	}
	if _, err := handleCallback(context.Background(), do, servers, pending, tokens, clients, "state", ""); !errors.IsInvalidArgument(err) {
		t.Errorf("empty code: expected InvalidArgument, got %v", err)
	}
}

// On a token-endpoint error, the pending state must survive for a retry and no
// token may be persisted.
func TestHandleCallback_ExchangeFailureKeepsPending(t *testing.T) {
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
		return statusResponse(http.StatusBadRequest), nil
	}

	_, err := handleCallback(context.Background(), do, servers, pending, tokens, newFakeClientStore(), "state-1", "auth-code-1")
	if err == nil {
		t.Fatal("expected error when token exchange fails")
	}
	if tokens.locates != 0 {
		t.Errorf("must not persist a token on exchange failure; locates=%d", tokens.locates)
	}
	if pending.deletes != 0 {
		t.Errorf("pending state must survive an exchange failure; deletes=%d", pending.deletes)
	}
	if _, ok := pending.entries["state-1"]; !ok {
		t.Error("pending state must still exist after exchange failure")
	}
}

// A token response without an access_token is rejected.
func TestHandleCallback_NoAccessToken(t *testing.T) {
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
		return jsonResponse(`{"token_type":"Bearer","expires_in":3600}`), nil
	}

	_, err := handleCallback(context.Background(), do, servers, pending, tokens, newFakeClientStore(), "state-1", "auth-code-1")
	if err == nil {
		t.Fatal("expected error when response has no access_token")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
	if tokens.locates != 0 {
		t.Errorf("must not persist an empty token; locates=%d", tokens.locates)
	}
}

// A pending state older than PendingStateTTL is rejected (and reaped) before any
// token exchange, guarding against TTL-sweep lag or a store that never reaps.
func TestHandleCallback_ExpiredPendingState(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer()
	pending := newFakePendingStore()
	seedPending(pending, "state-1", &PendingAuthState{
		ServerURL:    "https://api.example.com",
		AccountID:    "acct-1",
		ClientID:     "client-abc",
		CodeVerifier: "verifier-xyz",
		RedirectURI:  "https://app.example.com/callback",
		CreatedAt:    time.Now().Add(-PendingStateTTL - time.Minute),
	})
	tokens := newFakeTokenWriter()

	do := func(_ *http.Request) (*http.Response, error) {
		t.Fatal("token endpoint must not be called for an expired state")
		return nil, nil
	}

	_, err := handleCallback(context.Background(), do, servers, pending, tokens, newFakeClientStore(), "state-1", "auth-code-1")
	if !errors.IsNotFound(err) {
		t.Fatalf("expected NotFound for expired state, got %v", err)
	}
	if tokens.locates != 0 {
		t.Errorf("must not persist a token for an expired state; locates=%d", tokens.locates)
	}
	if _, ok := pending.entries["state-1"]; ok {
		t.Error("expired pending state must be reaped on callback")
	}
}

// Scopes fall back to the requested scopes when the server omits them.
// AuthorizationURL must thread AuthorizeOptions.ClientRef into the persisted
// PendingAuthState so HandleCallback can rebuild the correct TokenKey, and must
// resolve the client under the (ServerURL, ClientRef) pair.
func TestAuthorizationURL_StoresClientRef(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer()
	clients := newFakeClientStore()
	// Static client registered under a non-empty ClientRef.
	clients.entries[ckey("https://api.example.com", "tenant-a")] = &ClientEntry{ClientID: "client-tenant-a"}
	pending := newFakePendingStore()

	params, err := authorizationURL(context.Background(), servers, clients, pending, testConfig(),
		AuthorizeOptions{
			ServerURL: "https://api.example.com/",
			ClientRef: "tenant-a",
			AccountID: "acct-1",
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The client resolved must be the tenant-a static client, not the dynamic slot.
	if params.ClientID != "client-tenant-a" {
		t.Errorf("ClientID = %q, want client-tenant-a (resolved by ClientRef)", params.ClientID)
	}
	ps := pending.entries[params.State]
	if ps == nil {
		t.Fatalf("pending state not persisted under state %q", params.State)
	}
	if ps.ClientRef != "tenant-a" {
		t.Errorf("pending ClientRef = %q, want tenant-a", ps.ClientRef)
	}
}

// End-to-end ClientRef round-trip: an authorize started with ClientRef must
// produce a token persisted under a TokenKey carrying that same ClientRef.
func TestHandleCallback_ClientRefRoundTrip(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer()
	clients := newFakeClientStore()
	clients.entries[ckey("https://api.example.com", "tenant-a")] = &ClientEntry{ClientID: "client-tenant-a"}
	pending := newFakePendingStore()
	tokens := newFakeTokenWriter()

	params, err := authorizationURL(context.Background(), servers, clients, pending, testConfig(),
		AuthorizeOptions{
			ServerURL: "https://api.example.com",
			ClientRef: "tenant-a",
			AccountID: "acct-1",
		})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}

	do := func(_ *http.Request) (*http.Response, error) { return jsonResponse(tokenResp), nil }
	entry, err := handleCallback(context.Background(), do, servers, pending, tokens, clients, params.State, "auth-code-1")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if entry.AccessToken != "at-123" {
		t.Errorf("AccessToken = %q", entry.AccessToken)
	}

	// The token must be stored under the ClientRef-bearing key, not the dynamic
	// (ServerURL, "", AccountID) slot.
	want := TokenKey{ServerURL: "https://api.example.com", ClientRef: "tenant-a", AccountID: "acct-1"}
	if _, ok := tokens.entries[want]; !ok {
		t.Errorf("token not persisted under %+v; entries=%v", want, tokens.entries)
	}
	if _, ok := tokens.entries[TokenKey{ServerURL: "https://api.example.com", AccountID: "acct-1"}]; ok {
		t.Error("token must not be stored under the dynamic (empty ClientRef) key")
	}
}

// A confidential client must present client_secret on the auth-code exchange.
// handleCallback looks the ClientEntry up by ps.ClientRef and, when its ClientID
// matches the one bound into the pending state, attaches client_secret_post.
func TestHandleCallback_ConfidentialSendsSecret(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer()
	clients := newFakeClientStore()
	clients.entries[ckey("https://api.example.com", "tenant-a")] = &ClientEntry{
		ClientID: "client-tenant-a", ClientSecret: "s3cret", ClientType: ClientTypeConfidential,
	}
	pending := newFakePendingStore()
	seedPending(pending, "state-1", &PendingAuthState{
		ServerURL:    "https://api.example.com",
		ClientRef:    "tenant-a",
		AccountID:    "acct-1",
		ClientID:     "client-tenant-a",
		CodeVerifier: "verifier-xyz",
		RedirectURI:  "https://app.example.com/callback",
	})
	tokens := newFakeTokenWriter()

	var sentForm url.Values
	do := func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		sentForm, _ = url.ParseQuery(string(body))
		return jsonResponse(tokenResp), nil
	}

	if _, err := handleCallback(context.Background(), do, servers, pending, tokens, clients, "state-1", "auth-code-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sentForm.Get("client_id") != "client-tenant-a" {
		t.Errorf("client_id = %q", sentForm.Get("client_id"))
	}
	if sentForm.Get("client_secret") != "s3cret" {
		t.Errorf("confidential exchange must send client_secret, got %q", sentForm.Get("client_secret"))
	}
}

// A public client must not present client_secret on the auth-code exchange.
func TestHandleCallback_PublicNoSecret(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer()
	clients := newFakeClientStore()
	clients.entries[ckey("https://api.example.com", "tenant-a")] = &ClientEntry{
		ClientID: "client-tenant-a", ClientType: ClientTypePublic,
	}
	pending := newFakePendingStore()
	seedPending(pending, "state-1", &PendingAuthState{
		ServerURL:    "https://api.example.com",
		ClientRef:    "tenant-a",
		AccountID:    "acct-1",
		ClientID:     "client-tenant-a",
		CodeVerifier: "verifier-xyz",
		RedirectURI:  "https://app.example.com/callback",
	})
	tokens := newFakeTokenWriter()

	var sentForm url.Values
	do := func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		sentForm, _ = url.ParseQuery(string(body))
		return jsonResponse(tokenResp), nil
	}

	if _, err := handleCallback(context.Background(), do, servers, pending, tokens, clients, "state-1", "auth-code-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sentForm.Get("client_id") != "client-tenant-a" {
		t.Errorf("client_id = %q", sentForm.Get("client_id"))
	}
	if sentForm.Has("client_secret") {
		t.Errorf("public exchange must not send client_secret, got %q", sentForm.Get("client_secret"))
	}
}

// If the looked-up client's ClientID no longer matches the one bound into the
// pending state (e.g. a re-registration rotated it mid-flow), handleCallback
// falls back to public auth: it sends the pending-state client_id only, never a
// stale secret, and does not fail the exchange.
func TestHandleCallback_ClientIDMismatchFallsBack(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer()
	clients := newFakeClientStore()
	// The currently-registered client carries a different (rotated) client_id and
	// a secret; neither must leak into the exchange bound to the old client_id.
	clients.entries[ckey("https://api.example.com", "tenant-a")] = &ClientEntry{
		ClientID: "client-NEW", ClientSecret: "s3cret", ClientType: ClientTypeConfidential,
	}
	pending := newFakePendingStore()
	seedPending(pending, "state-1", &PendingAuthState{
		ServerURL:    "https://api.example.com",
		ClientRef:    "tenant-a",
		AccountID:    "acct-1",
		ClientID:     "client-OLD",
		CodeVerifier: "verifier-xyz",
		RedirectURI:  "https://app.example.com/callback",
	})
	tokens := newFakeTokenWriter()

	var sentForm url.Values
	do := func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		sentForm, _ = url.ParseQuery(string(body))
		return jsonResponse(tokenResp), nil
	}

	if _, err := handleCallback(context.Background(), do, servers, pending, tokens, clients, "state-1", "auth-code-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sentForm.Get("client_id") != "client-OLD" {
		t.Errorf("client_id must come from the pending state on mismatch, got %q", sentForm.Get("client_id"))
	}
	if sentForm.Has("client_secret") {
		t.Errorf("must not send a stale secret on client_id mismatch, got %q", sentForm.Get("client_secret"))
	}
}

func TestNewTokenEntry_ScopeFallback(t *testing.T) {
	ps := &PendingAuthState{Scopes: []string{"read", "write"}}
	tr := &tokenResponse{AccessToken: "at", ExpiresIn: 0}
	entry := newTokenEntry(tr, ps, time.Now())
	if strings.Join(entry.Scopes, ",") != "read,write" {
		t.Errorf("Scopes = %v, want fallback to requested", entry.Scopes)
	}
	if entry.ExpiresAt != 0 {
		t.Errorf("ExpiresAt = %d, want 0 when expires_in is absent", entry.ExpiresAt)
	}
	if entry.State != SessionActive {
		t.Errorf("State = %q", entry.State)
	}
}

// newTokenEntry must capture refresh capability explicitly from the response: a
// refresh token means Refreshable; its absence means NoRefresh, so a later forced
// refresh cannot wrongly revoke a non-refreshable (offline) token.
func TestNewTokenEntry_RefreshPolicy(t *testing.T) {
	ps := &PendingAuthState{Scopes: []string{"read"}}

	withRT := newTokenEntry(&tokenResponse{AccessToken: "at", RefreshToken: "rt"}, ps, time.Now())
	if withRT.RefreshPolicy != RefreshPolicyRefreshable {
		t.Errorf("RefreshPolicy = %d, want Refreshable when a refresh token is present", withRT.RefreshPolicy)
	}

	noRT := newTokenEntry(&tokenResponse{AccessToken: "at"}, ps, time.Now())
	if noRT.RefreshPolicy != RefreshPolicyNoRefresh {
		t.Errorf("RefreshPolicy = %d, want NoRefresh when the response omits a refresh token", noRT.RefreshPolicy)
	}
}
