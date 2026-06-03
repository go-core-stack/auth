// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-core-stack/core/errors"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// --- fakes ---

// fakeTokenStore is an in-memory tokenStore recording access counts so tests can
// assert persistence, deletion, and listing. Find returns a copy so a caller
// mutating the result does not leak into the store before Update.
type fakeTokenStore struct {
	entries     map[TokenKey]*TokenEntry
	findCalls   int
	updateCalls int
	deleteCalls int
	lastFilter  any
	deleteErr   error
}

func newFakeTokenStore() *fakeTokenStore {
	return &fakeTokenStore{entries: map[TokenKey]*TokenEntry{}}
}

func (f *fakeTokenStore) Find(_ context.Context, key *TokenKey) (*TokenEntry, error) {
	f.findCalls++
	e, ok := f.entries[*key]
	if !ok {
		return nil, errors.Wrap(errors.NotFound, "token not found")
	}
	cp := *e
	return &cp, nil
}

func (f *fakeTokenStore) Update(_ context.Context, key *TokenKey, entry *TokenEntry) error {
	f.updateCalls++
	cp := *entry
	f.entries[*key] = &cp
	return nil
}

func (f *fakeTokenStore) DeleteKey(_ context.Context, key *TokenKey) error {
	f.deleteCalls++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if _, ok := f.entries[*key]; !ok {
		return errors.Wrap(errors.NotFound, "token not found")
	}
	delete(f.entries, *key)
	return nil
}

func (f *fakeTokenStore) FindMany(_ context.Context, filter any, _, _ int32) ([]*TokenEntry, error) {
	f.lastFilter = filter
	want, byServer := "", false
	if m, ok := filter.(bson.M); ok {
		if s, ok := m["_id.serverUrl"].(string); ok {
			want, byServer = s, true
		}
	}
	var out []*TokenEntry
	for k, e := range f.entries {
		if byServer && k.ServerURL != want {
			continue
		}
		cp := *e
		out = append(out, &cp)
	}
	return out, nil
}

// jsonStatusResponse builds a JSON HTTP response with an explicit status code.
func jsonStatusResponse(code int, body string) *http.Response {
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func testTokenKey() *TokenKey {
	return &TokenKey{ServerURL: "https://api.example.com", AccountID: "acct-1"}
}

// revServer returns a discovered server with token and revocation endpoints.
func revServer() *ServerEntry {
	return &ServerEntry{
		AuthorizationEndpoint: "https://as.example.com/authorize",
		TokenEndpoint:         "https://as.example.com/token",
		RevocationEndpoint:    "https://as.example.com/revoke",
	}
}

// --- GetToken / RefreshToken (lock-guarded) ---

func TestGetToken_HealthyReturnsAsIs(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[*testTokenKey()] = &TokenEntry{
		AccessToken: "at", State: SessionActive, ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	locks := &fakeLocker{}

	got, err := getToken(context.Background(), tokens, locks, failRefresh(t), "https://api.example.com/", "acct-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AccessToken != "at" {
		t.Errorf("AccessToken = %q", got.AccessToken)
	}
	if locks.acquired != 0 {
		t.Errorf("a healthy token must not acquire the refresh lock")
	}
}

func TestGetToken_NearExpiryRefreshes(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[*testTokenKey()] = &TokenEntry{
		AccessToken: "old", RefreshToken: "rt", State: SessionActive,
		ExpiresAt: time.Now().Add(time.Minute).Unix(), // within RefreshThreshold
	}
	locks := &fakeLocker{}
	refreshed := &TokenEntry{AccessToken: "new", State: SessionActive, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	refresh := func(_ context.Context, _ *TokenKey, _ *TokenEntry) (*TokenEntry, error) { return refreshed, nil }

	got, err := getToken(context.Background(), tokens, locks, refresh, "https://api.example.com", "acct-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AccessToken != "new" {
		t.Errorf("expected refreshed token, got %q", got.AccessToken)
	}
	if tokens.updateCalls != 1 || tokens.entries[*testTokenKey()].AccessToken != "new" {
		t.Errorf("refreshed token must be persisted")
	}
	if locks.lock == nil || !locks.lock.closed {
		t.Errorf("refresh lock must be acquired and released")
	}
}

func TestGetToken_NotFound(t *testing.T) {
	tokens := newFakeTokenStore()
	_, err := getToken(context.Background(), tokens, &fakeLocker{}, failRefresh(t), "https://api.example.com", "acct-1")
	if !errors.IsNotFound(err) {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

func TestGetToken_RevokedReturnedAsIs(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[*testTokenKey()] = &TokenEntry{
		State: SessionRevoked, ExpiresAt: time.Now().Add(-time.Hour).Unix(),
	}
	locks := &fakeLocker{}

	got, err := getToken(context.Background(), tokens, locks, failRefresh(t), "https://api.example.com", "acct-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.State != SessionRevoked {
		t.Errorf("expected revoked token returned as-is, got %q", got.State)
	}
	if locks.acquired != 0 {
		t.Errorf("a revoked token must not be refreshed")
	}
}

func TestRefreshToken_ForcesRefreshOnHealthyToken(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[*testTokenKey()] = &TokenEntry{
		AccessToken: "old", State: SessionActive, ExpiresAt: time.Now().Add(time.Hour).Unix(), // healthy
	}
	locks := &fakeLocker{}
	called := false
	refresh := func(_ context.Context, _ *TokenKey, _ *TokenEntry) (*TokenEntry, error) {
		called = true
		return &TokenEntry{AccessToken: "new", State: SessionActive}, nil
	}

	got, err := forceRefresh(context.Background(), tokens, locks, refresh, "https://api.example.com", "acct-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("forced refresh must call refresh even for a healthy token")
	}
	if got.AccessToken != "new" || tokens.entries[*testTokenKey()].AccessToken != "new" {
		t.Errorf("forced refresh result must be returned and persisted")
	}
}

func TestLockedRefresh_PermanentRevokes(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[*testTokenKey()] = &TokenEntry{AccessToken: "old", RefreshToken: "rt", State: SessionActive}
	locks := &fakeLocker{}
	permanent := fmt.Errorf("server said no: %w", errPermanentRefresh)
	refresh := func(_ context.Context, _ *TokenKey, _ *TokenEntry) (*TokenEntry, error) { return nil, permanent }

	_, err := lockedRefresh(context.Background(), tokens, locks, refresh, testTokenKey(), true)
	if !errors.Is(err, errPermanentRefresh) {
		t.Fatalf("expected permanent refresh error surfaced, got %v", err)
	}
	stored := tokens.entries[*testTokenKey()]
	if stored.State != SessionRevoked || stored.ErrorReason == "" {
		t.Errorf("permanent failure must persist revoked state with a reason, got %+v", stored)
	}
}

func TestLockedRefresh_TransientFailsAndKeepsToken(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[*testTokenKey()] = &TokenEntry{AccessToken: "old", RefreshToken: "rt", State: SessionActive}
	locks := &fakeLocker{}
	transient := errors.Wrap(errors.Unknown, "network blip")
	refresh := func(_ context.Context, _ *TokenKey, _ *TokenEntry) (*TokenEntry, error) { return nil, transient }

	_, err := lockedRefresh(context.Background(), tokens, locks, refresh, testTokenKey(), true)
	if err == nil || errors.Is(err, errPermanentRefresh) {
		t.Fatalf("expected a transient (non-permanent) error, got %v", err)
	}
	stored := tokens.entries[*testTokenKey()]
	if stored.State != SessionFailed {
		t.Errorf("transient failure must mark state failed, got %q", stored.State)
	}
	if stored.AccessToken != "old" {
		t.Errorf("transient failure must keep the existing token, got %q", stored.AccessToken)
	}
}

func TestLockedRefresh_LockContention(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[*testTokenKey()] = &TokenEntry{State: SessionActive, RefreshToken: "rt"}
	locks := &fakeLocker{acquireErr: errors.Wrap(errors.AlreadyExists, "held")}

	_, err := lockedRefresh(context.Background(), tokens, locks, failRefresh(t), testTokenKey(), true)
	if err == nil {
		t.Fatal("expected error when the refresh lock is contended")
	}
}

// Under the lock, a token another replica already refreshed (no longer near
// expiry) must not be refreshed again on the non-forced path.
func TestLockedRefresh_ConcurrentRereadSkips(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[*testTokenKey()] = &TokenEntry{
		AccessToken: "fresh", State: SessionActive, ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	locks := &fakeLocker{}

	got, err := lockedRefresh(context.Background(), tokens, locks, failRefresh(t), testTokenKey(), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AccessToken != "fresh" {
		t.Errorf("expected the already-fresh token, got %q", got.AccessToken)
	}
	if locks.lock == nil || !locks.lock.closed {
		t.Errorf("lock must still be acquired and released around the re-read")
	}
	if tokens.updateCalls != 0 {
		t.Errorf("no refresh/update should occur when the re-read is fresh")
	}
}

// A session revoked between the caller's initial read and the locked re-read
// must not be refreshed back to life — even on the forced path — so a
// still-accepted refresh token can't undo a local revocation.
func TestLockedRefresh_RevokedSkipsEvenWhenForced(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[*testTokenKey()] = &TokenEntry{
		AccessToken: "old", RefreshToken: "rt", State: SessionRevoked,
	}
	locks := &fakeLocker{}

	got, err := lockedRefresh(context.Background(), tokens, locks, failRefresh(t), testTokenKey(), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.State != SessionRevoked {
		t.Errorf("revoked session must be returned as-is, got state %q", got.State)
	}
	if tokens.updateCalls != 0 {
		t.Errorf("revoked session must not be persisted/refreshed, got %d updates", tokens.updateCalls)
	}
}

// A RevokeToken that lands *during* the network-bound exchange (RevokeToken does
// not hold the refresh lock) must win: a successful refresh response arriving
// last must not resurrect the just-revoked session. The refresh callback here
// simulates that concurrent revoke by persisting SessionRevoked mid-exchange.
func TestLockedRefresh_RevokeDuringExchangeWins(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[*testTokenKey()] = &TokenEntry{
		AccessToken: "old", RefreshToken: "rt", State: SessionActive,
		ExpiresAt: time.Now().Add(time.Minute).Unix(), // within RefreshThreshold
	}
	locks := &fakeLocker{}
	// Simulate a concurrent RevokeToken completing while the exchange is in
	// flight, then return a successful refresh as if the token endpoint accepted
	// the still-valid refresh token.
	refresh := func(_ context.Context, key *TokenKey, _ *TokenEntry) (*TokenEntry, error) {
		revoked := &TokenEntry{AccessToken: "old", RefreshToken: "rt", State: SessionRevoked}
		if err := tokens.Update(context.Background(), key, revoked); err != nil {
			t.Fatalf("seed revoke: %v", err)
		}
		return &TokenEntry{AccessToken: "new", State: SessionActive, ExpiresAt: time.Now().Add(time.Hour).Unix()}, nil
	}

	got, err := lockedRefresh(context.Background(), tokens, locks, refresh, testTokenKey(), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.State != SessionRevoked {
		t.Errorf("revoke landing mid-exchange must win, got state %q", got.State)
	}
	if got.AccessToken != "old" {
		t.Errorf("refreshed token must be discarded, got %q", got.AccessToken)
	}
	if stored := tokens.entries[*testTokenKey()]; stored.State != SessionRevoked || stored.AccessToken != "old" {
		t.Errorf("store must retain the revoked entry, got state %q token %q", stored.State, stored.AccessToken)
	}
}

// --- refresh exchange + error classification ---

func TestRefreshTokenExchange_Success(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = revServer()
	clients := newFakeClientStore()
	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "client-abc"}

	var sentForm url.Values
	do := func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		sentForm, _ = url.ParseQuery(string(body))
		return jsonResponse(tokenResp), nil
	}

	prev := &TokenEntry{AccessToken: "old", RefreshToken: "rt-old", Scopes: []string{"read", "write"}, State: SessionFailed}
	got, err := refreshTokenExchange(context.Background(), do, servers, clients, testTokenKey(), prev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// request shape (RFC 6749 §6)
	if sentForm.Get("grant_type") != grantTypeRefreshToken {
		t.Errorf("grant_type = %q", sentForm.Get("grant_type"))
	}
	if sentForm.Get("refresh_token") != "rt-old" {
		t.Errorf("refresh_token = %q", sentForm.Get("refresh_token"))
	}
	if sentForm.Get("client_id") != "client-abc" {
		t.Errorf("client_id = %q", sentForm.Get("client_id"))
	}
	// scope is intentionally omitted on refresh (RFC 6749 §6: omitted => keep the
	// originally granted scope) to avoid servers that reject an explicit scope.
	if sentForm.Has("scope") {
		t.Errorf("scope must not be sent on refresh, got %q", sentForm.Get("scope"))
	}

	// refreshed token
	if got.AccessToken != "at-123" {
		t.Errorf("AccessToken = %q", got.AccessToken)
	}
	if got.RefreshToken != "rt-456" {
		t.Errorf("RefreshToken should update from the response, got %q", got.RefreshToken)
	}
	if got.State != SessionActive {
		t.Errorf("State = %q, want active", got.State)
	}
	if got.ErrorReason != "" {
		t.Errorf("ErrorReason should clear on success, got %q", got.ErrorReason)
	}
	if got.ExpiresAt == 0 || got.LastRefresh == 0 {
		t.Errorf("ExpiresAt/LastRefresh must be set: %+v", got)
	}
}

// A refresh response that omits refresh_token must retain the prior one.
func TestRefreshTokenExchange_KeepsPriorRefreshToken(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = revServer()
	clients := newFakeClientStore()
	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "client-abc"}

	do := func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(`{"access_token":"at-new","token_type":"Bearer","expires_in":3600}`), nil
	}
	prev := &TokenEntry{AccessToken: "old", RefreshToken: "rt-keep", State: SessionActive}
	got, err := refreshTokenExchange(context.Background(), do, servers, clients, testTokenKey(), prev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.RefreshToken != "rt-keep" {
		t.Errorf("expected prior refresh token retained, got %q", got.RefreshToken)
	}
}

// A refresh response that omits expires_in must reset ExpiresAt (unknown =
// non-expiring), not inherit the prior token's now-stale expiry — which would
// make the refreshed token look already-expired and drive a tight re-refresh
// loop.
func TestRefreshTokenExchange_MissingExpiresInResetsExpiry(t *testing.T) {
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = revServer()
	clients := newFakeClientStore()
	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "client-abc"}

	do := func(_ *http.Request) (*http.Response, error) {
		// no expires_in in the response
		return jsonResponse(`{"access_token":"at-new","token_type":"Bearer"}`), nil
	}
	stalePast := time.Now().Add(-time.Hour).Unix()
	prev := &TokenEntry{AccessToken: "old", RefreshToken: "rt", State: SessionActive, ExpiresAt: stalePast}

	got, err := refreshTokenExchange(context.Background(), do, servers, clients, testTokenKey(), prev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ExpiresAt != 0 {
		t.Errorf("ExpiresAt must reset to 0 when expires_in is absent, got %d (stale prior was %d)", got.ExpiresAt, stalePast)
	}
	if tokenNeedsRefresh(got, time.Now()) {
		t.Error("a refreshed token with unknown expiry must not be immediately due for refresh")
	}
}

func TestRefreshTokenExchange_NoRefreshTokenIsPermanent(t *testing.T) {
	servers := newFakeServerCache()
	clients := newFakeClientStore()
	do := func(req *http.Request) (*http.Response, error) {
		t.Fatalf("must not call the network without a refresh token: %s", req.URL)
		return nil, nil
	}
	prev := &TokenEntry{AccessToken: "old", State: SessionActive} // no RefreshToken
	_, err := refreshTokenExchange(context.Background(), do, servers, clients, testTokenKey(), prev)
	if !errors.Is(err, errPermanentRefresh) {
		t.Fatalf("a missing refresh token must be a permanent failure, got %v", err)
	}
}

func TestRefreshTokenExchange_InvalidGrantIsPermanent(t *testing.T) {
	assertRefreshClassification(t, http.StatusBadRequest, `{"error":"invalid_grant"}`, true)
}

func TestRefreshTokenExchange_InvalidClientIsPermanent(t *testing.T) {
	assertRefreshClassification(t, http.StatusUnauthorized, `{"error":"invalid_client","error_description":"bad client"}`, true)
}

func TestRefreshTokenExchange_TemporaryIsTransient(t *testing.T) {
	assertRefreshClassification(t, http.StatusServiceUnavailable, `{"error":"temporarily_unavailable"}`, false)
}

func TestRefreshTokenExchange_ServerErrorIsTransient(t *testing.T) {
	assertRefreshClassification(t, http.StatusInternalServerError, ``, false)
}

// assertRefreshClassification drives refreshTokenExchange against a token
// endpoint that returns the given status/body and asserts whether the resulting
// error is classified permanent (errPermanentRefresh) or transient.
func assertRefreshClassification(t *testing.T, status int, body string, wantPermanent bool) {
	t.Helper()
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = revServer()
	clients := newFakeClientStore()
	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "client-abc"}
	do := func(_ *http.Request) (*http.Response, error) { return jsonStatusResponse(status, body), nil }

	prev := &TokenEntry{RefreshToken: "rt", State: SessionActive}
	_, err := refreshTokenExchange(context.Background(), do, servers, clients, testTokenKey(), prev)
	if err == nil {
		t.Fatalf("expected an error for HTTP %d", status)
	}
	if got := errors.Is(err, errPermanentRefresh); got != wantPermanent {
		t.Errorf("permanent=%v for HTTP %d (%q), want %v (err=%v)", got, status, body, wantPermanent, err)
	}
}

// --- revoke ---

func TestRevokeToken_Success(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[*testTokenKey()] = &TokenEntry{AccessToken: "at", RefreshToken: "rt", State: SessionActive}
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = revServer()
	clients := newFakeClientStore()
	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "client-abc"}

	var sentForm url.Values
	var sawURL string
	do := func(req *http.Request) (*http.Response, error) {
		sawURL = req.URL.String()
		body, _ := io.ReadAll(req.Body)
		sentForm, _ = url.ParseQuery(string(body))
		return statusResponse(http.StatusOK), nil
	}

	if err := revokeToken(context.Background(), tokens, do, servers, clients, "https://api.example.com", "acct-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sawURL != "https://as.example.com/revoke" {
		t.Errorf("revocation posted to %q", sawURL)
	}
	if sentForm.Get("token") != "rt" || sentForm.Get("token_type_hint") != tokenTypeHintRefresh {
		t.Errorf("expected refresh token revoked, form=%v", sentForm)
	}
	if sentForm.Get("client_id") != "client-abc" {
		t.Errorf("client_id = %q", sentForm.Get("client_id"))
	}
	if tokens.entries[*testTokenKey()].State != SessionRevoked {
		t.Errorf("token must be marked revoked locally")
	}
}

// An already-revoked session is a no-op: no server call and no persistence
// round-trip.
func TestRevokeToken_AlreadyRevokedIsNoOp(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[*testTokenKey()] = &TokenEntry{RefreshToken: "rt", State: SessionRevoked}
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = revServer()
	clients := newFakeClientStore()
	do := func(_ *http.Request) (*http.Response, error) {
		t.Fatal("already-revoked session must not call the server")
		return nil, nil
	}

	if err := revokeToken(context.Background(), tokens, do, servers, clients, "https://api.example.com", "acct-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokens.updateCalls != 0 {
		t.Errorf("already-revoked session must not persist, got %d updates", tokens.updateCalls)
	}
}

// A failing server call must still mark the token revoked locally and surface
// the server error.
func TestRevokeToken_ServerFailureStillRevokesLocally(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[*testTokenKey()] = &TokenEntry{RefreshToken: "rt", State: SessionActive}
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = revServer()
	clients := newFakeClientStore()
	do := func(_ *http.Request) (*http.Response, error) {
		return statusResponse(http.StatusInternalServerError), nil
	}

	err := revokeToken(context.Background(), tokens, do, servers, clients, "https://api.example.com", "acct-1")
	if err == nil {
		t.Fatal("expected the server error to be surfaced")
	}
	stored := tokens.entries[*testTokenKey()]
	if stored.State != SessionRevoked || stored.ErrorReason == "" {
		t.Errorf("token must be revoked locally with the server error recorded, got %+v", stored)
	}
}

func TestRevokeToken_NoRevocationEndpoint(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[*testTokenKey()] = &TokenEntry{RefreshToken: "rt", State: SessionActive}
	servers := newFakeServerCache()
	servers.entries["https://api.example.com"] = authServer() // no revocation endpoint
	clients := newFakeClientStore()
	do := func(req *http.Request) (*http.Response, error) {
		t.Fatalf("must not call the network without a revocation endpoint: %s", req.URL)
		return nil, nil
	}

	err := revokeToken(context.Background(), tokens, do, servers, clients, "https://api.example.com", "acct-1")
	if err == nil {
		t.Fatal("expected an error when no revocation endpoint is advertised")
	}
	if tokens.entries[*testTokenKey()].State != SessionRevoked {
		t.Errorf("token must still be revoked locally")
	}
}

func TestRevokeToken_NotFound(t *testing.T) {
	tokens := newFakeTokenStore()
	do := func(_ *http.Request) (*http.Response, error) { return statusResponse(http.StatusOK), nil }
	err := revokeToken(context.Background(), tokens, do, newFakeServerCache(), newFakeClientStore(), "https://api.example.com", "acct-1")
	if !errors.IsNotFound(err) {
		t.Fatalf("expected NotFound for a missing token, got %v", err)
	}
}

// --- delete / session state / list ---

func TestDeleteToken_IdempotentAndRemoves(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[*testTokenKey()] = &TokenEntry{State: SessionActive}

	if err := deleteToken(context.Background(), tokens, "https://api.example.com", "acct-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := tokens.entries[*testTokenKey()]; ok {
		t.Error("token must be removed")
	}
	// deleting again is not an error (idempotent)
	if err := deleteToken(context.Background(), tokens, "https://api.example.com", "acct-1"); err != nil {
		t.Errorf("delete of a missing token must be idempotent, got %v", err)
	}
}

func TestGetSessionState(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[*testTokenKey()] = &TokenEntry{State: SessionFailed}

	st, err := getSessionState(context.Background(), tokens, "https://api.example.com", "acct-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st != SessionFailed {
		t.Errorf("state = %q, want %q", st, SessionFailed)
	}

	if _, err := getSessionState(context.Background(), tokens, "https://api.example.com", "missing"); !errors.IsNotFound(err) {
		t.Errorf("expected NotFound for missing token, got %v", err)
	}
}

func TestListTokens_AllAndByServer(t *testing.T) {
	tokens := newFakeTokenStore()
	tokens.entries[TokenKey{ServerURL: "https://api.example.com", AccountID: "a"}] = &TokenEntry{AccessToken: "1"}
	tokens.entries[TokenKey{ServerURL: "https://api.example.com", AccountID: "b"}] = &TokenEntry{AccessToken: "2"}
	tokens.entries[TokenKey{ServerURL: "https://other.example.com", AccountID: "c"}] = &TokenEntry{AccessToken: "3"}

	all, err := listTokens(context.Background(), tokens, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected all 3 tokens, got %d", len(all))
	}
	if tokens.lastFilter == nil {
		t.Error("expected a filter to be passed")
	}

	byServer, err := listTokens(context.Background(), tokens, "https://api.example.com/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(byServer) != 2 {
		t.Errorf("expected 2 tokens for the server, got %d", len(byServer))
	}
	if m, ok := tokens.lastFilter.(bson.M); !ok || m["_id.serverUrl"] != "https://api.example.com" {
		t.Errorf("expected a normalized server filter, got %v", tokens.lastFilter)
	}
}

func TestTokenKeyFor_Validation(t *testing.T) {
	if _, err := tokenKeyFor("", "acct"); !errors.IsInvalidArgument(err) {
		t.Errorf("empty serverURL: expected InvalidArgument, got %v", err)
	}
	if _, err := tokenKeyFor("https://api.example.com", "  "); !errors.IsInvalidArgument(err) {
		t.Errorf("blank accountID: expected InvalidArgument, got %v", err)
	}
	key, err := tokenKeyFor("https://api.example.com/", "acct")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key.ServerURL != "https://api.example.com" {
		t.Errorf("serverURL not normalized: %q", key.ServerURL)
	}
}
