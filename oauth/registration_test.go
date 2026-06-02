// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/go-core-stack/core/errors"
	coresync "github.com/go-core-stack/core/sync"
)

// --- fakes ---

// fakeClientStore is an in-memory clientStore recording access counts so tests
// can assert idempotency, the double-check, and re-registration behavior. onFind
// is an optional hook invoked with the (1-based) call number before each Find
// resolves, letting a test seed an entry "between" two lookups to simulate a
// lost registration race.
type fakeClientStore struct {
	entries   map[string]*ClientEntry
	findCalls int
	inserts   int
	deletes   int
	onFind    func(call int)
}

func newFakeClientStore() *fakeClientStore {
	return &fakeClientStore{entries: map[string]*ClientEntry{}}
}

func (c *fakeClientStore) Find(_ context.Context, key *ClientKey) (*ClientEntry, error) {
	c.findCalls++
	if c.onFind != nil {
		c.onFind(c.findCalls)
	}
	e, ok := c.entries[key.ServerURL]
	if !ok {
		return nil, errors.Wrapf(errors.NotFound, "no client for %s", key.ServerURL)
	}
	return e, nil
}

func (c *fakeClientStore) Insert(_ context.Context, key *ClientKey, entry *ClientEntry) error {
	c.inserts++
	if _, ok := c.entries[key.ServerURL]; ok {
		return errors.Wrapf(errors.AlreadyExists, "client already exists for %s", key.ServerURL)
	}
	c.entries[key.ServerURL] = entry
	return nil
}

func (c *fakeClientStore) DeleteKey(_ context.Context, key *ClientKey) error {
	c.deletes++
	if _, ok := c.entries[key.ServerURL]; !ok {
		return errors.Wrapf(errors.NotFound, "no client for %s", key.ServerURL)
	}
	delete(c.entries, key.ServerURL)
	return nil
}

// fakeRegistrationLocks is a registrationLocker that records the acquire count
// and retains the issued lock so a test can assert it was released. failWith,
// when set, makes TryAcquire fail. It reuses the package-shared fakeLock
// (declared in reconciler_test.go).
type fakeRegistrationLocks struct {
	acquires int
	lock     *fakeLock
	failWith error
}

func (l *fakeRegistrationLocks) TryAcquire(_ context.Context, _ *RegistrationLockKey) (coresync.Lock, error) {
	l.acquires++
	if l.failWith != nil {
		return nil, l.failWith
	}
	l.lock = &fakeLock{}
	return l.lock, nil
}

// released reports whether the most recently issued lock was closed.
func (l *fakeRegistrationLocks) released() bool {
	return l.lock != nil && l.lock.closed
}

// lockObservingStore wraps a clientStore and reports, at DeleteKey time, whether
// the registration lock was held — so a test can assert delete/register
// atomicity. "held" means the lock has been acquired and not yet released.
type lockObservingStore struct {
	store    *fakeClientStore
	locks    *fakeRegistrationLocks
	onDelete func(lockHeld bool)
}

func (s *lockObservingStore) Find(ctx context.Context, key *ClientKey) (*ClientEntry, error) {
	return s.store.Find(ctx, key)
}

func (s *lockObservingStore) Insert(ctx context.Context, key *ClientKey, entry *ClientEntry) error {
	return s.store.Insert(ctx, key, entry)
}

func (s *lockObservingStore) DeleteKey(ctx context.Context, key *ClientKey) error {
	if s.onDelete != nil {
		s.onDelete(s.locks.acquires > 0 && !s.locks.released())
	}
	return s.store.DeleteKey(ctx, key)
}

// staticDiscover returns a discoverFunc that always yields the given entry.
func staticDiscover(entry *ServerEntry) discoverFunc {
	return func(_ context.Context, _ string) (*ServerEntry, error) {
		return entry, nil
	}
}

const regResp = `{
	"client_id": "client-abc",
	"client_secret": "secret-xyz",
	"client_secret_expires_at": 0,
	"registration_client_uri": "https://as.example.com/register/client-abc",
	"registration_access_token": "rat-123",
	"redirect_uris": ["https://app.example.com/callback"],
	"grant_types": ["authorization_code", "refresh_token"],
	"scope": "read write"
}`

func testConfig() OAuthConfig {
	return OAuthConfig{
		ClientName:  "test-app",
		RedirectURI: "https://app.example.com/callback",
		Scopes:      []string{"read", "write"},
	}
}

func discoveredServer() *ServerEntry {
	return &ServerEntry{
		TokenEndpoint:        "https://as.example.com/token",
		RegistrationEndpoint: "https://as.example.com/register",
	}
}

// --- tests ---

func TestRegisterDynamicClient_HappyPath(t *testing.T) {
	locks := &fakeRegistrationLocks{}
	clients := newFakeClientStore()
	do := func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(regResp), nil
	}

	entry, err := registerDynamicClient(context.Background(), do, clients, locks,
		staticDiscover(discoveredServer()), testConfig(),
		RegisterClientOptions{ServerURL: "https://api.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.ClientID != "client-abc" {
		t.Errorf("client id = %q", entry.ClientID)
	}
	if entry.ClientSecret != "secret-xyz" {
		t.Errorf("client secret = %q", entry.ClientSecret)
	}
	if entry.RegistrationAccessToken != "rat-123" {
		t.Errorf("registration access token = %q", entry.RegistrationAccessToken)
	}
	if entry.ClientType != clientTypePublic {
		t.Errorf("client type = %q, want %q", entry.ClientType, clientTypePublic)
	}
	if entry.RegistrationType != registrationTypeDynamic {
		t.Errorf("registration type = %q, want %q", entry.RegistrationType, registrationTypeDynamic)
	}
	if entry.RegisteredAt == 0 {
		t.Error("RegisteredAt should be set")
	}
	if clients.inserts != 1 {
		t.Errorf("expected 1 insert, got %d", clients.inserts)
	}
	// lock acquired exactly once and released
	if locks.acquires != 1 || !locks.released() {
		t.Errorf("lock acquires=%d released=%v, want 1/true", locks.acquires, locks.released())
	}
	// persisted under the normalized server key
	if clients.entries["https://api.example.com"] == nil {
		t.Errorf("client not persisted under normalized key; keys=%v", clients.entries)
	}
}

// The RFC 7591 request must use the public-client configuration.
func TestRegisterDynamicClient_PublicClientPayload(t *testing.T) {
	locks := &fakeRegistrationLocks{}
	clients := newFakeClientStore()

	var sent clientRegistrationRequest
	var sawPostPath string
	do := func(req *http.Request) (*http.Response, error) {
		sawPostPath = req.URL.Path
		body, _ := io.ReadAll(req.Body)
		if err := json.Unmarshal(body, &sent); err != nil {
			t.Fatalf("request body not JSON: %v", err)
		}
		if ct := req.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		return jsonResponse(regResp), nil
	}

	_, err := registerDynamicClient(context.Background(), do, clients, locks,
		staticDiscover(discoveredServer()), testConfig(),
		RegisterClientOptions{ServerURL: "https://api.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sawPostPath != "/register" {
		t.Errorf("registration POST path = %q, want /register", sawPostPath)
	}
	if sent.TokenEndpointAuthMethod != TokenEndpointAuthMethodNone {
		t.Errorf("token_endpoint_auth_method = %q, want %q", sent.TokenEndpointAuthMethod, TokenEndpointAuthMethodNone)
	}
	if len(sent.ResponseTypes) != 1 || sent.ResponseTypes[0] != responseTypeCode {
		t.Errorf("response_types = %v, want [code]", sent.ResponseTypes)
	}
	if strings.Join(sent.GrantTypes, ",") != "authorization_code,refresh_token" {
		t.Errorf("grant_types = %v", sent.GrantTypes)
	}
	if sent.ClientName != "test-app" {
		t.Errorf("client_name = %q (defaults from config)", sent.ClientName)
	}
	if len(sent.RedirectURIs) != 1 || sent.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Errorf("redirect_uris = %v (defaults from config.RedirectURI)", sent.RedirectURIs)
	}
	if sent.Scope != "read write" {
		t.Errorf("scope = %q", sent.Scope)
	}
}

// On a cache hit the call is idempotent: it returns the existing client without
// taking the lock or making a network call.
func TestRegisterDynamicClient_IdempotentHit(t *testing.T) {
	locks := &fakeRegistrationLocks{}
	clients := newFakeClientStore()
	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "existing"}

	do := func(req *http.Request) (*http.Response, error) {
		t.Fatalf("network call made on idempotent hit: %s", req.URL)
		return nil, nil
	}

	// trailing slash also exercises key normalization on the hit path
	entry, err := registerDynamicClient(context.Background(), do, clients, locks,
		staticDiscover(discoveredServer()), testConfig(),
		RegisterClientOptions{ServerURL: "https://api.example.com/"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.ClientID != "existing" {
		t.Errorf("expected existing client, got %q", entry.ClientID)
	}
	if locks.acquires != 0 {
		t.Errorf("idempotent hit must not acquire the lock; acquires=%d", locks.acquires)
	}
	if clients.inserts != 0 {
		t.Errorf("idempotent hit must not insert; inserts=%d", clients.inserts)
	}
}

// Two replicas both miss the initial cache check and serialize on the lock; the
// one that loses the race must observe the winner's entry on the in-lock
// double-check and return it without registering again.
func TestRegisterDynamicClient_DoubleCheckUnderLock(t *testing.T) {
	locks := &fakeRegistrationLocks{}
	clients := newFakeClientStore()
	// First Find (fast path) misses; before the second Find (inside the lock)
	// resolves, seed the entry as if a peer registered while we waited.
	clients.onFind = func(call int) {
		if call == 2 {
			clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "winner"}
		}
	}

	do := func(req *http.Request) (*http.Response, error) {
		t.Fatalf("network call made though double-check should have short-circuited: %s", req.URL)
		return nil, nil
	}

	entry, err := registerDynamicClient(context.Background(), do, clients, locks,
		staticDiscover(discoveredServer()), testConfig(),
		RegisterClientOptions{ServerURL: "https://api.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.ClientID != "winner" {
		t.Errorf("expected peer-registered client, got %q", entry.ClientID)
	}
	if locks.acquires != 1 {
		t.Errorf("expected lock acquired once, got %d", locks.acquires)
	}
	if !locks.released() {
		t.Error("lock must be released even on the double-check short-circuit")
	}
	if clients.inserts != 0 {
		t.Errorf("double-check hit must not insert; inserts=%d", clients.inserts)
	}
}

// When the per-server lock is held by a peer that has already finished, the
// contended caller must observe the peer's client and return it rather than
// erroring — preserving idempotency under concurrent first-time registration.
func TestRegisterDynamicClient_LockHeldButPeerFinished(t *testing.T) {
	locks := &fakeRegistrationLocks{failWith: errors.Wrap(errors.AlreadyExists, "lock held")}
	clients := newFakeClientStore()
	// The peer's client appears after our fast-path miss: seed it on the second
	// Find (the post-acquire-failure re-check).
	clients.onFind = func(call int) {
		if call == 2 {
			clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "peer"}
		}
	}
	do := func(req *http.Request) (*http.Response, error) {
		t.Fatalf("network call made though a peer already registered: %s", req.URL)
		return nil, nil
	}

	entry, err := registerDynamicClient(context.Background(), do, clients, locks,
		staticDiscover(discoveredServer()), testConfig(),
		RegisterClientOptions{ServerURL: "https://api.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.ClientID != "peer" {
		t.Errorf("expected peer-registered client, got %q", entry.ClientID)
	}
	if clients.inserts != 0 {
		t.Errorf("must not insert when peer already registered; inserts=%d", clients.inserts)
	}
}

// When the lock is held and the peer has not finished yet (no entry on
// re-check), the contended caller must return a retryable error, not register a
// duplicate.
func TestRegisterDynamicClient_LockHeldPeerInFlight(t *testing.T) {
	locks := &fakeRegistrationLocks{failWith: errors.Wrap(errors.AlreadyExists, "lock held")}
	clients := newFakeClientStore()
	do := func(req *http.Request) (*http.Response, error) {
		t.Fatalf("network call made while a peer holds the registration lock: %s", req.URL)
		return nil, nil
	}

	_, err := registerDynamicClient(context.Background(), do, clients, locks,
		staticDiscover(discoveredServer()), testConfig(),
		RegisterClientOptions{ServerURL: "https://api.example.com"})
	if err == nil {
		t.Fatal("expected an error when the registration lock is held and no client exists yet")
	}
	if errors.GetErrCode(err) != errors.AlreadyExists {
		t.Errorf("expected a retryable (AlreadyExists) error on lock contention, got %v", err)
	}
	if clients.inserts != 0 {
		t.Errorf("must not insert while contended; inserts=%d", clients.inserts)
	}
}

func TestRegisterDynamicClient_NoRegistrationEndpoint(t *testing.T) {
	locks := &fakeRegistrationLocks{}
	clients := newFakeClientStore()
	do := func(req *http.Request) (*http.Response, error) {
		t.Fatalf("should not POST when no registration endpoint: %s", req.URL)
		return nil, nil
	}

	_, err := registerDynamicClient(context.Background(), do, clients, locks,
		staticDiscover(&ServerEntry{TokenEndpoint: "https://as.example.com/token"}), testConfig(),
		RegisterClientOptions{ServerURL: "https://api.example.com"})
	if err == nil {
		t.Fatal("expected error when server advertises no registration endpoint")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
	// lock acquired then released even on this error path
	if locks.acquires != 1 || !locks.released() {
		t.Errorf("lock acquires=%d released=%v, want 1/true", locks.acquires, locks.released())
	}
}

func TestReRegisterClient_DeletesThenRegisters(t *testing.T) {
	locks := &fakeRegistrationLocks{}
	clients := newFakeClientStore()
	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "stale"}

	do := func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(regResp), nil
	}

	entry, err := reRegisterClient(context.Background(), do, clients, locks,
		staticDiscover(discoveredServer()), testConfig(),
		RegisterClientOptions{ServerURL: "https://api.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clients.deletes != 1 {
		t.Errorf("expected 1 delete, got %d", clients.deletes)
	}
	if entry.ClientID != "client-abc" {
		t.Errorf("expected freshly-registered client, got %q", entry.ClientID)
	}
	if got := clients.entries["https://api.example.com"]; got == nil || got.ClientID != "client-abc" {
		t.Errorf("re-registered client not persisted; got %v", got)
	}
}

// Re-registration must succeed even when there is no existing client to delete.
func TestReRegisterClient_NoExistingClient(t *testing.T) {
	locks := &fakeRegistrationLocks{}
	clients := newFakeClientStore()
	do := func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(regResp), nil
	}

	entry, err := reRegisterClient(context.Background(), do, clients, locks,
		staticDiscover(discoveredServer()), testConfig(),
		RegisterClientOptions{ServerURL: "https://api.example.com"})
	if err != nil {
		t.Fatalf("unexpected error (delete of absent client must be tolerated): %v", err)
	}
	if entry.ClientID != "client-abc" {
		t.Errorf("expected registered client, got %q", entry.ClientID)
	}
}

// Re-registration must acquire the lock BEFORE deleting, so the delete and the
// fresh registration are atomic.
func TestReRegisterClient_LocksBeforeDeleting(t *testing.T) {
	clients := newFakeClientStore()
	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "stale"}
	// onFind asserts the lock is held before any client mutation; re-register
	// must not consult the cache fast-path, but if the implementation ever did,
	// the lock must already be held.
	locks := &fakeRegistrationLocks{}

	deletedWithLock := false
	clientsHook := &lockObservingStore{store: clients, locks: locks, onDelete: func(held bool) {
		deletedWithLock = held
	}}

	do := func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(regResp), nil
	}

	_, err := reRegisterClient(context.Background(), do, clientsHook, locks,
		staticDiscover(discoveredServer()), testConfig(),
		RegisterClientOptions{ServerURL: "https://api.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if locks.acquires != 1 {
		t.Errorf("expected lock acquired once, got %d", locks.acquires)
	}
	if !deletedWithLock {
		t.Error("delete must happen while the registration lock is held")
	}
	if !locks.released() {
		t.Error("lock must be released")
	}
}

// On lock contention, re-register must fail (retryable) rather than return a
// peer's client or register a duplicate — the delete must not be skipped
// silently.
func TestReRegisterClient_LockContentionFailsRetryable(t *testing.T) {
	locks := &fakeRegistrationLocks{failWith: errors.Wrap(errors.AlreadyExists, "lock held")}
	clients := newFakeClientStore()
	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "stale"}
	do := func(req *http.Request) (*http.Response, error) {
		t.Fatalf("network call made while the lock is held: %s", req.URL)
		return nil, nil
	}

	_, err := reRegisterClient(context.Background(), do, clients, locks,
		staticDiscover(discoveredServer()), testConfig(),
		RegisterClientOptions{ServerURL: "https://api.example.com"})
	if err == nil {
		t.Fatal("expected a retryable error on lock contention")
	}
	if errors.GetErrCode(err) != errors.AlreadyExists {
		t.Errorf("expected a retryable (AlreadyExists) error on lock contention, got %v", err)
	}
	if clients.deletes != 0 {
		t.Errorf("must not delete when the lock could not be acquired; deletes=%d", clients.deletes)
	}
	if clients.inserts != 0 {
		t.Errorf("must not register when the lock could not be acquired; inserts=%d", clients.inserts)
	}
}

func TestGetClient_HitAndMiss(t *testing.T) {
	clients := newFakeClientStore()

	got, err := getClient(context.Background(), clients, "https://api.example.com/")
	if err != nil {
		t.Fatalf("unexpected error on miss: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil on miss, got %v", got)
	}

	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "client-abc"}
	got, err = getClient(context.Background(), clients, "https://api.example.com")
	if err != nil {
		t.Fatalf("unexpected error on hit: %v", err)
	}
	if got == nil || got.ClientID != "client-abc" {
		t.Errorf("expected stored client, got %v", got)
	}
}

func TestRegisterStaticClient_Unimplemented(t *testing.T) {
	m := &OAuthManager{}
	err := m.RegisterStaticClient(context.Background(), "https://api.example.com", ClientEntry{})
	if err == nil {
		t.Fatal("expected an error from the static-registration stub")
	}
	if !errors.Is(err, errStaticRegistrationUnimplemented) {
		t.Errorf("expected errStaticRegistrationUnimplemented, got %v", err)
	}
}

func TestMergeRegisterOptions_DefaultsAndOverrides(t *testing.T) {
	cfg := testConfig()

	// empty opts -> all defaults from config
	got := mergeRegisterOptions(cfg, RegisterClientOptions{ServerURL: "https://api.example.com"})
	if got.ClientName != "test-app" {
		t.Errorf("ClientName = %q", got.ClientName)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Errorf("RedirectURIs = %v", got.RedirectURIs)
	}
	if strings.Join(got.Scopes, ",") != "read,write" {
		t.Errorf("Scopes = %v", got.Scopes)
	}

	// explicit opts win over config
	got = mergeRegisterOptions(cfg, RegisterClientOptions{
		ServerURL:    "https://api.example.com",
		ClientName:   "custom",
		RedirectURIs: []string{"https://other/cb"},
		Scopes:       []string{"openid"},
	})
	if got.ClientName != "custom" {
		t.Errorf("override ClientName = %q", got.ClientName)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://other/cb" {
		t.Errorf("override RedirectURIs = %v", got.RedirectURIs)
	}
	if strings.Join(got.Scopes, ",") != "openid" {
		t.Errorf("override Scopes = %v", got.Scopes)
	}
}
