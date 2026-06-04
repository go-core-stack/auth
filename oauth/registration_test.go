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
	locates   int
	deletes   int
	onFind    func(call int)
}

func newFakeClientStore() *fakeClientStore {
	return &fakeClientStore{entries: map[string]*ClientEntry{}}
}

// ckey is the map key the fake uses to model the composite (ServerURL,
// ClientRef) primary key. An empty ClientRef (the dynamic slot) maps to the bare
// ServerURL so existing dynamic-only tests keep indexing entries by URL.
func ckey(serverURL, clientRef string) string {
	if clientRef == "" {
		return serverURL
	}
	return serverURL + "\x00" + clientRef
}

func (c *fakeClientStore) Find(_ context.Context, key *ClientKey) (*ClientEntry, error) {
	c.findCalls++
	if c.onFind != nil {
		c.onFind(c.findCalls)
	}
	e, ok := c.entries[ckey(key.ServerURL, key.ClientRef)]
	if !ok {
		return nil, errors.Wrapf(errors.NotFound, "no client for %s", key.ServerURL)
	}
	return e, nil
}

func (c *fakeClientStore) Insert(_ context.Context, key *ClientKey, entry *ClientEntry) error {
	c.inserts++
	k := ckey(key.ServerURL, key.ClientRef)
	if _, ok := c.entries[k]; ok {
		return errors.Wrapf(errors.AlreadyExists, "client already exists for %s", key.ServerURL)
	}
	c.entries[k] = entry
	return nil
}

func (c *fakeClientStore) Locate(_ context.Context, key *ClientKey, entry *ClientEntry) error {
	c.locates++
	c.entries[ckey(key.ServerURL, key.ClientRef)] = entry
	return nil
}

func (c *fakeClientStore) DeleteKey(_ context.Context, key *ClientKey) error {
	c.deletes++
	k := ckey(key.ServerURL, key.ClientRef)
	if _, ok := c.entries[k]; !ok {
		return errors.Wrapf(errors.NotFound, "no client for %s", key.ServerURL)
	}
	delete(c.entries, k)
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

func (s *lockObservingStore) Locate(ctx context.Context, key *ClientKey, entry *ClientEntry) error {
	return s.store.Locate(ctx, key, entry)
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
	if entry.ClientType != ClientTypePublic {
		t.Errorf("client type = %d, want %d", entry.ClientType, ClientTypePublic)
	}
	if entry.RegistrationType != RegistrationTypeDynamic {
		t.Errorf("registration type = %d, want %d", entry.RegistrationType, RegistrationTypeDynamic)
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

	got, err := getClient(context.Background(), clients, "https://api.example.com/", "")
	if err != nil {
		t.Fatalf("unexpected error on miss: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil on miss, got %v", got)
	}

	clients.entries["https://api.example.com"] = &ClientEntry{ClientID: "client-abc"}
	got, err = getClient(context.Background(), clients, "https://api.example.com", "")
	if err != nil {
		t.Fatalf("unexpected error on hit: %v", err)
	}
	if got == nil || got.ClientID != "client-abc" {
		t.Errorf("expected stored client, got %v", got)
	}
}

// GetClient must resolve by (serverURL, clientRef): looking up a clientRef that
// was never stored is a miss even when another clientRef exists for the server.
func TestGetClient_DistinguishesByClientRef(t *testing.T) {
	clients := newFakeClientStore()
	clients.entries[ckey("https://api.example.com", "tenant-a")] = &ClientEntry{ClientID: "client-a"}

	got, err := getClient(context.Background(), clients, "https://api.example.com", "tenant-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.ClientID != "client-a" {
		t.Errorf("expected tenant-a client, got %v", got)
	}

	got, err = getClient(context.Background(), clients, "https://api.example.com", "tenant-b")
	if err != nil {
		t.Fatalf("unexpected error on miss: %v", err)
	}
	if got != nil {
		t.Errorf("expected miss for unregistered clientRef, got %v", got)
	}
}

// Static registration must reject an empty clientRef: "" is reserved for the
// dynamic client slot.
func TestRegisterStaticClient_EmptyClientRefRejected(t *testing.T) {
	clients := newFakeClientStore()

	err := registerStaticClient(context.Background(), clients, "https://api.example.com", "", ClientEntry{ClientID: "x"})
	if err == nil {
		t.Fatal("expected an error when clientRef is empty")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
	if clients.locates != 0 || clients.inserts != 0 {
		t.Errorf("must not persist on rejection; locates=%d inserts=%d", clients.locates, clients.inserts)
	}
}

// Static registration must reject a server URL that normalizes to empty (e.g.
// whitespace-only): a non-empty clientRef alone is not enough to provision.
func TestRegisterStaticClient_EmptyServerURLRejected(t *testing.T) {
	clients := newFakeClientStore()

	err := registerStaticClient(context.Background(), clients, "   ", "tenant-a", ClientEntry{ClientID: "x"})
	if err == nil {
		t.Fatal("expected an error when serverURL normalizes to empty")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
	if clients.locates != 0 || clients.inserts != 0 {
		t.Errorf("must not persist on rejection; locates=%d inserts=%d", clients.locates, clients.inserts)
	}
}

// A successful static registration normalizes the server URL, stamps static
// metadata, and upserts the consumer-supplied entry under (ServerURL, ClientRef).
func TestRegisterStaticClient_SetsMetadataAndUpserts(t *testing.T) {
	clients := newFakeClientStore()

	// trailing slash exercises normalization on the write path
	err := registerStaticClient(context.Background(), clients, "https://api.example.com/", "tenant-a",
		ClientEntry{ClientID: "static-id", ClientSecret: "shh", ClientType: ClientTypeConfidential})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stored := clients.entries[ckey("https://api.example.com", "tenant-a")]
	if stored == nil {
		t.Fatalf("client not persisted under normalized (server, clientRef) key; keys=%v", clients.entries)
	}
	if stored.RegistrationType != RegistrationTypeStatic {
		t.Errorf("registration type = %d, want %d", stored.RegistrationType, RegistrationTypeStatic)
	}
	if stored.RegisteredAt == 0 {
		t.Error("RegisteredAt should be set")
	}
	// Secret present -> derived confidential (the consumer value happens to agree).
	if stored.ClientType != ClientTypeConfidential {
		t.Errorf("ClientType = %d, want derived %d", stored.ClientType, ClientTypeConfidential)
	}
	if stored.ClientID != "static-id" || stored.ClientSecret != "shh" {
		t.Errorf("consumer-supplied credentials not preserved: %+v", stored)
	}

	// Locate is an upsert: re-registering the same ref must not error.
	if err := registerStaticClient(context.Background(), clients, "https://api.example.com", "tenant-a",
		ClientEntry{ClientID: "rotated", ClientSecret: "shh2", ClientType: ClientTypeConfidential}); err != nil {
		t.Fatalf("re-provisioning a static client must succeed: %v", err)
	}
	if got := clients.entries[ckey("https://api.example.com", "tenant-a")]; got == nil || got.ClientID != "rotated" {
		t.Errorf("re-provision did not replace the entry; got %v", got)
	}
}

// A non-empty ClientSecret derives ClientTypeConfidential.
func TestRegisterStaticClient_DerivesConfidentialFromSecret(t *testing.T) {
	clients := newFakeClientStore()

	// No ClientType supplied; it must be derived from the secret's presence.
	if err := registerStaticClient(context.Background(), clients, "https://api.example.com", "tenant-a",
		ClientEntry{ClientID: "id", ClientSecret: "shh"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stored := clients.entries[ckey("https://api.example.com", "tenant-a")]
	if stored == nil {
		t.Fatalf("client not persisted; keys=%v", clients.entries)
	}
	if stored.ClientType != ClientTypeConfidential {
		t.Errorf("ClientType = %d, want %d (confidential)", stored.ClientType, ClientTypeConfidential)
	}
}

// An empty or whitespace-only ClientSecret derives ClientTypePublic.
func TestRegisterStaticClient_DerivesPublicFromBlankSecret(t *testing.T) {
	cases := map[string]string{
		"empty secret":      "",
		"whitespace secret": "   \t ",
	}
	for name, secret := range cases {
		t.Run(name, func(t *testing.T) {
			clients := newFakeClientStore()
			if err := registerStaticClient(context.Background(), clients, "https://api.example.com", "tenant-a",
				ClientEntry{ClientID: "id", ClientSecret: secret}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			stored := clients.entries[ckey("https://api.example.com", "tenant-a")]
			if stored == nil {
				t.Fatalf("client not persisted; keys=%v", clients.entries)
			}
			if stored.ClientType != ClientTypePublic {
				t.Errorf("ClientType = %d, want %d (public)", stored.ClientType, ClientTypePublic)
			}
		})
	}
}

// The derived ClientType is authoritative: a consumer-supplied ClientType must
// not override it, in either direction.
func TestRegisterStaticClient_ConsumerClientTypeIgnored(t *testing.T) {
	// Consumer claims confidential but provides no secret -> derived public.
	clients := newFakeClientStore()
	if err := registerStaticClient(context.Background(), clients, "https://api.example.com", "tenant-a",
		ClientEntry{ClientID: "id", ClientType: ClientTypeConfidential}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stored := clients.entries[ckey("https://api.example.com", "tenant-a")]
	if stored == nil || stored.ClientType != ClientTypePublic {
		t.Errorf("ClientType = %v, want %d (public, ignoring consumer confidential)", stored, ClientTypePublic)
	}

	// Consumer claims public but provides a secret -> derived confidential.
	clients = newFakeClientStore()
	if err := registerStaticClient(context.Background(), clients, "https://api.example.com", "tenant-b",
		ClientEntry{ClientID: "id", ClientSecret: "shh", ClientType: ClientTypePublic}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stored = clients.entries[ckey("https://api.example.com", "tenant-b")]
	if stored == nil || stored.ClientType != ClientTypeConfidential {
		t.Errorf("ClientType = %v, want %d (confidential, ignoring consumer public)", stored, ClientTypeConfidential)
	}
}

// Two static clients for the SAME server with different clientRefs must coexist
// independently — neither overwrites the other.
func TestRegisterStaticClient_TwoTenantsSameServer(t *testing.T) {
	clients := newFakeClientStore()
	const server = "https://api.example.com"

	if err := registerStaticClient(context.Background(), clients, server, "tenant-a",
		ClientEntry{ClientID: "id-a", ClientType: ClientTypeConfidential}); err != nil {
		t.Fatalf("tenant-a registration failed: %v", err)
	}
	if err := registerStaticClient(context.Background(), clients, server, "tenant-b",
		ClientEntry{ClientID: "id-b", ClientType: ClientTypeConfidential}); err != nil {
		t.Fatalf("tenant-b registration failed: %v", err)
	}

	a, err := getClient(context.Background(), clients, server, "tenant-a")
	if err != nil || a == nil || a.ClientID != "id-a" {
		t.Errorf("tenant-a lookup = %v, err=%v; want id-a", a, err)
	}
	b, err := getClient(context.Background(), clients, server, "tenant-b")
	if err != nil || b == nil || b.ClientID != "id-b" {
		t.Errorf("tenant-b lookup = %v, err=%v; want id-b", b, err)
	}
}

// A static client (clientRef "tenant-a") and a dynamic client (clientRef "")
// for the same server must not interfere with each other.
func TestRegisterStaticClient_CoexistsWithDynamic(t *testing.T) {
	locks := &fakeRegistrationLocks{}
	clients := newFakeClientStore()
	do := func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(regResp), nil
	}
	const server = "https://api.example.com"

	// Dynamic client occupies the "" slot.
	dyn, err := registerDynamicClient(context.Background(), do, clients, locks,
		staticDiscover(discoveredServer()), testConfig(),
		RegisterClientOptions{ServerURL: server})
	if err != nil {
		t.Fatalf("dynamic registration failed: %v", err)
	}

	// Static client for the same server under a distinct clientRef.
	if err := registerStaticClient(context.Background(), clients, server, "tenant-a",
		ClientEntry{ClientID: "static-id", ClientType: ClientTypeConfidential}); err != nil {
		t.Fatalf("static registration failed: %v", err)
	}

	gotDyn, err := getClient(context.Background(), clients, server, "")
	if err != nil || gotDyn == nil || gotDyn.ClientID != dyn.ClientID {
		t.Errorf("dynamic client clobbered: got %v err=%v, want %q", gotDyn, err, dyn.ClientID)
	}
	if gotDyn.RegistrationType != RegistrationTypeDynamic {
		t.Errorf("dynamic slot type = %d, want %d", gotDyn.RegistrationType, RegistrationTypeDynamic)
	}
	gotStatic, err := getClient(context.Background(), clients, server, "tenant-a")
	if err != nil || gotStatic == nil || gotStatic.ClientID != "static-id" {
		t.Errorf("static client lookup = %v err=%v, want static-id", gotStatic, err)
	}
	if gotStatic.RegistrationType != RegistrationTypeStatic {
		t.Errorf("static slot type = %d, want %d", gotStatic.RegistrationType, RegistrationTypeStatic)
	}
}

// --- DeleteClient (cascade) ---

// DeleteClient removes the client record and cascade-deletes every token issued
// for that (server, clientRef).
func TestDeleteClient_CascadeDeletesTokensAndClient(t *testing.T) {
	const server = "https://api.example.com"
	clients := newFakeClientStore()
	if err := registerStaticClient(context.Background(), clients, server, "tenant-a",
		ClientEntry{ClientID: "id-a", ClientSecret: "shh"}); err != nil {
		t.Fatalf("setup: static registration failed: %v", err)
	}
	tokens := newFakeTokenStore()
	for _, acct := range []string{"acct-1", "acct-2", "acct-3"} {
		tokens.entries[TokenKey{ServerURL: server, ClientRef: "tenant-a", AccountID: acct}] =
			&TokenEntry{AccessToken: "at-" + acct}
	}
	locks := &fakeRegistrationLocks{}

	// trailing slash exercises normalization on the delete path
	if err := deleteClient(context.Background(), clients, tokens, locks, server+"/", "tenant-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokens.filterDeletes != 1 {
		t.Errorf("expected exactly 1 cascade DeleteByFilter, got %d", tokens.filterDeletes)
	}
	if len(tokens.entries) != 0 {
		t.Errorf("expected all tenant-a tokens deleted, %d remain: %v", len(tokens.entries), tokens.entries)
	}
	if _, ok := clients.entries[ckey(server, "tenant-a")]; ok {
		t.Errorf("client record not deleted; entries=%v", clients.entries)
	}
	if clients.deletes != 1 {
		t.Errorf("expected exactly 1 client DeleteKey, got %d", clients.deletes)
	}
	// The registration lock must be acquired exactly once and released.
	if locks.acquires != 1 || !locks.released() {
		t.Errorf("lock acquires=%d released=%v, want 1/true", locks.acquires, locks.released())
	}
}

// An empty clientRef is rejected: the dynamic slot cannot be deleted via this
// API, and nothing is deleted.
func TestDeleteClient_EmptyClientRefRejected(t *testing.T) {
	clients := newFakeClientStore()
	tokens := newFakeTokenStore()
	locks := &fakeRegistrationLocks{}

	err := deleteClient(context.Background(), clients, tokens, locks, "https://api.example.com", "")
	if err == nil {
		t.Fatal("expected an error when clientRef is empty")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
	if tokens.filterDeletes != 0 || clients.deletes != 0 {
		t.Errorf("must not delete on rejection; cascade=%d clientDeletes=%d", tokens.filterDeletes, clients.deletes)
	}
	// Validation must precede locking: an invalid request never takes the lock.
	if locks.acquires != 0 {
		t.Errorf("must not acquire the lock on rejection; acquires=%d", locks.acquires)
	}
}

// A serverURL that normalizes to empty is rejected, and nothing is deleted.
func TestDeleteClient_EmptyServerURLRejected(t *testing.T) {
	clients := newFakeClientStore()
	tokens := newFakeTokenStore()
	locks := &fakeRegistrationLocks{}

	err := deleteClient(context.Background(), clients, tokens, locks, "   ", "tenant-a")
	if err == nil {
		t.Fatal("expected an error when serverURL normalizes to empty")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
	if tokens.filterDeletes != 0 || clients.deletes != 0 {
		t.Errorf("must not delete on rejection; cascade=%d clientDeletes=%d", tokens.filterDeletes, clients.deletes)
	}
	if locks.acquires != 0 {
		t.Errorf("must not acquire the lock on rejection; acquires=%d", locks.acquires)
	}
}

// Deleting an already-absent client is not an error (idempotent): the NotFound
// from the client delete is tolerated, and the token cascade still runs.
func TestDeleteClient_IdempotentWhenClientAbsent(t *testing.T) {
	clients := newFakeClientStore()
	tokens := newFakeTokenStore()
	locks := &fakeRegistrationLocks{}

	if err := deleteClient(context.Background(), clients, tokens, locks, "https://api.example.com", "tenant-a"); err != nil {
		t.Fatalf("deleting an absent client must be tolerated: %v", err)
	}
	if tokens.filterDeletes != 1 {
		t.Errorf("cascade must still run for an absent client; filterDeletes=%d", tokens.filterDeletes)
	}
	if !locks.released() {
		t.Error("lock must be released even on the idempotent (absent client) path")
	}
}

// Deleting one tenant must leave another tenant's tokens and the dynamic slot's
// tokens for the same server untouched.
func TestDeleteClient_IsolatesOtherClients(t *testing.T) {
	const server = "https://api.example.com"
	clients := newFakeClientStore()
	if err := registerStaticClient(context.Background(), clients, server, "tenant-a",
		ClientEntry{ClientID: "id-a", ClientSecret: "shh"}); err != nil {
		t.Fatalf("setup: tenant-a registration failed: %v", err)
	}
	if err := registerStaticClient(context.Background(), clients, server, "tenant-b",
		ClientEntry{ClientID: "id-b", ClientSecret: "shh"}); err != nil {
		t.Fatalf("setup: tenant-b registration failed: %v", err)
	}

	tokens := newFakeTokenStore()
	tokens.entries[TokenKey{ServerURL: server, ClientRef: "tenant-a", AccountID: "acct-1"}] = &TokenEntry{AccessToken: "a"}
	tokens.entries[TokenKey{ServerURL: server, ClientRef: "tenant-b", AccountID: "acct-1"}] = &TokenEntry{AccessToken: "b"}
	// dynamic slot ("") token for the same server
	tokens.entries[TokenKey{ServerURL: server, ClientRef: "", AccountID: "acct-1"}] = &TokenEntry{AccessToken: "d"}
	locks := &fakeRegistrationLocks{}

	if err := deleteClient(context.Background(), clients, tokens, locks, server, "tenant-a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := tokens.entries[(TokenKey{ServerURL: server, ClientRef: "tenant-a", AccountID: "acct-1"})]; ok {
		t.Error("tenant-a token should have been deleted")
	}
	if _, ok := tokens.entries[(TokenKey{ServerURL: server, ClientRef: "tenant-b", AccountID: "acct-1"})]; !ok {
		t.Error("tenant-b token must be untouched")
	}
	if _, ok := tokens.entries[(TokenKey{ServerURL: server, ClientRef: "", AccountID: "acct-1"})]; !ok {
		t.Error("dynamic-slot token must be untouched")
	}
	// The tenant-b client record must also survive.
	if _, ok := clients.entries[ckey(server, "tenant-b")]; !ok {
		t.Error("tenant-b client record must be untouched")
	}
}

// A failure in the token cascade aborts before the client record is deleted, so
// no orphaned tokens are left pointing at a removed client. The error is wrapped
// with the cascade's error code.
func TestDeleteClient_CascadeFailureAbortsBeforeClientDelete(t *testing.T) {
	const server = "https://api.example.com"
	clients := newFakeClientStore()
	if err := registerStaticClient(context.Background(), clients, server, "tenant-a",
		ClientEntry{ClientID: "id-a", ClientSecret: "shh"}); err != nil {
		t.Fatalf("setup: static registration failed: %v", err)
	}
	tokens := newFakeTokenStore()
	tokens.filterDeleteErr = errors.Wrap(errors.Unknown, "boom")
	locks := &fakeRegistrationLocks{}

	err := deleteClient(context.Background(), clients, tokens, locks, server, "tenant-a")
	if err == nil {
		t.Fatal("expected an error when the token cascade fails")
	}
	if clients.deletes != 0 {
		t.Errorf("client record must NOT be deleted when the cascade fails; deletes=%d", clients.deletes)
	}
	if _, ok := clients.entries[ckey(server, "tenant-a")]; !ok {
		t.Error("client record must survive a cascade failure")
	}
	// The lock is taken before the cascade, so it must still be released on the
	// cascade-failure path.
	if !locks.released() {
		t.Error("lock must be released even when the cascade fails")
	}
}

// Lock contention must surface a retryable error and delete nothing: deleting
// while a (re-)registration of the same client is in flight would race.
func TestDeleteClient_LockContentionFailsRetryable(t *testing.T) {
	const server = "https://api.example.com"
	clients := newFakeClientStore()
	if err := registerStaticClient(context.Background(), clients, server, "tenant-a",
		ClientEntry{ClientID: "id-a", ClientSecret: "shh"}); err != nil {
		t.Fatalf("setup: static registration failed: %v", err)
	}
	tokens := newFakeTokenStore()
	tokens.entries[TokenKey{ServerURL: server, ClientRef: "tenant-a", AccountID: "acct-1"}] = &TokenEntry{AccessToken: "a"}
	locks := &fakeRegistrationLocks{failWith: errors.Wrap(errors.AlreadyExists, "lock held")}

	err := deleteClient(context.Background(), clients, tokens, locks, server, "tenant-a")
	if err == nil {
		t.Fatal("expected a retryable error on lock contention")
	}
	if errors.GetErrCode(err) != errors.AlreadyExists {
		t.Errorf("expected a retryable (AlreadyExists) error on lock contention, got %v", err)
	}
	if tokens.filterDeletes != 0 {
		t.Errorf("must not cascade-delete tokens when the lock is held; filterDeletes=%d", tokens.filterDeletes)
	}
	if clients.deletes != 0 {
		t.Errorf("must not delete the client record when the lock is held; deletes=%d", clients.deletes)
	}
	if _, ok := tokens.entries[(TokenKey{ServerURL: server, ClientRef: "tenant-a", AccountID: "acct-1"})]; !ok {
		t.Error("tenant-a token must survive a contended delete")
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
