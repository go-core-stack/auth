// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/go-core-stack/core/errors"
)

// --- fakes ---

// fakeServerCache is an in-memory serverCache that records access counts so
// tests can assert cache-hit/miss and read-only behavior.
type fakeServerCache struct {
	entries   map[string]*ServerEntry
	findCalls int
	locates   int
}

func newFakeServerCache() *fakeServerCache {
	return &fakeServerCache{entries: map[string]*ServerEntry{}}
}

func (c *fakeServerCache) Find(_ context.Context, key *ServerKey) (*ServerEntry, error) {
	c.findCalls++
	e, ok := c.entries[key.ServerURL]
	if !ok {
		return nil, errors.Wrapf(errors.NotFound, "no entry for %s", key.ServerURL)
	}
	return e, nil
}

func (c *fakeServerCache) Locate(_ context.Context, key *ServerKey, entry *ServerEntry) error {
	c.locates++
	c.entries[key.ServerURL] = entry
	return nil
}

// jsonResponse builds a 200 JSON HTTP response.
func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

// statusResponse builds an empty response with the given status code.
func statusResponse(code int) *http.Response {
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     http.Header{},
	}
}

// routingDoer returns an httpDoFunc that serves responses keyed by the request
// path suffix, recording each path it was asked for.
func routingDoer(t *testing.T, routes map[string]*http.Response, calls *[]string) httpDoFunc {
	t.Helper()
	return func(req *http.Request) (*http.Response, error) {
		*calls = append(*calls, req.URL.Path)
		if resp, ok := routes[req.URL.Path]; ok {
			return resp, nil
		}
		t.Fatalf("unexpected request to %s", req.URL.String())
		return nil, nil
	}
}

const (
	prDoc = `{
		"resource": "https://api.example.com",
		"authorization_servers": ["https://as.example.com"],
		"scopes_supported": ["read", "write"]
	}`
	asDoc = `{
		"issuer": "https://as.example.com",
		"authorization_endpoint": "https://as.example.com/authorize",
		"token_endpoint": "https://as.example.com/token",
		"revocation_endpoint": "https://as.example.com/revoke",
		"registration_endpoint": "https://as.example.com/register",
		"grant_types_supported": ["authorization_code", "refresh_token"]
	}`
	oidcDoc = `{
		"issuer": "https://as.example.com",
		"authorization_endpoint": "https://as.example.com/oidc/authorize",
		"token_endpoint": "https://as.example.com/oidc/token"
	}`
)

// --- tests ---

func TestDiscoverAndCache_HappyPath(t *testing.T) {
	var calls []string
	do := routingDoer(t, map[string]*http.Response{
		WellKnownProtectedResource:   jsonResponse(prDoc),
		WellKnownAuthorizationServer: jsonResponse(asDoc),
	}, &calls)
	cache := newFakeServerCache()

	entry, err := discoverAndCache(context.Background(), do, cache, "https://api.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.AuthorizationEndpoint != "https://as.example.com/authorize" {
		t.Errorf("authorization endpoint = %q", entry.AuthorizationEndpoint)
	}
	if entry.TokenEndpoint != "https://as.example.com/token" {
		t.Errorf("token endpoint = %q", entry.TokenEndpoint)
	}
	if entry.RegistrationEndpoint != "https://as.example.com/register" {
		t.Errorf("registration endpoint = %q", entry.RegistrationEndpoint)
	}
	if entry.DiscoveredAt == 0 {
		t.Error("DiscoveredAt should be set")
	}
	if len(entry.AuthorizationServers) != 1 || entry.AuthorizationServers[0] != "https://as.example.com" {
		t.Errorf("authorization servers = %v", entry.AuthorizationServers)
	}
	if cache.locates != 1 {
		t.Errorf("expected 1 upsert, got %d", cache.locates)
	}
	if got := cache.entries["https://api.example.com"]; got == nil {
		t.Error("entry not cached under normalized key")
	}
}

func TestDiscoverAndCache_MissingAuthorizationServers(t *testing.T) {
	var calls []string
	do := routingDoer(t, map[string]*http.Response{
		WellKnownProtectedResource: jsonResponse(`{"resource":"https://api.example.com"}`),
	}, &calls)
	cache := newFakeServerCache()

	_, err := discoverAndCache(context.Background(), do, cache, "https://api.example.com")
	if err == nil {
		t.Fatal("expected error for missing authorization_servers")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
	if cache.locates != 0 {
		t.Error("nothing should be cached on failure")
	}
}

func TestDiscoverAndCache_OIDCFallback(t *testing.T) {
	var calls []string
	do := routingDoer(t, map[string]*http.Response{
		WellKnownProtectedResource:   jsonResponse(prDoc),
		WellKnownAuthorizationServer: statusResponse(http.StatusNotFound), // RFC 8414 unavailable
		WellKnownOpenIDConfiguration: jsonResponse(oidcDoc),
	}, &calls)
	cache := newFakeServerCache()

	entry, err := discoverAndCache(context.Background(), do, cache, "https://api.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.TokenEndpoint != "https://as.example.com/oidc/token" {
		t.Errorf("expected OIDC token endpoint, got %q", entry.TokenEndpoint)
	}
	// confirm the fallback path was actually exercised
	var sawOIDC bool
	for _, p := range calls {
		if p == WellKnownOpenIDConfiguration {
			sawOIDC = true
		}
	}
	if !sawOIDC {
		t.Errorf("OIDC fallback not attempted; calls=%v", calls)
	}
}

func TestDiscoverAndCache_NoEndpoints(t *testing.T) {
	var calls []string
	// RFC 8414 responds 200 but without endpoints, and OIDC is unavailable: with
	// no usable metadata from either source, discovery must fail.
	do := routingDoer(t, map[string]*http.Response{
		WellKnownProtectedResource:   jsonResponse(prDoc),
		WellKnownAuthorizationServer: jsonResponse(`{"issuer":"https://as.example.com"}`),
		WellKnownOpenIDConfiguration: statusResponse(http.StatusNotFound),
	}, &calls)
	cache := newFakeServerCache()

	_, err := discoverAndCache(context.Background(), do, cache, "https://api.example.com")
	if err == nil {
		t.Fatal("expected error when no token/authorization endpoint is discovered")
	}
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
	if cache.locates != 0 {
		t.Error("nothing should be cached on failure")
	}
}

// An RFC 8414 document that is reachable (HTTP 200) but missing endpoints must
// still trigger the OIDC fallback, which here supplies the usable metadata.
func TestDiscoverAndCache_OIDCFallbackOnIncomplete8414(t *testing.T) {
	var calls []string
	do := routingDoer(t, map[string]*http.Response{
		WellKnownProtectedResource:   jsonResponse(prDoc),
		WellKnownAuthorizationServer: jsonResponse(`{"issuer":"https://as.example.com"}`), // 200 but no endpoints
		WellKnownOpenIDConfiguration: jsonResponse(oidcDoc),
	}, &calls)
	cache := newFakeServerCache()

	entry, err := discoverAndCache(context.Background(), do, cache, "https://api.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.TokenEndpoint != "https://as.example.com/oidc/token" {
		t.Errorf("expected OIDC token endpoint, got %q", entry.TokenEndpoint)
	}
}

func TestDiscoverAndCache_BothASDocsFail(t *testing.T) {
	var calls []string
	do := routingDoer(t, map[string]*http.Response{
		WellKnownProtectedResource:   jsonResponse(prDoc),
		WellKnownAuthorizationServer: statusResponse(http.StatusNotFound),
		WellKnownOpenIDConfiguration: statusResponse(http.StatusNotFound),
	}, &calls)
	cache := newFakeServerCache()

	if _, err := discoverAndCache(context.Background(), do, cache, "https://api.example.com"); err == nil {
		t.Fatal("expected error when both RFC 8414 and OIDC discovery fail")
	}
}

func TestDiscoverServer_CacheHitNoNetwork(t *testing.T) {
	cache := newFakeServerCache()
	cache.entries["https://api.example.com"] = &ServerEntry{TokenEndpoint: "https://as.example.com/token"}

	// A do func that fails the test if invoked proves the cache hit short-circuits
	// the network. The trailing slash also exercises key normalization on hit.
	do := func(req *http.Request) (*http.Response, error) {
		t.Fatalf("network call made on cache hit: %s", req.URL)
		return nil, nil
	}

	entry, err := discoverServer(context.Background(), do, cache, "https://api.example.com/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.TokenEndpoint != "https://as.example.com/token" {
		t.Errorf("expected cached entry, got %v", entry)
	}
	if cache.locates != 0 {
		t.Error("cache hit must not upsert")
	}
}

func TestRefreshServerMetadata_SkipsCache(t *testing.T) {
	var calls []string
	do := routingDoer(t, map[string]*http.Response{
		WellKnownProtectedResource:   jsonResponse(prDoc),
		WellKnownAuthorizationServer: jsonResponse(asDoc),
	}, &calls)
	cache := newFakeServerCache()
	// Pre-seed a stale entry; refresh must ignore it and re-fetch over the network.
	cache.entries["https://api.example.com"] = &ServerEntry{TokenEndpoint: "stale"}

	entry, err := refreshServerMetadata(context.Background(), do, cache, "https://api.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.TokenEndpoint != "https://as.example.com/token" {
		t.Errorf("refresh did not re-fetch; token endpoint = %q", entry.TokenEndpoint)
	}
	if len(calls) == 0 {
		t.Error("refresh must perform network calls even when cached")
	}
	if cache.locates != 1 {
		t.Errorf("refresh must upsert fresh metadata; locates = %d", cache.locates)
	}
}

func TestGetCachedServer_HitAndMiss(t *testing.T) {
	cache := newFakeServerCache()

	// miss → (nil, nil), no upsert, read-only
	got, err := getCachedServer(context.Background(), cache, "https://api.example.com/")
	if err != nil {
		t.Fatalf("unexpected error on miss: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil on miss, got %v", got)
	}

	// hit (note normalization: stored under the no-trailing-slash key)
	cache.entries["https://api.example.com"] = &ServerEntry{TokenEndpoint: "https://as.example.com/token"}
	got, err = getCachedServer(context.Background(), cache, "https://api.example.com")
	if err != nil {
		t.Fatalf("unexpected error on hit: %v", err)
	}
	if got == nil || got.TokenEndpoint != "https://as.example.com/token" {
		t.Errorf("expected cached entry, got %v", got)
	}
	if cache.locates != 0 {
		t.Error("GetCachedServer must be read-only")
	}
}

func TestNormalizeServerURL(t *testing.T) {
	cases := map[string]string{
		"https://api.example.com/":    "https://api.example.com",
		"https://api.example.com":     "https://api.example.com",
		"  https://api.example.com/ ": "https://api.example.com",
		"https://api.example.com///":  "https://api.example.com",
		"":                            "",
	}
	for in, want := range cases {
		if got := normalizeServerURL(in); got != want {
			t.Errorf("normalizeServerURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWellKnownInsertURL(t *testing.T) {
	cases := []struct{ base, want string }{
		{"https://h", "https://h/.well-known/oauth-protected-resource"},
		{"https://h/tenant", "https://h/.well-known/oauth-protected-resource/tenant"},
		{"https://h/a/b", "https://h/.well-known/oauth-protected-resource/a/b"},
	}
	for _, c := range cases {
		got, err := wellKnownInsertURL(c.base, WellKnownProtectedResource)
		if err != nil {
			t.Fatalf("wellKnownInsertURL(%q): %v", c.base, err)
		}
		if got != c.want {
			t.Errorf("wellKnownInsertURL(%q) = %q, want %q", c.base, got, c.want)
		}
	}
}

func TestWellKnownAppendURL(t *testing.T) {
	cases := []struct{ base, want string }{
		{"https://h", "https://h/.well-known/openid-configuration"},
		{"https://h/tenant", "https://h/tenant/.well-known/openid-configuration"},
	}
	for _, c := range cases {
		got, err := wellKnownAppendURL(c.base, WellKnownOpenIDConfiguration)
		if err != nil {
			t.Fatalf("wellKnownAppendURL(%q): %v", c.base, err)
		}
		if got != c.want {
			t.Errorf("wellKnownAppendURL(%q) = %q, want %q", c.base, got, c.want)
		}
	}
}

// Resource and authorization-server identifiers that carry a path must have the
// well-known segment inserted after the host (RFC 9728 / RFC 8414), not simply
// appended to the end of the path.
func TestDiscoverAndCache_PathBearingURLs(t *testing.T) {
	var calls []string
	do := routingDoer(t, map[string]*http.Response{
		"/.well-known/oauth-protected-resource/mcp": jsonResponse(
			`{"resource":"https://api.example.com/mcp","authorization_servers":["https://as.example.com/tenant1"]}`),
		"/.well-known/oauth-authorization-server/tenant1": jsonResponse(asDoc),
	}, &calls)
	cache := newFakeServerCache()

	entry, err := discoverAndCache(context.Background(), do, cache, "https://api.example.com/mcp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.TokenEndpoint != "https://as.example.com/token" {
		t.Errorf("token endpoint = %q", entry.TokenEndpoint)
	}
	// cached under the normalized path-bearing resource URL
	if cache.entries["https://api.example.com/mcp"] == nil {
		t.Errorf("entry not cached under path-bearing key; keys=%v", cache.entries)
	}
}
