// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-core-stack/core/errors"
)

// maxMetadataBytes caps the size of a discovery document we are willing to read
// into memory, so a misbehaving (or hostile) server cannot exhaust memory.
const maxMetadataBytes = 1 << 20 // 1 MiB

// httpDoFunc executes an HTTP request. *OAuthManager supplies m.httpDo (the
// single outbound-HTTP chokepoint); unit tests supply a fake. Keeping discovery
// parameterized on this func — and on serverCache below — lets the network and
// caching paths be exercised with fakes, without a live MongoDB or server.
type httpDoFunc func(req *http.Request) (*http.Response, error)

// serverCache is the subset of the server table discovery needs. The concrete
// *table.Table[ServerKey, ServerEntry] satisfies it; tests substitute a fake.
type serverCache interface {
	Find(ctx context.Context, key *ServerKey) (*ServerEntry, error)
	Locate(ctx context.Context, key *ServerKey, entry *ServerEntry) error
}

// protectedResourceMetadata is the RFC 9728 protected-resource document. JSON
// is parsed defensively: optional fields are simply absent when omitted.
type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// authServerMetadata is the RFC 8414 authorization-server document, which is a
// superset-compatible shape with the OIDC openid-configuration fallback.
type authServerMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	RevocationEndpoint    string   `json:"revocation_endpoint"`
	RegistrationEndpoint  string   `json:"registration_endpoint"`
	GrantTypesSupported   []string `json:"grant_types_supported"`
}

// DiscoverServer returns the OAuth/OIDC metadata for a remote server, fetching
// and caching it on a miss. On a cache hit it returns the stored entry without
// any network call. Discovery is layered: RFC 9728 protected-resource metadata
// identifies the authorization server, whose RFC 8414 metadata (with an OIDC
// openid-configuration fallback) yields the authorization/token/revocation/
// registration endpoints. The result is upserted into the server table keyed by
// the normalized server URL.
func (m *OAuthManager) DiscoverServer(ctx context.Context, serverURL string) (*ServerEntry, error) {
	return discoverServer(ctx, m.httpDo, m.serverTable, serverURL)
}

// RefreshServerMetadata forces a fresh discovery, ignoring any cached entry, and
// upserts the result.
func (m *OAuthManager) RefreshServerMetadata(ctx context.Context, serverURL string) (*ServerEntry, error) {
	return refreshServerMetadata(ctx, m.httpDo, m.serverTable, serverURL)
}

// GetCachedServer returns the cached metadata for a server, or (nil, nil) if it
// has not been discovered yet. It never performs a network call.
func (m *OAuthManager) GetCachedServer(ctx context.Context, serverURL string) (*ServerEntry, error) {
	return getCachedServer(ctx, m.serverTable, serverURL)
}

// discoverServer implements DiscoverServer against the serverCache/httpDoFunc
// interfaces so it is unit-testable with fakes.
func discoverServer(ctx context.Context, do httpDoFunc, cache serverCache, serverURL string) (*ServerEntry, error) {
	normalized := normalizeServerURL(serverURL)
	if normalized == "" {
		return nil, errors.Wrap(errors.InvalidArgument, "oauth: serverURL must not be empty")
	}

	entry, err := cache.Find(ctx, &ServerKey{ServerURL: normalized})
	if err == nil {
		return entry, nil
	}
	if !errors.IsNotFound(err) {
		return nil, err
	}

	return discoverAndCache(ctx, do, cache, normalized)
}

// refreshServerMetadata implements RefreshServerMetadata (skip cache, fetch
// fresh, upsert).
func refreshServerMetadata(ctx context.Context, do httpDoFunc, cache serverCache, serverURL string) (*ServerEntry, error) {
	normalized := normalizeServerURL(serverURL)
	if normalized == "" {
		return nil, errors.Wrap(errors.InvalidArgument, "oauth: serverURL must not be empty")
	}
	return discoverAndCache(ctx, do, cache, normalized)
}

// getCachedServer implements GetCachedServer's read-only lookup, mapping a cache
// miss to (nil, nil).
func getCachedServer(ctx context.Context, cache serverCache, serverURL string) (*ServerEntry, error) {
	normalized := normalizeServerURL(serverURL)
	if normalized == "" {
		return nil, errors.Wrap(errors.InvalidArgument, "oauth: serverURL must not be empty")
	}
	entry, err := cache.Find(ctx, &ServerKey{ServerURL: normalized})
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return entry, nil
}

// discoverAndCache performs the full discovery chain for an already-normalized
// server URL and upserts the resulting entry into the cache.
func discoverAndCache(ctx context.Context, do httpDoFunc, cache serverCache, normalized string) (*ServerEntry, error) {
	// RFC 9728: protected-resource metadata names the authorization server(s).
	prURL, err := wellKnownInsertURL(normalized, WellKnownProtectedResource)
	if err != nil {
		return nil, err
	}
	var prm protectedResourceMetadata
	if err := getJSON(ctx, do, prURL, &prm); err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err),
			"oauth: failed to fetch protected-resource metadata for %s: %s", normalized, err)
	}
	if len(prm.AuthorizationServers) == 0 {
		return nil, errors.Wrapf(errors.InvalidArgument,
			"oauth: protected-resource metadata for %s has no authorization_servers", normalized)
	}
	asURL := normalizeServerURL(prm.AuthorizationServers[0])

	// RFC 8414 authorization-server metadata, with OIDC discovery fallback.
	// fetchAuthServerMetadata guarantees a usable token/authorization endpoint
	// or a clear error, so no further endpoint check is needed here.
	asMeta, err := fetchAuthServerMetadata(ctx, do, asURL)
	if err != nil {
		return nil, err
	}

	entry := &ServerEntry{
		Resource:              prm.Resource,
		AuthorizationServers:  prm.AuthorizationServers,
		ScopesSupported:       prm.ScopesSupported,
		Issuer:                asMeta.Issuer,
		AuthorizationEndpoint: asMeta.AuthorizationEndpoint,
		TokenEndpoint:         asMeta.TokenEndpoint,
		RevocationEndpoint:    asMeta.RevocationEndpoint,
		RegistrationEndpoint:  asMeta.RegistrationEndpoint,
		GrantTypesSupported:   asMeta.GrantTypesSupported,
		DiscoveredAt:          time.Now().Unix(),
	}
	if err := cache.Locate(ctx, &ServerKey{ServerURL: normalized}, entry); err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err),
			"oauth: failed to cache server metadata for %s: %s", normalized, err)
	}
	return entry, nil
}

// fetchAuthServerMetadata tries RFC 8414 first and falls back to OIDC
// openid-configuration. The fallback is taken not only when the RFC 8414 fetch
// fails but also when it succeeds yet yields no usable token/authorization
// endpoint (a present-but-incomplete 8414 document), so a server that only
// publishes complete metadata at the OIDC endpoint still discovers.
func fetchAuthServerMetadata(ctx context.Context, do httpDoFunc, asURL string) (*authServerMetadata, error) {
	rfcURL, err := wellKnownInsertURL(asURL, WellKnownAuthorizationServer)
	if err != nil {
		return nil, err
	}
	var meta authServerMetadata
	rfcErr := getJSON(ctx, do, rfcURL, &meta)
	if rfcErr == nil && metadataHasEndpoint(&meta) {
		return &meta, nil
	}

	// Fall back to OIDC discovery. Reset to avoid retaining any partial parse.
	oidcURL, err := wellKnownAppendURL(asURL, WellKnownOpenIDConfiguration)
	if err != nil {
		return nil, err
	}
	var oidc authServerMetadata
	oidcErr := getJSON(ctx, do, oidcURL, &oidc)
	if oidcErr == nil && metadataHasEndpoint(&oidc) {
		return &oidc, nil
	}

	return nil, errors.Wrapf(errors.InvalidArgument,
		"oauth: no usable authorization-server metadata for %s (RFC 8414: %s; OIDC: %s)",
		asURL, metadataFailureReason(rfcErr), metadataFailureReason(oidcErr))
}

// metadataHasEndpoint reports whether a discovery document carries at least one
// of the endpoints the rest of the library needs.
func metadataHasEndpoint(m *authServerMetadata) bool {
	return m.AuthorizationEndpoint != "" || m.TokenEndpoint != ""
}

// metadataFailureReason renders why an authorization-server fetch did not yield
// usable metadata: the fetch error if any, otherwise the document was reachable
// but incomplete.
func metadataFailureReason(err error) string {
	if err != nil {
		return err.Error()
	}
	return "no token or authorization endpoint"
}

// getJSON performs a GET and decodes a JSON body into out, wrapping network,
// HTTP-status, and parse failures with core/errors codes.
func getJSON(ctx context.Context, do httpDoFunc, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return errors.Wrapf(errors.InvalidArgument, "oauth: failed to build request for %s: %s", url, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := do(req)
	if err != nil {
		return errors.Wrapf(errors.Unknown, "oauth: request to %s failed: %s", url, err)
	}
	// Wrap the body in a single LimitReader so reads and the deferred drain share
	// one maxMetadataBytes budget: an oversized or hostile body can never cause
	// more than maxMetadataBytes total to be read.
	limited := io.LimitReader(resp.Body, maxMetadataBytes)
	// Drain (bounded) before closing so the underlying connection can be reused
	// for the next discovery request, including on the non-2xx and size-limit
	// paths where the body is otherwise left partially read.
	defer func() {
		_, _ = io.Copy(io.Discard, limited)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return errors.Wrapf(errors.Unknown, "oauth: %s returned HTTP status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(limited)
	if err != nil {
		return errors.Wrapf(errors.Unknown, "oauth: failed to read response from %s: %s", url, err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return errors.Wrapf(errors.InvalidArgument, "oauth: failed to parse JSON from %s: %s", url, err)
	}
	return nil
}

// normalizeServerURL trims surrounding whitespace and any trailing slash so the
// same logical server maps to one cache key and one set of well-known URLs.
func normalizeServerURL(serverURL string) string {
	return strings.TrimRight(strings.TrimSpace(serverURL), "/")
}

// wellKnownInsertURL builds an RFC 9728 / RFC 8414 well-known URL by inserting
// the well-known segment between the host and any path component of base, as the
// RFCs require for identifiers that carry a path:
//
//	https://h           + /.well-known/x -> https://h/.well-known/x
//	https://h/tenant    + /.well-known/x -> https://h/.well-known/x/tenant
//
// For the common bare-origin case (no path) this is identical to a suffix
// append. Query and fragment are dropped (discovery identifiers carry neither).
func wellKnownInsertURL(base, segment string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", errors.Wrapf(errors.InvalidArgument, "oauth: invalid server URL %q: %s", base, err)
	}
	u.Path = segment + strings.TrimSuffix(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// wellKnownAppendURL builds an OIDC discovery URL by appending the well-known
// segment after any path component of base, per OpenID Connect Discovery §4:
//
//	https://h/tenant + /.well-known/openid-configuration
//	  -> https://h/tenant/.well-known/openid-configuration
func wellKnownAppendURL(base, segment string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", errors.Wrapf(errors.InvalidArgument, "oauth: invalid server URL %q: %s", base, err)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + segment
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
