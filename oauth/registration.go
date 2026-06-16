// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-core-stack/core/errors"
	coresync "github.com/go-core-stack/core/sync"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const (
	responseTypeCode = "code"
)

// clientStore is the subset of the client table that registration needs. The
// concrete *table.Table[ClientKey, ClientEntry] satisfies it; tests substitute a
// fake so the cache, lock, and HTTP paths are exercised without a live MongoDB.
type clientStore interface {
	Find(ctx context.Context, key *ClientKey) (*ClientEntry, error)
	Insert(ctx context.Context, key *ClientKey, entry *ClientEntry) error
	// Locate upserts (insert-or-update); used by static registration to
	// (re)provision a client keyed by (ServerURL, ClientRef).
	Locate(ctx context.Context, key *ClientKey, entry *ClientEntry) error
	DeleteKey(ctx context.Context, key *ClientKey) error
}

// registrationLocker is the subset of the registration lock table registration
// needs. *coresync.LockTable[RegistrationLockKey] satisfies it.
type registrationLocker interface {
	TryAcquire(ctx context.Context, key *RegistrationLockKey) (coresync.Lock, error)
}

// discoverFunc resolves (and caches) server metadata for a server URL.
// *OAuthManager supplies m.DiscoverServer; tests supply a fake.
type discoverFunc func(ctx context.Context, serverURL string) (*ServerEntry, error)

// clientRegistrationRequest is the RFC 7591 dynamic client registration request
// body for a public client.
type clientRegistrationRequest struct {
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

// clientRegistrationResponse is the RFC 7591 §3.2.1 registration response. Parsed
// defensively: optional fields are simply absent when omitted by the server.
type clientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RegistrationClientURI   string   `json:"registration_client_uri"`
	RegistrationAccessToken string   `json:"registration_access_token"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	Scope                   string   `json:"scope"`
}

// RegisterDynamicClient registers (RFC 7591) a public OAuth client for a remote
// server and persists it, returning the existing client on a cache hit so the
// call is idempotent. Registration is serialized per server by a distributed
// lock, with a double-check inside the lock so two replicas that both miss the
// initial cache check register exactly once.
func (m *OAuthManager) RegisterDynamicClient(ctx context.Context, opts RegisterClientOptions) (*ClientEntry, error) {
	return registerDynamicClient(ctx, m.httpDo, m.clientTable, m.registrationLocks, m.DiscoverServer, m.config, opts)
}

// ReRegisterClient deletes any stored client for the server, then runs the
// dynamic registration path fresh. Used when an existing client may have expired
// or the server returned invalid_client.
func (m *OAuthManager) ReRegisterClient(ctx context.Context, opts RegisterClientOptions) (*ClientEntry, error) {
	return reRegisterClient(ctx, m.httpDo, m.clientTable, m.registrationLocks, m.DiscoverServer, m.config, opts)
}

// GetClient returns the stored client for a (server, clientRef) pair, or
// (nil, nil) if none has been registered yet. clientRef disambiguates multiple
// clients registered against the same server; dynamic clients use clientRef "".
// It never performs a network call.
func (m *OAuthManager) GetClient(ctx context.Context, serverURL string, clientRef string) (*ClientEntry, error) {
	return getClient(ctx, m.clientTable, serverURL, clientRef)
}

// RegisterStaticClient (pre-)provisions a confidential/static OAuth client under
// a consumer-defined clientRef. Unlike dynamic registration it performs no
// network call: the consumer supplies the credentials in entry, which are
// upserted (encrypted at rest) keyed by (ServerURL, ClientRef). clientRef must
// be non-empty — "" is reserved exclusively for the dynamic client slot.
func (m *OAuthManager) RegisterStaticClient(ctx context.Context, serverURL string, clientRef string, entry ClientEntry) error {
	return registerStaticClient(ctx, m.clientTable, serverURL, clientRef, entry)
}

// DeleteClient removes a static client registration and cascade-deletes every
// token issued for that (serverURL, clientRef) pair. It is the offboarding
// counterpart to RegisterStaticClient: tokens are deleted first so a partial
// failure never leaves orphaned tokens pointing at a deleted client. The cascade
// and the record delete run under the per-(server, clientRef) registration lock
// so they are atomic against a concurrent (re-)registration of the same client.
// clientRef must be non-empty — the dynamic client slot ("") cannot be deleted
// via this API. A missing client record is tolerated (idempotent).
func (m *OAuthManager) DeleteClient(ctx context.Context, serverURL, clientRef string) error {
	return deleteClient(ctx, m.clientTable, m.tokenTable, m.registrationLocks, serverURL, clientRef)
}

// registerDynamicClient implements RegisterDynamicClient against the
// clientStore/registrationLocker/discoverFunc/httpDoFunc interfaces so it is
// unit-testable with fakes.
func registerDynamicClient(ctx context.Context, do httpDoFunc, clients clientStore, locks registrationLocker, discover discoverFunc, cfg OAuthConfig, opts RegisterClientOptions) (*ClientEntry, error) {
	normalized := normalizeServerURL(opts.ServerURL)
	if normalized == "" {
		return nil, errors.Wrap(errors.InvalidArgument, "oauth: serverURL must not be empty")
	}
	merged := mergeRegisterOptions(cfg, opts)
	// clientRef disambiguates clients for the same server; dynamic uses "".
	clientRef := opts.ClientRef

	// Idempotent fast path: return an already-registered client without taking
	// the lock or touching the network.
	existing, err := findClient(ctx, clients, normalized, clientRef)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return existing, nil
	}

	// Serialize registration per (server, clientRef) across replicas. Keying the
	// lock on clientRef too means static and dynamic registrations for the same
	// server do not serialize on each other. TryAcquire is non-blocking: it
	// fails when another replica currently holds the lock.
	lock, err := locks.TryAcquire(ctx, &RegistrationLockKey{ServerURL: normalized, ClientRef: clientRef})
	if err != nil {
		// A peer is registering this server right now. It may already have
		// finished between our fast-path miss and this acquire attempt; re-check
		// the cache and return its client so a concurrent first-time
		// registration does not surface a spurious error. If the peer is still
		// in flight (no entry yet), surface a retryable error rather than
		// blocking — core/sync offers no blocking acquire.
		if existing, ferr := findClient(ctx, clients, normalized, clientRef); ferr == nil && existing != nil {
			return existing, nil
		}
		return nil, errors.Wrapf(errors.GetErrCode(err),
			"oauth: registration already in progress for %s: %s", normalized, err)
	}
	// Always release the lock, including on the error paths below.
	defer func() { _ = lock.Close() }()

	// Double-check inside the lock: another replica may have registered between
	// our fast-path miss and acquiring the lock.
	existing, err = findClient(ctx, clients, normalized, clientRef)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return existing, nil
	}

	return performRegistration(ctx, do, clients, discover, merged, normalized, clientRef)
}

// reRegisterClient forces a fresh registration: under the per-server lock it
// deletes any existing client record and then registers anew. Holding the lock
// across the delete makes delete-then-register atomic, so a concurrent
// RegisterDynamicClient cannot slip a client in between (it would block on the
// lock and then observe the freshly registered client). Used when an existing
// client may have expired or the server returned invalid_client.
func reRegisterClient(ctx context.Context, do httpDoFunc, clients clientStore, locks registrationLocker, discover discoverFunc, cfg OAuthConfig, opts RegisterClientOptions) (*ClientEntry, error) {
	normalized := normalizeServerURL(opts.ServerURL)
	if normalized == "" {
		return nil, errors.Wrap(errors.InvalidArgument, "oauth: serverURL must not be empty")
	}
	merged := mergeRegisterOptions(cfg, opts)
	// clientRef disambiguates clients for the same server; dynamic uses "".
	clientRef := opts.ClientRef

	// Acquire the lock BEFORE the delete so the replace is atomic. Unlike the
	// dynamic path there is no fast-path/return-existing on contention: a
	// re-register caller wants a definitively fresh client, so on lock
	// contention we surface a retryable error rather than another replica's
	// (possibly the very client we were asked to replace) entry.
	lock, err := locks.TryAcquire(ctx, &RegistrationLockKey{ServerURL: normalized, ClientRef: clientRef})
	if err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err),
			"oauth: registration already in progress for %s: %s", normalized, err)
	}
	defer func() { _ = lock.Close() }()

	// Delete the existing record under the lock; tolerate its absence.
	if err := clients.DeleteKey(ctx, &ClientKey{ServerURL: normalized, ClientRef: clientRef}); err != nil && !errors.IsNotFound(err) {
		return nil, errors.Wrapf(errors.GetErrCode(err),
			"oauth: failed to delete existing client for %s: %s", normalized, err)
	}

	return performRegistration(ctx, do, clients, discover, merged, normalized, clientRef)
}

// performRegistration runs the RFC 7591 dynamic registration body for an
// already-normalized server URL: ensure metadata / a registration endpoint,
// POST the public-client request, and persist the result. The caller MUST hold
// the per-server registration lock and MUST have established that no client
// should be returned from cache first (fast-path / double-check, or a delete for
// re-registration).
func performRegistration(ctx context.Context, do httpDoFunc, clients clientStore, discover discoverFunc, merged RegisterClientOptions, normalized, clientRef string) (*ClientEntry, error) {
	// Resolve the registration endpoint: prefer the caller-supplied override,
	// fall back to the discovered metadata.
	endpoint := merged.RegistrationEndpoint

	// Always run discovery to obtain other metadata (TokenEndpoint,
	// AuthorizationEndpoint, etc.) that the rest of the library needs.
	server, err := discover(ctx, normalized)
	if err != nil {
		return nil, err
	}

	if endpoint == "" {
		endpoint = server.RegistrationEndpoint
	}
	if endpoint == "" {
		return nil, errors.Wrapf(errors.InvalidArgument,
			"oauth: no registration endpoint for %s (not in caller options and not discovered)", normalized)
	}

	// RFC 7591 dynamic registration for a public client.
	reqBody := clientRegistrationRequest{
		ClientName:              merged.ClientName,
		RedirectURIs:            merged.RedirectURIs,
		GrantTypes:              DefaultGrantTypes(),
		ResponseTypes:           []string{responseTypeCode},
		TokenEndpointAuthMethod: TokenEndpointAuthMethodNone,
		Scope:                   strings.Join(merged.Scopes, " "),
	}

	var resp clientRegistrationResponse
	if merged.InitialAccessToken != "" {
		// When an initial access token is required, build the HTTP request
		// directly so the Authorization header is scoped to registration only
		// (Option A from issue #42). This avoids changing postJSON's signature.
		if err := postJSONWithAuth(ctx, do, endpoint, merged.InitialAccessToken, &reqBody, &resp); err != nil {
			return nil, errors.Wrapf(errors.GetErrCode(err),
				"oauth: dynamic client registration failed for %s: %s", normalized, err)
		}
	} else {
		if err := postJSON(ctx, do, endpoint, &reqBody, &resp); err != nil {
			return nil, errors.Wrapf(errors.GetErrCode(err),
				"oauth: dynamic client registration failed for %s: %s", normalized, err)
		}
	}
	if resp.ClientID == "" {
		return nil, errors.Wrapf(errors.InvalidArgument,
			"oauth: registration response for %s did not include a client_id", normalized)
	}

	entry := &ClientEntry{
		ClientID:                resp.ClientID,
		ClientSecret:            resp.ClientSecret,
		ClientSecretExpiresAt:   resp.ClientSecretExpiresAt,
		RegistrationURI:         resp.RegistrationClientURI,
		RegistrationAccessToken: resp.RegistrationAccessToken,
		RedirectURIs:            preferStrings(resp.RedirectURIs, merged.RedirectURIs),
		Scopes:                  preferStrings(strings.Fields(resp.Scope), merged.Scopes),
		ClientType:              ClientTypePublic,
		RegistrationType:        RegistrationTypeDynamic,
		RegisteredAt:            time.Now().Unix(),
	}

	// Persist; sensitive fields are encrypted at rest by ClientEntry.MarshalBSON.
	if err := clients.Insert(ctx, &ClientKey{ServerURL: normalized, ClientRef: clientRef}, entry); err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err),
			"oauth: failed to persist registered client for %s: %s", normalized, err)
	}
	return entry, nil
}

// registerStaticClient implements RegisterStaticClient against the clientStore
// interface so it is unit-testable with a fake. clientRef must be non-empty;
// the (already consumer-supplied) entry is stamped with static metadata and
// upserted under (ServerURL, ClientRef), encrypted at rest by
// ClientEntry.MarshalBSON.
func registerStaticClient(ctx context.Context, clients clientStore, serverURL, clientRef string, entry ClientEntry) error {
	// "" is reserved exclusively for the dynamic client slot.
	if strings.TrimSpace(clientRef) == "" {
		return errors.Wrap(errors.InvalidArgument,
			"oauth: clientRef must not be empty for static client registration")
	}
	normalized := normalizeServerURL(serverURL)
	if normalized == "" {
		return errors.Wrap(errors.InvalidArgument, "oauth: serverURL must not be empty")
	}

	entry.RegistrationType = RegistrationTypeStatic
	entry.RegisteredAt = time.Now().Unix()

	// Derive ClientType from secret presence — do not trust the consumer. A
	// static client with a (non-whitespace) secret is confidential; otherwise
	// it is public. This derivation is authoritative and overwrites any
	// ClientType the consumer supplied.
	if strings.TrimSpace(entry.ClientSecret) != "" {
		entry.ClientType = ClientTypeConfidential
	} else {
		entry.ClientType = ClientTypePublic
	}

	// Upsert so a static client can be re-provisioned (e.g. rotated secret)
	// without a separate delete. Sensitive fields are encrypted at rest by
	// ClientEntry.MarshalBSON, exactly as on the dynamic path.
	if err := clients.Locate(ctx, &ClientKey{ServerURL: normalized, ClientRef: clientRef}, &entry); err != nil {
		return errors.Wrapf(errors.GetErrCode(err),
			"oauth: failed to persist static client for %s (clientRef %q): %s", normalized, clientRef, err)
	}
	return nil
}

// deleteClient implements DeleteClient against the clientStore / tokenDeleter /
// registrationLocker interfaces so it is unit-testable with fakes. It
// cascade-deletes the client's tokens before removing the client record:
// ordering it this way means a partial failure (tokens deleted, client delete
// fails) never leaves orphaned tokens pointing at a deleted client. Restricted
// to static clients (clientRef != ""): the dynamic slot ("") cannot be deleted
// here. A NotFound on the client delete is tolerated (idempotent) — the token
// cascade may still have done useful work.
//
// The cascade and the record delete are performed under the per-(server,
// clientRef) registration lock, mirroring reRegisterClient's discipline, so a
// concurrent RegisterStaticClient / ReRegisterClient for the same client cannot
// interleave with the delete (e.g. re-provision a client between the token
// cascade and the record delete, leaving the freshly registered client
// deleted). As in the re-register path, lock contention surfaces a retryable
// error rather than racing — input validation runs first so an invalid request
// never takes the lock.
func deleteClient(ctx context.Context, clients clientStore, tokens tokenDeleter, locks registrationLocker, serverURL, clientRef string) error {
	normalized := normalizeServerURL(serverURL)
	if normalized == "" {
		return errors.Wrap(errors.InvalidArgument, "oauth: serverURL must not be empty")
	}
	if strings.TrimSpace(clientRef) == "" {
		return errors.Wrap(errors.InvalidArgument,
			"oauth: clientRef must not be empty for client deletion")
	}

	// Serialize against (re-)registration of the same (server, clientRef). The
	// lock is keyed identically to the registration paths, so a delete and a
	// concurrent register cannot run at once. TryAcquire is non-blocking; on
	// contention surface a retryable error rather than deleting under a peer's
	// in-flight registration.
	lock, err := locks.TryAcquire(ctx, &RegistrationLockKey{ServerURL: normalized, ClientRef: clientRef})
	if err != nil {
		return errors.Wrapf(errors.GetErrCode(err),
			"oauth: registration in progress for %s (clientRef %q); retry deletion: %s", normalized, clientRef, err)
	}
	defer func() { _ = lock.Close() }()

	// Cascade: delete all tokens for this (serverURL, clientRef). clientRef is a
	// non-empty static value here, so plain equality is correct — this avoids the
	// absent-or-empty subtlety that only affects the dynamic "" case in
	// ListTokens. The deleted count is intentionally ignored.
	filter := bson.M{
		"_id.serverUrl": normalized,
		"_id.clientRef": clientRef,
	}
	if _, err := tokens.DeleteByFilter(ctx, filter); err != nil {
		return errors.Wrapf(errors.GetErrCode(err),
			"oauth: failed to delete tokens for client %s/%s: %s", normalized, clientRef, err)
	}

	// Delete the client record; tolerate its absence so the operation is
	// idempotent.
	if err := clients.DeleteKey(ctx, &ClientKey{ServerURL: normalized, ClientRef: clientRef}); err != nil && !errors.IsNotFound(err) {
		return errors.Wrapf(errors.GetErrCode(err),
			"oauth: failed to delete client %s/%s: %s", normalized, clientRef, err)
	}
	return nil
}

// getClient implements GetClient's read-only lookup, mapping a cache miss to
// (nil, nil).
func getClient(ctx context.Context, clients clientStore, serverURL, clientRef string) (*ClientEntry, error) {
	normalized := normalizeServerURL(serverURL)
	if normalized == "" {
		return nil, errors.Wrap(errors.InvalidArgument, "oauth: serverURL must not be empty")
	}
	return findClient(ctx, clients, normalized, clientRef)
}

// findClient looks up a client by normalized server URL and clientRef, mapping
// NotFound to (nil, nil) and surfacing any other error.
func findClient(ctx context.Context, clients clientStore, normalized, clientRef string) (*ClientEntry, error) {
	entry, err := clients.Find(ctx, &ClientKey{ServerURL: normalized, ClientRef: clientRef})
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return entry, nil
}

// mergeRegisterOptions fills unset RegisterClientOptions fields from the manager
// configuration: ClientName, RedirectURIs (from the single RedirectURI), and
// Scopes. RegistrationEndpoint and InitialAccessToken are per-call fields with
// no config-level defaults — they are copied through unchanged.
func mergeRegisterOptions(cfg OAuthConfig, opts RegisterClientOptions) RegisterClientOptions {
	merged := opts
	if merged.ClientName == "" {
		merged.ClientName = cfg.ClientName
	}
	if len(merged.RedirectURIs) == 0 && cfg.RedirectURI != "" {
		merged.RedirectURIs = []string{cfg.RedirectURI}
	}
	if len(merged.Scopes) == 0 {
		merged.Scopes = cfg.Scopes
	}
	// RegistrationEndpoint and InitialAccessToken are per-call overrides with
	// no config-level defaults; they propagate via the struct copy above.
	return merged
}

// preferStrings returns primary when it is non-empty, otherwise fallback. Used
// to prefer the server-echoed redirect_uris / scope over the requested values.
func preferStrings(primary, fallback []string) []string {
	if len(primary) > 0 {
		return primary
	}
	return fallback
}

// postJSON marshals payload, POSTs it as application/json, and decodes a JSON
// response body into out, wrapping network, HTTP-status, and parse failures with
// core/errors codes. The response body is bounded by maxMetadataBytes (defined
// in discovery.go) so a hostile server cannot exhaust memory.
func postJSON(ctx context.Context, do httpDoFunc, url string, payload, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrapf(errors.InvalidArgument, "oauth: failed to encode request for %s: %s", url, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return errors.Wrapf(errors.InvalidArgument, "oauth: failed to build request for %s: %s", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := do(req)
	if err != nil {
		return errors.Wrapf(errors.Unknown, "oauth: request to %s failed: %s", url, err)
	}
	// Share one maxMetadataBytes budget across the parse read and the deferred
	// drain so the body can never read more than that in total, while still
	// draining (bounded) on every path so the connection can be reused.
	limited := io.LimitReader(resp.Body, maxMetadataBytes)
	defer func() {
		_, _ = io.Copy(io.Discard, limited)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return errors.Wrapf(errors.Unknown, "oauth: %s returned HTTP status %d", url, resp.StatusCode)
	}

	raw, err := io.ReadAll(limited)
	if err != nil {
		return errors.Wrapf(errors.Unknown, "oauth: failed to read response from %s: %s", url, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return errors.Wrapf(errors.InvalidArgument, "oauth: failed to parse JSON from %s: %s", url, err)
	}
	return nil
}

// postJSONWithAuth is like postJSON but additionally sets an Authorization:
// Bearer header on the outbound request. Used by performRegistration when the
// caller supplies an InitialAccessToken per RFC 7591 §3.1. Keeping this as a
// separate function (rather than adding an optional parameter to postJSON)
// avoids touching postJSON's signature and keeps the auth concern local to
// registration.
func postJSONWithAuth(ctx context.Context, do httpDoFunc, url, bearerToken string, payload, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrapf(errors.InvalidArgument, "oauth: failed to encode request for %s: %s", url, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return errors.Wrapf(errors.InvalidArgument, "oauth: failed to build request for %s: %s", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := do(req)
	if err != nil {
		return errors.Wrapf(errors.Unknown, "oauth: request to %s failed: %s", url, err)
	}
	limited := io.LimitReader(resp.Body, maxMetadataBytes)
	defer func() {
		_, _ = io.Copy(io.Discard, limited)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return errors.Wrapf(errors.Unknown, "oauth: %s returned HTTP status %d", url, resp.StatusCode)
	}

	raw, err := io.ReadAll(limited)
	if err != nil {
		return errors.Wrapf(errors.Unknown, "oauth: failed to read response from %s: %s", url, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return errors.Wrapf(errors.InvalidArgument, "oauth: failed to parse JSON from %s: %s", url, err)
	}
	return nil
}
