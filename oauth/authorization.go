// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-core-stack/core/errors"
)

// Authorization Code + PKCE protocol constants.
const (
	grantTypeAuthorizationCode = "authorization_code"

	// codeVerifierBytes is the number of random bytes drawn for a PKCE code
	// verifier. 32 bytes base64url-encode (no padding) to a 43-character
	// verifier, the minimum length RFC 7636 §4.1 permits.
	codeVerifierBytes = 32
	// stateBytes is the number of random bytes drawn for the CSRF state token.
	stateBytes = 32
)

// pendingStore is the subset of the pending-auth-state table the authorization
// flow needs. The concrete *table.Table[PendingAuthStateKey, PendingAuthState]
// satisfies it; tests substitute a fake so the PKCE/exchange paths are exercised
// without a live MongoDB.
type pendingStore interface {
	Insert(ctx context.Context, key *PendingAuthStateKey, entry *PendingAuthState) error
	Find(ctx context.Context, key *PendingAuthStateKey) (*PendingAuthState, error)
	DeleteKey(ctx context.Context, key *PendingAuthStateKey) error
}

// tokenWriter is the subset of the token table the callback handler needs. It
// upserts (Locate) rather than inserts so a re-authorization overwrites any
// existing token for the (server, account) pair.
type tokenWriter interface {
	Locate(ctx context.Context, key *TokenKey, entry *TokenEntry) error
}

// tokenResponse is the RFC 6749 §5.1 access-token response. Parsed defensively:
// optional fields are simply absent when omitted by the server.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
}

// tokenResponseMappers is the type for the optional per-server-URL mapper map.
// It is defined here for readability in the internal function signatures.
type tokenResponseMappers map[string]func(raw []byte) (*TokenResponse, error)

// tokenResponseFromPublic converts a public TokenResponse (returned by a
// consumer-supplied TokenResponseMapper) into the internal tokenResponse used
// by the library's exchange and persistence logic.
func tokenResponseFromPublic(pub *TokenResponse) tokenResponse {
	return tokenResponse{
		AccessToken:  pub.AccessToken,
		TokenType:    pub.TokenType,
		ExpiresIn:    pub.ExpiresIn,
		RefreshToken: pub.RefreshToken,
		Scope:        pub.Scope,
		IDToken:      pub.IDToken,
	}
}

// applyTokenResponseMapper looks up the consumer-supplied mapper for the given
// serverURL and calls it when the standard token-endpoint parse yielded an empty
// AccessToken. It is the shared mapper application logic used by both
// handleCallback and refreshTokenExchange.
func applyTokenResponseMapper(mappers tokenResponseMappers, raw []byte, tr *tokenResponse, serverURL string) error {
	if tr.AccessToken != "" || mappers == nil {
		return nil
	}
	mapper, ok := mappers[serverURL]
	if !ok || mapper == nil {
		return nil
	}
	mapped, err := mapper(raw)
	if err != nil {
		return errors.Wrapf(errors.InvalidArgument,
			"oauth: token response mapper failed for %s: %s", serverURL, err)
	}
	if mapped != nil {
		*tr = tokenResponseFromPublic(mapped)
	}
	return nil
}

// AuthorizationURL builds the Authorization Code + PKCE request parameters for a
// remote server and persists the transient state needed to complete the flow. It
// generates a PKCE verifier/challenge (S256) and a CSRF state token, stores a
// PendingAuthState (verifier encrypted at rest) keyed by the state, and returns
// the tokenized *AuthorizationParams — the consumer assembles the final redirect
// URL. The state value in the eventual callback URL is the only session handle;
// no in-memory session is kept.
func (m *OAuthManager) AuthorizationURL(ctx context.Context, opts AuthorizeOptions) (*AuthorizationParams, error) {
	return authorizationURL(ctx, m.serverTable, m.clientTable, m.pendingTable, m.config, opts)
}

// HandleCallback completes the Authorization Code + PKCE flow: it looks up the
// pending state by the returned CSRF state, exchanges the authorization code for
// tokens at the server's token endpoint (presenting the stored PKCE verifier),
// persists the resulting token (encrypted, state=active) keyed by
// {serverURL, clientRef, accountId} — clientRef recovered from the pending state
// — and deletes the now-consumed pending state. An unknown
// or expired state yields a clear error.
//
// Security note: the account the token is stored under is taken from the
// server-side PendingAuthState bound at AuthorizationURL time — never from the
// callback request — so a callback cannot be steered to a different account. The
// state value is the CSRF/session handle, but the library cannot verify that the
// browser completing the callback is the same one that began the flow. The
// consuming service MUST bind the state (or the resulting account) to its own
// authenticated session before calling this, and reject a mismatch, to prevent
// login-CSRF / session-fixation.
func (m *OAuthManager) HandleCallback(ctx context.Context, state string, code string) (*TokenEntry, error) {
	return handleCallback(ctx, m.httpDo, m.serverTable, m.pendingTable, m.tokenTable, m.clientTable, state, code, m.config.TokenResponseMappers)
}

// authorizationURL implements AuthorizationURL against the
// serverCache/clientStore/pendingStore interfaces so it is unit-testable with
// fakes.
func authorizationURL(ctx context.Context, servers serverCache, clients clientStore, pending pendingStore, cfg OAuthConfig, opts AuthorizeOptions) (*AuthorizationParams, error) {
	normalized := normalizeServerURL(opts.ServerURL)
	if normalized == "" {
		return nil, errors.Wrap(errors.InvalidArgument, "oauth: serverURL must not be empty")
	}
	if strings.TrimSpace(opts.AccountID) == "" {
		return nil, errors.Wrap(errors.InvalidArgument, "oauth: accountID must not be empty")
	}
	merged := mergeAuthorizeOptions(cfg, opts)
	if merged.RedirectURI == "" {
		return nil, errors.Wrap(errors.InvalidArgument,
			"oauth: redirectURI must be set via AuthorizeOptions or OAuthConfig")
	}

	// The client must already be registered and the server already discovered:
	// the consumer drives registration/discovery before starting a flow.
	client, err := findClient(ctx, clients, normalized, merged.ClientRef)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.Wrapf(errors.NotFound,
			"oauth: no registered client for %s; register before authorizing", normalized)
	}

	server, err := getCachedServer(ctx, servers, normalized)
	if err != nil {
		return nil, err
	}
	if server == nil {
		return nil, errors.Wrapf(errors.NotFound,
			"oauth: server %s not discovered; discover before authorizing", normalized)
	}
	if server.AuthorizationEndpoint == "" {
		return nil, errors.Wrapf(errors.InvalidArgument,
			"oauth: server %s does not advertise an authorization endpoint", normalized)
	}

	// PKCE (S256) and CSRF state, both from crypto/rand.
	verifier, err := generateRandomToken(codeVerifierBytes)
	if err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err), "oauth: failed to generate PKCE verifier: %s", err)
	}
	state, err := generateRandomToken(stateBytes)
	if err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err), "oauth: failed to generate CSRF state: %s", err)
	}

	// Persist the transient state; the verifier is encrypted at rest by
	// PendingAuthState.MarshalBSON. Everything needed to finish the exchange
	// lives here, so the callback needs no in-memory session.
	ps := &PendingAuthState{
		ServerURL:    normalized,
		ClientRef:    merged.ClientRef,
		AccountID:    merged.AccountID,
		ClientID:     client.ClientID,
		CodeVerifier: verifier,
		RedirectURI:  merged.RedirectURI,
		Scopes:       merged.Scopes,
		CreatedAt:    time.Now(),
	}
	if err := pending.Insert(ctx, &PendingAuthStateKey{State: state}, ps); err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err),
			"oauth: failed to persist pending authorization state for %s: %s", normalized, err)
	}

	return &AuthorizationParams{
		Endpoint:            server.AuthorizationEndpoint,
		ClientID:            client.ClientID,
		RedirectURI:         merged.RedirectURI,
		ResponseType:        responseTypeCode,
		Scope:               strings.Join(merged.Scopes, " "),
		State:               state,
		CodeChallenge:       codeChallengeS256(verifier),
		CodeChallengeMethod: CodeChallengeMethodS256,
		ExtraParams:         merged.ExtraParams,
	}, nil
}

// handleCallback implements HandleCallback against the
// pendingStore/serverCache/tokenWriter/clientStore/httpDoFunc interfaces so it is
// unit-testable with fakes. The clientStore lets the exchange attach confidential
// client authentication (client_secret_post) when the initiating client is one.
func handleCallback(ctx context.Context, do httpDoFunc, servers serverCache, pending pendingStore, tokens tokenWriter, clients clientStore, state, code string, mappers tokenResponseMappers) (*TokenEntry, error) {
	if strings.TrimSpace(state) == "" {
		return nil, errors.Wrap(errors.InvalidArgument, "oauth: callback state must not be empty")
	}
	if strings.TrimSpace(code) == "" {
		return nil, errors.Wrap(errors.InvalidArgument, "oauth: callback code must not be empty")
	}

	stateKey := &PendingAuthStateKey{State: state}
	ps, err := pending.Find(ctx, stateKey)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.Wrap(errors.NotFound,
				"oauth: unknown or expired authorization state")
		}
		return nil, err
	}

	// Defence-in-depth against TTL-sweep lag (and non-MongoDB/fake stores that
	// don't reap at all): the IdP code single-use, PKCE binding, and CSRF state
	// entropy already bound the callback window, but enforce the advertised
	// PendingStateTTL here too rather than trust a lingering state. Best-effort
	// delete, then return the same opaque error as an unknown state.
	if !ps.CreatedAt.Add(PendingStateTTL).After(time.Now()) {
		_ = pending.DeleteKey(ctx, stateKey)
		return nil, errors.Wrap(errors.NotFound,
			"oauth: unknown or expired authorization state")
	}

	server, err := getCachedServer(ctx, servers, ps.ServerURL)
	if err != nil {
		return nil, err
	}
	if server == nil || server.TokenEndpoint == "" {
		return nil, errors.Wrapf(errors.InvalidArgument,
			"oauth: server %s has no usable token endpoint", ps.ServerURL)
	}

	// RFC 6749 §4.1.3 / RFC 7636 §4.5 authorization-code exchange, presenting the
	// stored PKCE verifier. The client_id is the one that initiated the flow
	// (persisted in the pending state), not whatever is currently registered: the
	// authorization code is bound to the initiating client, so a re-registration
	// between AuthorizationURL and HandleCallback must not change the client_id
	// presented at the exchange.
	form := url.Values{}
	form.Set("grant_type", grantTypeAuthorizationCode)
	form.Set("code", code)
	form.Set("code_verifier", ps.CodeVerifier)
	form.Set("redirect_uri", ps.RedirectURI)

	// Attach client authentication. A confidential client must present its
	// client_secret (client_secret_post) at the token endpoint, so look up the
	// full ClientEntry by ps.ClientRef (the key field — NOT ps.ClientID, the
	// protocol id). attachClientAuth is used only when the looked-up client still
	// matches the client_id bound into the pending state; if the client is gone,
	// the lookup errors, or the client_id changed (e.g. a re-registration mid-flow
	// rotated it), fall back to public auth — send client_id only, never a stale
	// secret, and never fail the exchange over it.
	client, err := findClient(ctx, clients, ps.ServerURL, ps.ClientRef)
	if err == nil && client != nil && client.ClientID == ps.ClientID {
		attachClientAuth(form, client)
	} else {
		// Fall back to public auth (client_id only). A non-nil err here is a real
		// store failure (findClient maps NotFound to nil/nil), not a benign miss:
		// log it so a confidential client silently downgrading to a failing public
		// exchange leaves a breadcrumb, rather than surfacing only as an opaque
		// invalid_client from the token endpoint.
		if err != nil {
			log.Printf("oauth: client lookup failed during callback for %s/%s; using public auth: %s",
				ps.ServerURL, ps.ClientRef, err)
		}
		form.Set("client_id", ps.ClientID)
	}

	var tr tokenResponse
	raw, err := postForm(ctx, do, server.TokenEndpoint, form, &tr)
	if err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err),
			"oauth: authorization code exchange failed for %s: %s", ps.ServerURL, err)
	}
	if err := applyTokenResponseMapper(mappers, raw, &tr, ps.ServerURL); err != nil {
		return nil, err
	}
	if tr.AccessToken == "" {
		return nil, errors.Wrapf(errors.InvalidArgument,
			"oauth: token response for %s did not include an access_token", ps.ServerURL)
	}

	entry := newTokenEntry(&tr, ps, time.Now())

	// Persist the token BEFORE deleting the pending state: if persistence fails
	// the state survives (TTL-bounded) for a retry, and we never drop the
	// verifier with no token to show for it. Sensitive fields are encrypted at
	// rest by TokenEntry.MarshalBSON.
	tokenKey := &TokenKey{ServerURL: ps.ServerURL, ClientRef: ps.ClientRef, AccountID: ps.AccountID}
	if err := tokens.Locate(ctx, tokenKey, entry); err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err),
			"oauth: failed to persist token for %s: %s", tokenKey.id(), err)
	}

	// Consume the single-use pending state. The token is already durably stored,
	// so a delete failure is non-fatal: the TTL index and stale-state reconciler
	// reap the entry, and its state value cannot be replayed against a missing
	// record without also reproducing the (single-use) authorization code.
	if err := pending.DeleteKey(ctx, stateKey); err != nil && !errors.IsNotFound(err) {
		log.Printf("oauth: failed to delete consumed pending auth state for %s/%s: %s",
			ps.ServerURL, ps.AccountID, err)
	}

	return entry, nil
}

// newTokenEntry builds an active TokenEntry from a token response and the pending
// state it completes. ExpiresAt is derived from expires_in relative to now;
// LastRefresh records the issuance instant so the refresh reconciler can apply
// its lifetime-fraction heuristic. Scopes fall back to the requested scopes when
// the server does not echo them.
func newTokenEntry(tr *tokenResponse, ps *PendingAuthState, now time.Time) *TokenEntry {
	entry := &TokenEntry{
		AccessToken:  tr.AccessToken,
		TokenType:    tr.TokenType,
		RefreshToken: tr.RefreshToken,
		Scopes:       preferStrings(strings.Fields(tr.Scope), ps.Scopes),
		IDToken:      tr.IDToken,
		State:        SessionActive,
		LastRefresh:  now.Unix(),
	}
	// Capture refresh capability explicitly from the response: a refresh token
	// means the session is refreshable; its absence means the server issued a
	// non-refreshable (e.g. offline) token that must not later trip a permanent
	// refresh failure on a transiently-blanked field.
	if strings.TrimSpace(tr.RefreshToken) != "" {
		entry.RefreshPolicy = RefreshPolicyRefreshable
	} else {
		entry.RefreshPolicy = RefreshPolicyNoRefresh
	}
	if tr.ExpiresIn > 0 {
		entry.ExpiresAt = now.Add(time.Duration(tr.ExpiresIn) * time.Second).Unix()
	}
	return entry
}

// mergeAuthorizeOptions fills unset AuthorizeOptions fields from the manager
// configuration: RedirectURI and Scopes. AccountID and ExtraParams pass through
// verbatim.
func mergeAuthorizeOptions(cfg OAuthConfig, opts AuthorizeOptions) AuthorizeOptions {
	merged := opts
	if merged.RedirectURI == "" {
		merged.RedirectURI = cfg.RedirectURI
	}
	if len(merged.Scopes) == 0 {
		merged.Scopes = cfg.Scopes
	}
	return merged
}

// generateRandomToken returns n cryptographically random bytes encoded as
// base64url without padding (RFC 7636 §4.1 / §4.2), suitable for a PKCE verifier
// or a CSRF state token.
func generateRandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", errors.Wrapf(errors.Unknown, "oauth: failed to read random bytes: %s", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// codeChallengeS256 derives the PKCE S256 code challenge from a verifier:
// base64url(SHA256(verifier)) without padding (RFC 7636 §4.2).
func codeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// postForm POSTs form as application/x-www-form-urlencoded and decodes a JSON
// response body into out, wrapping network, HTTP-status, and parse failures with
// core/errors codes. The token endpoint takes form-encoded input (RFC 6749
// §4.1.3) but returns JSON (§5.1). The response body is bounded by
// maxMetadataBytes (defined in discovery.go) so a hostile server cannot exhaust
// memory. The raw response bytes are returned alongside so callers can apply a
// TokenResponseMapper when the standard parse yields an empty access_token.
func postForm(ctx context.Context, do httpDoFunc, endpoint string, form url.Values, out any) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.Wrapf(errors.InvalidArgument, "oauth: failed to build request for %s: %s", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := do(req)
	if err != nil {
		return nil, errors.Wrapf(errors.Unknown, "oauth: request to %s failed: %s", endpoint, err)
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
		return nil, errors.Wrapf(errors.Unknown, "oauth: %s returned HTTP status %d", endpoint, resp.StatusCode)
	}

	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, errors.Wrapf(errors.Unknown, "oauth: failed to read response from %s: %s", endpoint, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, errors.Wrapf(errors.InvalidArgument, "oauth: failed to parse JSON from %s: %s", endpoint, err)
	}
	return raw, nil
}
