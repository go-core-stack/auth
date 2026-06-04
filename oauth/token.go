// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-core-stack/core/errors"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Token lifecycle protocol constants.
const (
	grantTypeRefreshToken = "refresh_token"

	// tokenTypeHintRefresh / tokenTypeHintAccess are the RFC 7009 §2.1
	// token_type_hint values sent with a revocation request.
	tokenTypeHintRefresh = "refresh_token"
	tokenTypeHintAccess  = "access_token"

	// OAuth error codes (RFC 6749 §5.2) that classify a refresh failure as
	// permanent — the grant or client is no longer valid and re-authorization is
	// required, so retrying is pointless.
	oauthErrInvalidGrant  = "invalid_grant"
	oauthErrInvalidClient = "invalid_client"
)

// tokenStore is the subset of the token table the lifecycle API needs. The
// concrete *table.Table[TokenKey, TokenEntry] satisfies it; tests substitute a
// fake so the refresh/revoke/list paths are exercised without a live MongoDB.
type tokenStore interface {
	Find(ctx context.Context, key *TokenKey) (*TokenEntry, error)
	Update(ctx context.Context, key *TokenKey, entry *TokenEntry) error
	DeleteKey(ctx context.Context, key *TokenKey) error
	FindMany(ctx context.Context, filter any, offset, limit int32) ([]*TokenEntry, error)
}

// tokenDeleter is the subset of the token table the client-deletion cascade
// needs: a bulk delete by filter. The concrete *table.Table[TokenKey, TokenEntry]
// satisfies it; tests substitute a fake. The signature mirrors
// core/table.Table.DeleteByFilter exactly — it returns (int64, error), not error
// alone — so *table.Table is assignable to it; deleteClient ignores the count.
type tokenDeleter interface {
	DeleteByFilter(ctx context.Context, filter any) (int64, error)
}

// attachClientAuth sets the client authentication parameters on a token-endpoint
// request form. It always sends client_id; for a confidential client carrying a
// non-empty secret it additionally sends client_secret (the client_secret_post
// method, RFC 6749 §2.3.1). A public client — or a confidential client whose
// secret is empty — sends client_id only.
//
// This is the single chokepoint the auth-code exchange, token refresh, and token
// revocation paths all route through, so adding client_secret_basic (HTTP Basic)
// later is a localized change here rather than at three call sites.
func attachClientAuth(form url.Values, client *ClientEntry) {
	form.Set("client_id", client.ClientID)
	if client.ClientType == ClientTypeConfidential && client.ClientSecret != "" {
		form.Set("client_secret", client.ClientSecret)
	}
}

// oauthErrorResponse is the RFC 6749 §5.2 token-endpoint error response. Parsed
// to classify a non-2xx refresh outcome as permanent vs transient.
type oauthErrorResponse struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// GetToken returns the stored token for a (server, account) pair, refreshing it
// first if it is within the near-expiry threshold (RefreshThreshold or past
// RefreshLifetimeFraction of its lifetime). A token that is comfortably valid is
// returned without any network call. A revoked token is returned as-is — refresh
// cannot resurrect it — so callers should inspect TokenEntry.State (or use
// GetSessionState) and re-authorize when it is not active.
func (m *OAuthManager) GetToken(ctx context.Context, serverURL, clientRef, accountID string) (*TokenEntry, error) {
	return getToken(ctx, m.tokenTable, m.tokenRefreshLocks, m.refreshToken, serverURL, clientRef, accountID)
}

// RefreshToken forces a token refresh regardless of remaining lifetime, under
// the same distributed lock the proactive reconciler uses, and returns the
// refreshed token. A permanent failure (invalid_grant / invalid_client) marks
// the session revoked and surfaces the error; a transient failure marks it
// failed (keeping the existing token) and surfaces the error.
func (m *OAuthManager) RefreshToken(ctx context.Context, serverURL, clientRef, accountID string) (*TokenEntry, error) {
	return forceRefresh(ctx, m.tokenTable, m.tokenRefreshLocks, m.refreshToken, serverURL, clientRef, accountID)
}

// RevokeToken revokes the token at the server's RFC 7009 revocation endpoint and
// marks the local session revoked. The local state transition is best-effort
// independent of the server call: even if the server call fails (or no
// revocation endpoint is advertised) the token is marked revoked locally, and
// the server error is surfaced to the caller.
func (m *OAuthManager) RevokeToken(ctx context.Context, serverURL, clientRef, accountID string) error {
	return revokeToken(ctx, m.tokenTable, m.httpDo, m.serverTable, m.clientTable, serverURL, clientRef, accountID)
}

// DeleteToken removes the stored token for a (server, account) pair. It is
// idempotent: deleting an absent token is not an error.
func (m *OAuthManager) DeleteToken(ctx context.Context, serverURL, clientRef, accountID string) error {
	return deleteToken(ctx, m.tokenTable, serverURL, clientRef, accountID)
}

// GetSessionState returns the lifecycle state of the stored token for a
// (server, account) pair. A missing token yields a NotFound error.
func (m *OAuthManager) GetSessionState(ctx context.Context, serverURL, clientRef, accountID string) (SessionState, error) {
	return getSessionState(ctx, m.tokenTable, serverURL, clientRef, accountID)
}

// ListTokens returns the stored tokens for a given (server, clientRef) pair. The
// primary use case is token invalidation when a static client is removed, so the
// listing is always scoped to a single ClientRef (dynamic callers pass ""). When
// serverURL is empty the listing spans every server for that ClientRef.
func (m *OAuthManager) ListTokens(ctx context.Context, serverURL string, clientRef string) ([]*TokenEntry, error) {
	return listTokens(ctx, m.tokenTable, serverURL, clientRef)
}

// refreshToken performs the token-refresh exchange (RFC 6749 §6) with the
// authorization server and maps the outcome to a refreshed *TokenEntry or a
// classified error (errPermanentRefresh for invalid_grant / invalid_client,
// otherwise a transient error). It performs NO locking and NO persistence: both
// the proactive token-refresh reconciler (AUTH-0003) and the on-demand
// lock-guarded path (lockedRefresh) call it as the single shared exchange so
// error classification is identical everywhere, and each owns the surrounding
// lock and persistence. It is wired into the reconciler by NewOAuthManager.
func (m *OAuthManager) refreshToken(ctx context.Context, key *TokenKey, entry *TokenEntry) (*TokenEntry, error) {
	return refreshTokenExchange(ctx, m.httpDo, m.serverTable, m.clientTable, key, entry)
}

// getToken implements GetToken against the tokenStore/refreshLockerAPI/refreshFunc
// interfaces so it is unit-testable with fakes.
func getToken(ctx context.Context, tokens tokenStore, locks refreshLockerAPI, refresh refreshFunc, serverURL, clientRef, accountID string) (*TokenEntry, error) {
	key, err := tokenKeyFor(serverURL, clientRef, accountID)
	if err != nil {
		return nil, err
	}
	entry, err := tokens.Find(ctx, key)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.Wrapf(errors.NotFound, "oauth: no token for %s", key.id())
		}
		return nil, err
	}

	// A revoked session cannot be refreshed back to life; hand it back as-is so
	// the caller can detect it and re-authorize.
	if entry.State == SessionRevoked {
		return entry, nil
	}

	if !tokenNeedsRefresh(entry, time.Now()) {
		return entry, nil
	}
	return lockedRefresh(ctx, tokens, locks, refresh, key, false)
}

// forceRefresh implements RefreshToken: a lock-guarded refresh regardless of
// remaining lifetime.
func forceRefresh(ctx context.Context, tokens tokenStore, locks refreshLockerAPI, refresh refreshFunc, serverURL, clientRef, accountID string) (*TokenEntry, error) {
	key, err := tokenKeyFor(serverURL, clientRef, accountID)
	if err != nil {
		return nil, err
	}
	return lockedRefresh(ctx, tokens, locks, refresh, key, true)
}

// lockedRefresh is the shared on-demand refresh path used by GetToken and
// RefreshToken. It mirrors the reconciler's lock discipline: acquire the
// per-(server,account) token-refresh lock, re-read the token under the lock
// (another replica or the reconciler may have refreshed it already), then run
// the shared exchange and apply the correct session-state transition:
//
//	success        → persist refreshed token (state=active)
//	invalid_grant  → state=revoked, surface the error (re-authorization required)
//	invalid_client → state=revoked, surface the error
//	transient err  → state=failed, keep the existing token, surface the error
//
// When force is false the re-read short-circuits if the token is no longer near
// expiry, returning the fresh token without a network call.
func lockedRefresh(ctx context.Context, tokens tokenStore, locks refreshLockerAPI, refresh refreshFunc, key *TokenKey, force bool) (*TokenEntry, error) {
	lock, err := locks.TryAcquire(ctx, &TokenRefreshLockKey{ServerURL: key.ServerURL, ClientRef: key.ClientRef, AccountID: key.AccountID})
	if err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err),
			"oauth: could not acquire token-refresh lock for %s: %s", key.id(), err)
	}
	defer func() {
		if cerr := lock.Close(); cerr != nil {
			log.Printf("oauth: failed to release token-refresh lock for %s: %s", key.id(), cerr)
		}
	}()

	// Re-read under the lock — another instance may have refreshed already.
	entry, err := tokens.Find(ctx, key)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.Wrapf(errors.NotFound, "oauth: no token for %s", key.id())
		}
		return nil, err
	}
	// A revoked session cannot be refreshed back to life — even a forced
	// refresh. A concurrent RevokeToken (or a permanent failure on another
	// replica) may have revoked it between the caller's initial read and this
	// locked re-read; hand it back as-is so the caller re-authorizes instead of
	// reactivating it with a still-accepted refresh token.
	if entry.State == SessionRevoked {
		return entry, nil
	}
	if !force && !tokenNeedsRefresh(entry, time.Now()) {
		return entry, nil
	}

	updated, err := refresh(ctx, key, entry)
	if err != nil {
		// Classify and record the failed state, then surface the error. State
		// persistence is best-effort: the refresh error is the caller's primary
		// signal, so a persistence failure is logged rather than masking it.
		if errors.Is(err, errPermanentRefresh) {
			entry.State = SessionRevoked
		} else {
			entry.State = SessionFailed
		}
		entry.ErrorReason = err.Error()
		if uerr := tokens.Update(ctx, key, entry); uerr != nil {
			log.Printf("oauth: failed to persist state %d for %s after refresh failure: %s",
				entry.State, key.id(), uerr)
		}
		return nil, err
	}
	if updated == nil {
		return nil, errors.Wrap(errors.Unknown, "oauth: refresh returned a nil token without an error")
	}
	// RevokeToken does not take this lock, so a revoke can land during the
	// network-bound exchange above: it would read the pre-refresh active entry,
	// revoke at the server, and persist SessionRevoked while we were waiting on
	// the token endpoint. Re-read under the lock before persisting — if the
	// session was revoked in that window, a still-accepted refresh token must NOT
	// resurrect it; hand back the revoked entry and discard the refresh result.
	if current, rerr := tokens.Find(ctx, key); rerr == nil && current.State == SessionRevoked {
		return current, nil
	}
	if err := tokens.Update(ctx, key, updated); err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err),
			"oauth: failed to persist refreshed token for %s: %s", key.id(), err)
	}
	return updated, nil
}

// refreshTokenExchange performs the RFC 6749 §6 refresh_token grant for a public
// client and builds the refreshed TokenEntry. A missing refresh token, or an
// invalid_grant / invalid_client response, is a permanent failure
// (errPermanentRefresh); other failures are transient.
func refreshTokenExchange(ctx context.Context, do httpDoFunc, servers serverCache, clients clientStore, key *TokenKey, entry *TokenEntry) (*TokenEntry, error) {
	if strings.TrimSpace(entry.RefreshToken) == "" {
		// No refresh token to present — the session can only be restored by a
		// fresh authorization, so treat it as permanent.
		return nil, fmt.Errorf("oauth: no refresh token stored for %s: %w",
			key.id(), errPermanentRefresh)
	}

	server, err := getCachedServer(ctx, servers, key.ServerURL)
	if err != nil {
		return nil, err
	}
	if server == nil || server.TokenEndpoint == "" {
		return nil, errors.Wrapf(errors.InvalidArgument,
			"oauth: server %s has no usable token endpoint", key.ServerURL)
	}

	client, err := findClient(ctx, clients, key.ServerURL, key.ClientRef)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.Wrapf(errors.NotFound,
			"oauth: no registered client for %s; cannot refresh", key.ServerURL)
	}

	form := url.Values{}
	form.Set("grant_type", grantTypeRefreshToken)
	form.Set("refresh_token", entry.RefreshToken)
	attachClientAuth(form, client)
	// Deliberately omit `scope`: per RFC 6749 §6 an omitted scope means the new
	// token keeps exactly the scope originally granted — the same result echoing
	// the stored scopes would aim for, but without tripping authorization servers
	// that reject an explicit scope on refresh. The granted scope is preserved
	// from the response (or the prior entry) in refreshedTokenEntry.

	tr, err := postTokenEndpoint(ctx, do, server.TokenEndpoint, form)
	if err != nil {
		return nil, err
	}
	if tr.AccessToken == "" {
		return nil, errors.Wrapf(errors.InvalidArgument,
			"oauth: refresh response for %s did not include an access_token", key.ServerURL)
	}
	return refreshedTokenEntry(entry, tr, time.Now()), nil
}

// refreshedTokenEntry builds the updated TokenEntry from a refresh response,
// preserving prior values the server omits. Per RFC 6749 §6 the response MAY
// omit refresh_token (the existing one stays valid); token_type and id_token are
// likewise retained when absent. State resets to active and LastRefresh records
// the instant for the reconciler's lifetime-fraction heuristic.
func refreshedTokenEntry(prev *TokenEntry, tr *tokenResponse, now time.Time) *TokenEntry {
	updated := *prev
	updated.AccessToken = tr.AccessToken
	if tr.TokenType != "" {
		updated.TokenType = tr.TokenType
	}
	if tr.RefreshToken != "" {
		updated.RefreshToken = tr.RefreshToken
	}
	if tr.IDToken != "" {
		updated.IDToken = tr.IDToken
	}
	updated.Scopes = preferStrings(strings.Fields(tr.Scope), prev.Scopes)
	updated.State = SessionActive
	updated.ErrorReason = ""
	updated.LastRefresh = now.Unix()
	// Always recompute the expiry from this response. ExpiresAt is reset rather
	// than inherited from prev: a response that omits expires_in (RFC 6749 §5.1,
	// optional) leaves the expiry unknown, which we treat as non-expiring (no
	// proactive refresh) — same as newTokenEntry for the initial exchange.
	// Retaining the stale prior (now-past) expiry would make the freshly
	// refreshed token look immediately expired and drive the reconciler into a
	// tight re-refresh loop.
	if tr.ExpiresIn > 0 {
		updated.ExpiresAt = now.Add(time.Duration(tr.ExpiresIn) * time.Second).Unix()
	} else {
		updated.ExpiresAt = 0
	}
	return &updated
}

// revokeToken implements RevokeToken against the tokenStore/serverCache/
// clientStore/httpDoFunc interfaces so it is unit-testable with fakes.
func revokeToken(ctx context.Context, tokens tokenStore, do httpDoFunc, servers serverCache, clients clientStore, serverURL, clientRef, accountID string) error {
	key, err := tokenKeyFor(serverURL, clientRef, accountID)
	if err != nil {
		return err
	}
	entry, err := tokens.Find(ctx, key)
	if err != nil {
		if errors.IsNotFound(err) {
			return errors.Wrapf(errors.NotFound, "oauth: no token for %s", key.id())
		}
		return err
	}

	// Already revoked — nothing to revoke at the server and no state change to
	// persist; return without a round-trip.
	if entry.State == SessionRevoked {
		return nil
	}

	// Best-effort server-side revocation; the result does not gate the local
	// state transition.
	serverErr := revokeAtServer(ctx, do, servers, clients, key, entry)

	entry.State = SessionRevoked
	if serverErr != nil {
		entry.ErrorReason = serverErr.Error()
	}
	if uerr := tokens.Update(ctx, key, entry); uerr != nil {
		return errors.Wrapf(errors.GetErrCode(uerr),
			"oauth: failed to mark token revoked for %s: %s", key.id(), uerr)
	}
	// Surface the server error (if any) so the caller knows server-side
	// revocation did not complete, even though the local session is revoked.
	return serverErr
}

// revokeAtServer POSTs an RFC 7009 revocation request, preferring the refresh
// token (which revokes the whole grant) and falling back to the access token. A
// server that advertises no revocation endpoint yields a clear error so the
// caller learns the token was not revoked server-side.
func revokeAtServer(ctx context.Context, do httpDoFunc, servers serverCache, clients clientStore, key *TokenKey, entry *TokenEntry) error {
	server, err := getCachedServer(ctx, servers, key.ServerURL)
	if err != nil {
		return err
	}
	if server == nil || server.RevocationEndpoint == "" {
		return errors.Wrapf(errors.InvalidArgument,
			"oauth: server %s does not advertise a revocation endpoint", key.ServerURL)
	}

	token, hint := entry.RefreshToken, tokenTypeHintRefresh
	if token == "" {
		token, hint = entry.AccessToken, tokenTypeHintAccess
	}
	if token == "" {
		return errors.Wrapf(errors.InvalidArgument,
			"oauth: token for %s has nothing to revoke", key.id())
	}

	form := url.Values{}
	form.Set("token", token)
	form.Set("token_type_hint", hint)

	client, err := findClient(ctx, clients, key.ServerURL, key.ClientRef)
	if err != nil {
		return err
	}
	if client != nil {
		attachClientAuth(form, client)
	}

	return postRevocation(ctx, do, server.RevocationEndpoint, form)
}

// deleteToken implements DeleteToken: an idempotent remove (a missing entry is
// not an error).
func deleteToken(ctx context.Context, tokens tokenStore, serverURL, clientRef, accountID string) error {
	key, err := tokenKeyFor(serverURL, clientRef, accountID)
	if err != nil {
		return err
	}
	if err := tokens.DeleteKey(ctx, key); err != nil && !errors.IsNotFound(err) {
		return errors.Wrapf(errors.GetErrCode(err),
			"oauth: failed to delete token for %s: %s", key.id(), err)
	}
	return nil
}

// getSessionState implements GetSessionState.
func getSessionState(ctx context.Context, tokens tokenStore, serverURL, clientRef, accountID string) (SessionState, error) {
	key, err := tokenKeyFor(serverURL, clientRef, accountID)
	if err != nil {
		// State is meaningless on the error path; callers must check err first.
		return 0, err
	}
	entry, err := tokens.Find(ctx, key)
	if err != nil {
		if errors.IsNotFound(err) {
			return 0, errors.Wrapf(errors.NotFound, "oauth: no token for %s", key.id())
		}
		return 0, err
	}
	return entry.State, nil
}

// listTokens implements ListTokens. The listing is scoped to a single clientRef
// on the token key (_id): an empty serverURL spans every server for that
// clientRef, a non-empty one also filters by the normalized server URL. A zero
// limit means no limit.
//
// The clientRef filter is asymmetric. A non-empty clientRef is a plain equality.
// The dynamic case (clientRef == "") must NOT use a naive {"_id.clientRef": ""}:
// dynamic token documents omit clientRef entirely (the omitempty BSON tag), and
// in MongoDB an equality against "" does not match a document that lacks the
// field. Match absent-or-empty explicitly with $in:["",nil] instead. (Point
// lookups — GetToken/DeleteToken/etc. — marshal the full TokenKey _id with
// omitempty, so they already match correctly and need no special-casing; this
// asymmetry is unique to ListTokens' partial filter.)
func listTokens(ctx context.Context, tokens tokenStore, serverURL string, clientRef string) ([]*TokenEntry, error) {
	filter := bson.M{}
	if clientRef == "" {
		filter["_id.clientRef"] = bson.M{"$in": bson.A{"", nil}}
	} else {
		filter["_id.clientRef"] = clientRef
	}
	if normalized := normalizeServerURL(serverURL); normalized != "" {
		filter["_id.serverUrl"] = normalized
	}
	entries, err := tokens.FindMany(ctx, filter, 0, 0)
	if err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err), "oauth: failed to list tokens: %s", err)
	}
	return entries, nil
}

// tokenKeyFor validates the inputs and builds a normalized token key. clientRef
// is the consumer-defined opaque label disambiguating multiple clients for the
// same server; dynamic registration passes "" (omitted from the stored key by
// the omitempty BSON tag).
func tokenKeyFor(serverURL, clientRef, accountID string) (*TokenKey, error) {
	normalized := normalizeServerURL(serverURL)
	if normalized == "" {
		return nil, errors.Wrap(errors.InvalidArgument, "oauth: serverURL must not be empty")
	}
	if strings.TrimSpace(accountID) == "" {
		return nil, errors.Wrap(errors.InvalidArgument, "oauth: accountID must not be empty")
	}
	return &TokenKey{ServerURL: normalized, ClientRef: clientRef, AccountID: accountID}, nil
}

// id renders the token key as a human-readable identity for diagnostics:
// "serverURL/clientRef/accountID". A dynamic client's empty ClientRef renders as
// an empty middle segment ("serverURL//accountID"), which unambiguously signals
// the dynamic slot and disambiguates the message once multiple clients can share
// a (server, account) pair.
func (k *TokenKey) id() string {
	return fmt.Sprintf("%s/%s/%s", k.ServerURL, k.ClientRef, k.AccountID)
}

// postTokenEndpoint POSTs a form-encoded token request and, on success, decodes
// the JSON token response. On a non-2xx response it parses the RFC 6749 §5.2
// error body and classifies invalid_grant / invalid_client as permanent
// (errPermanentRefresh); every other failure is returned as a transient error.
// The response body is bounded by maxMetadataBytes.
func postTokenEndpoint(ctx context.Context, do httpDoFunc, endpoint string, form url.Values) (*tokenResponse, error) {
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
	limited := io.LimitReader(resp.Body, maxMetadataBytes)
	defer func() {
		_, _ = io.Copy(io.Discard, limited)
		_ = resp.Body.Close()
	}()

	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, errors.Wrapf(errors.Unknown, "oauth: failed to read response from %s: %s", endpoint, err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, classifyTokenError(endpoint, resp.StatusCode, raw)
	}

	var tr tokenResponse
	if err := json.Unmarshal(raw, &tr); err != nil {
		return nil, errors.Wrapf(errors.InvalidArgument, "oauth: failed to parse token response from %s: %s", endpoint, err)
	}
	return &tr, nil
}

// classifyTokenError turns a non-2xx token-endpoint response into a permanent
// (errPermanentRefresh) or transient error, based on the RFC 6749 §5.2 error
// code when present.
func classifyTokenError(endpoint string, status int, body []byte) error {
	var oe oauthErrorResponse
	_ = json.Unmarshal(body, &oe) // body may be empty or non-JSON; best-effort

	if oe.ErrorCode == oauthErrInvalidGrant || oe.ErrorCode == oauthErrInvalidClient {
		detail := oe.ErrorCode
		if oe.ErrorDescription != "" {
			detail = fmt.Sprintf("%s: %s", oe.ErrorCode, oe.ErrorDescription)
		}
		return fmt.Errorf("oauth: %s rejected refresh (HTTP %d, %s): %w",
			endpoint, status, detail, errPermanentRefresh)
	}

	if oe.ErrorCode != "" {
		return errors.Wrapf(errors.Unknown, "oauth: %s returned HTTP %d (%s)", endpoint, status, oe.ErrorCode)
	}
	return errors.Wrapf(errors.Unknown, "oauth: %s returned HTTP status %d", endpoint, status)
}

// postRevocation POSTs an RFC 7009 revocation request and treats any 2xx as
// success. The endpoint returns no useful body (RFC 7009 §2.2), so the bounded
// body is drained and discarded.
func postRevocation(ctx context.Context, do httpDoFunc, endpoint string, form url.Values) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.Wrapf(errors.InvalidArgument, "oauth: failed to build revocation request for %s: %s", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := do(req)
	if err != nil {
		return errors.Wrapf(errors.Unknown, "oauth: revocation request to %s failed: %s", endpoint, err)
	}
	limited := io.LimitReader(resp.Body, maxMetadataBytes)
	defer func() {
		_, _ = io.Copy(io.Discard, limited)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return errors.Wrapf(errors.Unknown, "oauth: %s returned HTTP status %d", endpoint, resp.StatusCode)
	}
	return nil
}
