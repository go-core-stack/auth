// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"context"
	"log"
	"time"

	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/reconciler"
	coresync "github.com/go-core-stack/core/sync"
)

// Reconciler controller names registered with the embedded
// reconciler.ManagerImpl on the respective tables.
const (
	pendingStateReconcilerName = "oauth-pending-state-cleanup"
	tokenRefreshReconcilerName = "oauth-token-refresh"

	// transientRefreshBackoff is the fixed delay before re-attempting a token
	// refresh that failed transiently. The core reconciler pipeline re-enqueues
	// a key immediately (no backoff) when Reconcile returns a bare error, which
	// would hot-loop the token endpoint during a sustained outage; so for
	// transient failures the reconciler requeues with this delay instead of
	// returning an error. AUTH-0007 may refine this into a jittered/exponential
	// backoff once it classifies refresh failures.
	transientRefreshBackoff = 30 * time.Second
)

// Sentinel refresh errors used by the token reconciler to decide between
// stopping (permanent), retrying (transient), and deferring (not-yet-wired).
var (
	// errRefreshNotImplemented is returned by the placeholder refresh helper
	// until AUTH-0007 implements the real HTTP refresh exchange. The reconciler
	// treats it specially so the skeleton wires through without hot-looping.
	errRefreshNotImplemented = errors.New("oauth: token refresh not yet implemented (AUTH-0007)")

	// errPermanentRefresh marks a refresh failure that must not be retried
	// (e.g. an invalid_grant response). The reconciler revokes the session and
	// stops reconciling.
	//
	// AUTH-0007 must surface this sentinel so errors.Is matches: either return
	// it directly, or wrap with fmt.Errorf("...: %w", errPermanentRefresh).
	// Do NOT wrap it via core/errors.Wrap — that type does not implement
	// Unwrap, so errors.Is would not match and the revoke path would be missed.
	errPermanentRefresh = errors.New("oauth: permanent refresh failure (re-authorization required)")
)

// --- minimal table/lock dependencies (kept small so reconcilers are unit
// testable with fakes; *table.Table and *sync.LockTable satisfy these and the
// db.StoreCollection interface — which carries an unexported method — never
// needs to be mocked). ---

// pendingStateTableAPI is the subset of the pending-auth-state table the
// stale-state cleanup reconciler needs.
type pendingStateTableAPI interface {
	Find(ctx context.Context, key *PendingAuthStateKey) (*PendingAuthState, error)
	DeleteKey(ctx context.Context, key *PendingAuthStateKey) error
}

// tokenTableAPI is the subset of the token table the refresh reconciler needs.
type tokenTableAPI interface {
	Find(ctx context.Context, key *TokenKey) (*TokenEntry, error)
	Update(ctx context.Context, key *TokenKey, entry *TokenEntry) error
}

// refreshLockerAPI is the subset of the token-refresh lock table the refresh
// reconciler needs.
type refreshLockerAPI interface {
	TryAcquire(ctx context.Context, key *TokenRefreshLockKey) (coresync.Lock, error)
}

// refreshFunc performs the actual refresh exchange for a token. It is pluggable
// so AUTH-0007 can supply the real implementation and tests can substitute a
// fake.
type refreshFunc func(ctx context.Context, key *TokenKey, entry *TokenEntry) (*TokenEntry, error)

// --- stale-state cleanup reconciler (pending_auth_states) ---

// pendingStateReconciler actively removes expired pending authorization states,
// complementing the MongoDB TTL index (which may lag) and re-enqueuing valid
// entries to be cleaned up exactly when they expire.
type pendingStateReconciler struct {
	table pendingStateTableAPI
}

// Reconcile implements reconciler.Controller for pending auth states.
func (r *pendingStateReconciler) Reconcile(k any) (*reconciler.Result, error) {
	key, ok := k.(*PendingAuthStateKey)
	if !ok {
		return nil, errors.Wrapf(errors.InvalidArgument, "pending-state reconciler: unexpected key type %T", k)
	}

	ctx := context.Background()
	entry, err := r.table.Find(ctx, key)
	if err != nil {
		if errors.IsNotFound(err) {
			// already gone — nothing to clean up
			return nil, nil
		}
		return nil, err
	}

	now := time.Now()
	expiry := entry.CreatedAt.Add(PendingStateTTL)
	if !expiry.After(now) {
		// expired — delete and stop reconciling this key
		if err := r.table.DeleteKey(ctx, key); err != nil && !errors.IsNotFound(err) {
			return nil, err
		}
		return nil, nil
	}

	// still valid — requeue for cleanup exactly when it expires
	return &reconciler.Result{RequeueAfter: expiry.Sub(now)}, nil
}

// --- token-refresh reconciler (tokens) ---

// tokenRefreshReconciler proactively refreshes tokens before they expire so that
// consumers reading via GetToken (AUTH-0007) almost always see a fresh token.
type tokenRefreshReconciler struct {
	tokens  tokenTableAPI
	locks   refreshLockerAPI
	refresh refreshFunc
}

// Reconcile implements reconciler.Controller for tokens.
func (r *tokenRefreshReconciler) Reconcile(k any) (*reconciler.Result, error) {
	key, ok := k.(*TokenKey)
	if !ok {
		return nil, errors.Wrapf(errors.InvalidArgument, "token reconciler: unexpected key type %T", k)
	}

	ctx := context.Background()
	entry, err := r.tokens.Find(ctx, key)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	// revoked tokens are dead — stop reconciling
	if entry.State == SessionRevoked {
		return nil, nil
	}

	now := time.Now()

	// A NoRefresh token must never be auto-refreshed. With no expiry there is
	// nothing left to track — stop reconciling entirely so offline tokens are
	// not churned forever. With an expiry, keep requeuing for state bookkeeping
	// but never attempt a refresh.
	if entry.RefreshPolicy == RefreshPolicyNoRefresh {
		if entry.ExpiresAt == 0 {
			return nil, nil
		}
		return &reconciler.Result{RequeueAfter: timeUntilRefresh(entry, now)}, nil
	}

	if !tokenNeedsRefresh(entry, now) {
		// healthy — re-check when it approaches the refresh threshold
		return &reconciler.Result{RequeueAfter: timeUntilRefresh(entry, now)}, nil
	}

	// near expiry — serialize refresh across instances with a distributed lock.
	// The lock key carries ClientRef (sourced from the token key) so a static
	// client's refresh does not serialize on the dynamic slot — or another
	// client — for the same (server, account) pair.
	lock, err := r.locks.TryAcquire(ctx, &TokenRefreshLockKey{ServerURL: key.ServerURL, ClientRef: key.ClientRef, AccountID: key.AccountID})
	if err != nil {
		// another instance is refreshing (or the lock is briefly contended);
		// back off and retry rather than spinning
		return &reconciler.Result{RequeueAfter: RefreshThreshold}, nil
	}
	defer func() {
		if cerr := lock.Close(); cerr != nil {
			log.Printf("oauth: failed to release token-refresh lock for %s: %s", key.id(), cerr)
		}
	}()

	// re-read under the lock — another instance may have refreshed already
	entry, err = r.tokens.Find(ctx, key)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if entry.State == SessionRevoked {
		return nil, nil
	}
	now = time.Now()
	if !tokenNeedsRefresh(entry, now) {
		return &reconciler.Result{RequeueAfter: timeUntilRefresh(entry, now)}, nil
	}

	updated, err := r.refresh(ctx, key, entry)
	if err != nil {
		switch {
		case errors.Is(err, errPermanentRefresh):
			// permanent — revoke the session and stop reconciling
			entry.State = SessionRevoked
			entry.ErrorReason = err.Error()
			if uerr := r.tokens.Update(ctx, key, entry); uerr != nil {
				return nil, uerr
			}
			return nil, nil
		case errors.Is(err, errRefreshNotImplemented):
			// AUTH-0007 will wire the real exchange; defer to avoid a hot loop
			log.Printf("oauth: token refresh not yet implemented (AUTH-0007); deferring %s", key.id())
			return &reconciler.Result{RequeueAfter: RefreshThreshold}, nil
		default:
			// transient — requeue with a backoff rather than returning a bare
			// error (which the pipeline would re-enqueue immediately, hot-looping
			// the token endpoint during a sustained outage)
			log.Printf("oauth: transient token-refresh failure for %s, retrying in %s: %s",
				key.id(), transientRefreshBackoff, err)
			return &reconciler.Result{RequeueAfter: transientRefreshBackoff}, nil
		}
	}

	if updated == nil {
		// defensive: a refresh implementation must return a token on success
		return nil, errors.Wrap(errors.Unknown, "oauth: refresh returned a nil token without an error")
	}
	if err := r.tokens.Update(ctx, key, updated); err != nil {
		return nil, err
	}
	return &reconciler.Result{RequeueAfter: timeUntilRefresh(updated, time.Now())}, nil
}

// tokenNeedsRefresh reports whether a token is close enough to expiry to warrant
// a proactive refresh: already expired, within RefreshThreshold of expiry, or
// past RefreshLifetimeFraction of its observed lifetime (when an issuance
// reference is available via LastRefresh).
func tokenNeedsRefresh(e *TokenEntry, now time.Time) bool {
	if e.ExpiresAt == 0 {
		// no expiry information — nothing to refresh proactively
		return false
	}
	expiry := time.Unix(e.ExpiresAt, 0)
	if !expiry.After(now) {
		return true // already expired
	}
	if expiry.Sub(now) <= RefreshThreshold {
		return true
	}
	if e.LastRefresh > 0 {
		issued := time.Unix(e.LastRefresh, 0)
		if lifetime := expiry.Sub(issued); lifetime > 0 {
			if float64(now.Sub(issued)) >= RefreshLifetimeFraction*float64(lifetime) {
				return true
			}
		}
	}
	return false
}

// timeUntilRefresh returns how long until a healthy token should next be
// evaluated for refresh. It never returns a non-positive duration (which would
// cause an immediate requeue spin); a token already at the threshold returns a
// small floor.
func timeUntilRefresh(e *TokenEntry, now time.Time) time.Duration {
	if e.ExpiresAt == 0 {
		return RefreshThreshold
	}
	expiry := time.Unix(e.ExpiresAt, 0)
	d := expiry.Sub(now) - RefreshThreshold
	if d < time.Second {
		return time.Second
	}
	return d
}
