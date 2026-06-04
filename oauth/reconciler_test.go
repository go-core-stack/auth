// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/go-core-stack/core/errors"
	coresync "github.com/go-core-stack/core/sync"
)

// --- fakes (the small table/lock interfaces are mockable; db.StoreCollection,
// which carries an unexported method, is not — hence the reconcilers depend on
// these narrow interfaces) ---

type fakePendingTable struct {
	entry     *PendingAuthState
	findErr   error
	deleted   []PendingAuthStateKey
	deleteErr error
}

func (f *fakePendingTable) Find(_ context.Context, _ *PendingAuthStateKey) (*PendingAuthState, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	cp := *f.entry
	return &cp, nil
}

func (f *fakePendingTable) DeleteKey(_ context.Context, key *PendingAuthStateKey) error {
	f.deleted = append(f.deleted, *key)
	return f.deleteErr
}

type fakeTokenTable struct {
	entries     map[TokenKey]*TokenEntry
	findCalls   int
	updateCalls int
}

func newFakeTokenTable() *fakeTokenTable {
	return &fakeTokenTable{entries: map[TokenKey]*TokenEntry{}}
}

func (f *fakeTokenTable) Find(_ context.Context, key *TokenKey) (*TokenEntry, error) {
	f.findCalls++
	e, ok := f.entries[*key]
	if !ok {
		return nil, errors.Wrap(errors.NotFound, "token not found")
	}
	cp := *e
	return &cp, nil
}

func (f *fakeTokenTable) Update(_ context.Context, key *TokenKey, entry *TokenEntry) error {
	f.updateCalls++
	cp := *entry
	f.entries[*key] = &cp
	return nil
}

type fakeLock struct{ closed bool }

func (l *fakeLock) Close() error { l.closed = true; return nil }

type fakeLocker struct {
	acquireErr error
	lock       *fakeLock
	acquired   int
	lastKey    *TokenRefreshLockKey
}

func (f *fakeLocker) TryAcquire(_ context.Context, key *TokenRefreshLockKey) (coresync.Lock, error) {
	f.acquired++
	f.lastKey = key
	if f.acquireErr != nil {
		return nil, f.acquireErr
	}
	f.lock = &fakeLock{}
	return f.lock, nil
}

// --- stale-state cleanup reconciler ---

func TestPendingStateReconciler_DeletesExpired(t *testing.T) {
	ft := &fakePendingTable{
		entry: &PendingAuthState{
			ServerURL: "https://example.com",
			CreatedAt: time.Now().Add(-2 * PendingStateTTL), // long expired
		},
	}
	r := &pendingStateReconciler{table: ft}

	res, err := r.Reconcile(&PendingAuthStateKey{State: "abc"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != nil {
		t.Errorf("expected no requeue for expired entry, got %+v", res)
	}
	if len(ft.deleted) != 1 || ft.deleted[0].State != "abc" {
		t.Errorf("expected expired entry deleted, got %+v", ft.deleted)
	}
}

func TestPendingStateReconciler_RequeuesValid(t *testing.T) {
	ft := &fakePendingTable{
		entry: &PendingAuthState{
			ServerURL: "https://example.com",
			CreatedAt: time.Now(), // fresh — ~full TTL remaining
		},
	}
	r := &pendingStateReconciler{table: ft}

	res, err := r.Reconcile(&PendingAuthStateKey{State: "abc"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ft.deleted) != 0 {
		t.Errorf("valid entry should not be deleted, got %+v", ft.deleted)
	}
	if res == nil || res.RequeueAfter <= 0 || res.RequeueAfter > PendingStateTTL {
		t.Errorf("expected requeue within TTL, got %+v", res)
	}
}

func TestPendingStateReconciler_NotFoundIsNoOp(t *testing.T) {
	ft := &fakePendingTable{findErr: errors.Wrap(errors.NotFound, "gone")}
	r := &pendingStateReconciler{table: ft}

	res, err := r.Reconcile(&PendingAuthStateKey{State: "abc"})
	if err != nil || res != nil {
		t.Fatalf("expected (nil,nil) for missing entry, got res=%+v err=%v", res, err)
	}
	if len(ft.deleted) != 0 {
		t.Errorf("nothing should be deleted, got %+v", ft.deleted)
	}
}

func TestPendingStateReconciler_WrongKeyType(t *testing.T) {
	r := &pendingStateReconciler{table: &fakePendingTable{}}
	if _, err := r.Reconcile("not-a-key"); err == nil {
		t.Fatal("expected error for unexpected key type")
	}
}

// --- token-refresh reconciler ---

func tokenKey() *TokenKey { return &TokenKey{ServerURL: "https://example.com", AccountID: "user-1"} }

func TestTokenReconciler_RevokedIsDead(t *testing.T) {
	ft := newFakeTokenTable()
	ft.entries[*tokenKey()] = &TokenEntry{State: SessionRevoked, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	fl := &fakeLocker{}
	r := &tokenRefreshReconciler{tokens: ft, locks: fl, refresh: failRefresh(t)}

	res, err := r.Reconcile(tokenKey())
	if err != nil || res != nil {
		t.Fatalf("expected (nil,nil) for revoked token, got res=%+v err=%v", res, err)
	}
	if fl.acquired != 0 {
		t.Errorf("revoked token must not acquire the refresh lock")
	}
}

func TestTokenReconciler_HealthyRequeues(t *testing.T) {
	ft := newFakeTokenTable()
	ft.entries[*tokenKey()] = &TokenEntry{State: SessionActive, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	fl := &fakeLocker{}
	r := &tokenRefreshReconciler{tokens: ft, locks: fl, refresh: failRefresh(t)}

	res, err := r.Reconcile(tokenKey())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.RequeueAfter <= 0 {
		t.Errorf("healthy token should requeue with positive delay, got %+v", res)
	}
	if fl.acquired != 0 {
		t.Errorf("healthy token must not acquire the refresh lock")
	}
}

func TestTokenReconciler_NearExpiryRefreshSuccess(t *testing.T) {
	ft := newFakeTokenTable()
	ft.entries[*tokenKey()] = &TokenEntry{State: SessionActive, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	fl := &fakeLocker{}

	refreshed := &TokenEntry{State: SessionActive, AccessToken: "new", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	r := &tokenRefreshReconciler{
		tokens: ft,
		locks:  fl,
		refresh: func(_ context.Context, _ *TokenKey, _ *TokenEntry) (*TokenEntry, error) {
			return refreshed, nil
		},
	}

	res, err := r.Reconcile(tokenKey())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.RequeueAfter <= 0 {
		t.Errorf("expected requeue after successful refresh, got %+v", res)
	}
	if ft.updateCalls != 1 || ft.entries[*tokenKey()].AccessToken != "new" {
		t.Errorf("expected token updated with refreshed value, got %+v", ft.entries[*tokenKey()])
	}
	if fl.lock == nil || !fl.lock.closed {
		t.Errorf("refresh lock should be acquired and released")
	}
}

func TestTokenReconciler_PermanentFailureRevokes(t *testing.T) {
	ft := newFakeTokenTable()
	ft.entries[*tokenKey()] = &TokenEntry{State: SessionActive, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	fl := &fakeLocker{}
	r := &tokenRefreshReconciler{
		tokens: ft,
		locks:  fl,
		refresh: func(_ context.Context, _ *TokenKey, _ *TokenEntry) (*TokenEntry, error) {
			return nil, errPermanentRefresh
		},
	}

	res, err := r.Reconcile(tokenKey())
	if err != nil || res != nil {
		t.Fatalf("permanent failure should stop reconciling, got res=%+v err=%v", res, err)
	}
	if got := ft.entries[*tokenKey()]; got.State != SessionRevoked || got.ErrorReason == "" {
		t.Errorf("expected token revoked with reason, got %+v", got)
	}
}

func TestTokenReconciler_TransientFailureBacksOff(t *testing.T) {
	ft := newFakeTokenTable()
	ft.entries[*tokenKey()] = &TokenEntry{State: SessionActive, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	fl := &fakeLocker{}
	transient := errors.Wrap(errors.Unknown, "network blip")
	r := &tokenRefreshReconciler{
		tokens: ft,
		locks:  fl,
		refresh: func(_ context.Context, _ *TokenKey, _ *TokenEntry) (*TokenEntry, error) {
			return nil, transient
		},
	}

	// A transient failure must requeue with a backoff (not return a bare error,
	// which the pipeline would re-enqueue immediately and hot-loop).
	res, err := r.Reconcile(tokenKey())
	if err != nil {
		t.Fatalf("transient failure should not surface as an error, got %v", err)
	}
	if res == nil || res.RequeueAfter != transientRefreshBackoff {
		t.Errorf("expected backoff requeue of %s, got %+v", transientRefreshBackoff, res)
	}
	if ft.updateCalls != 0 {
		t.Errorf("transient failure must not mutate the token")
	}
}

func TestTokenReconciler_NotImplementedDefers(t *testing.T) {
	ft := newFakeTokenTable()
	ft.entries[*tokenKey()] = &TokenEntry{State: SessionActive, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	fl := &fakeLocker{}
	// the default stub refresh returns errRefreshNotImplemented
	r := &tokenRefreshReconciler{
		tokens: ft,
		locks:  fl,
		refresh: func(_ context.Context, _ *TokenKey, _ *TokenEntry) (*TokenEntry, error) {
			return nil, errRefreshNotImplemented
		},
	}

	res, err := r.Reconcile(tokenKey())
	if err != nil {
		t.Fatalf("not-implemented should not surface as an error, got %v", err)
	}
	if res == nil || res.RequeueAfter != RefreshThreshold {
		t.Errorf("expected deferred requeue of RefreshThreshold, got %+v", res)
	}
	if ft.updateCalls != 0 {
		t.Errorf("not-implemented refresh must not mutate the token")
	}
}

func TestTokenReconciler_LockContentionBacksOff(t *testing.T) {
	ft := newFakeTokenTable()
	ft.entries[*tokenKey()] = &TokenEntry{State: SessionActive, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	fl := &fakeLocker{acquireErr: errors.Wrap(errors.AlreadyExists, "held")}
	r := &tokenRefreshReconciler{tokens: ft, locks: fl, refresh: failRefresh(t)}

	res, err := r.Reconcile(tokenKey())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.RequeueAfter != RefreshThreshold {
		t.Errorf("lock contention should back off by RefreshThreshold, got %+v", res)
	}
}

func TestTokenReconciler_NilRefreshResultErrors(t *testing.T) {
	ft := newFakeTokenTable()
	ft.entries[*tokenKey()] = &TokenEntry{State: SessionActive, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	fl := &fakeLocker{}
	r := &tokenRefreshReconciler{
		tokens: ft,
		locks:  fl,
		refresh: func(_ context.Context, _ *TokenKey, _ *TokenEntry) (*TokenEntry, error) {
			return nil, nil // misbehaving refresh: nil token, nil error
		},
	}

	res, err := r.Reconcile(tokenKey())
	if err == nil {
		t.Fatal("expected error when refresh returns a nil token without an error")
	}
	if res != nil {
		t.Errorf("expected no Result alongside the error, got %+v", res)
	}
	if ft.updateCalls != 0 {
		t.Errorf("nil refresh result must not update the token")
	}
}

func TestTokenReconciler_NotFoundIsNoOp(t *testing.T) {
	r := &tokenRefreshReconciler{tokens: newFakeTokenTable(), locks: &fakeLocker{}, refresh: failRefresh(t)}
	res, err := r.Reconcile(tokenKey())
	if err != nil || res != nil {
		t.Fatalf("expected (nil,nil) for missing token, got res=%+v err=%v", res, err)
	}
}

// failRefresh returns a refresh func that fails the test if it is ever called —
// used by cases where refresh must not be attempted.
func failRefresh(t *testing.T) refreshFunc {
	t.Helper()
	return func(_ context.Context, _ *TokenKey, _ *TokenEntry) (*TokenEntry, error) {
		t.Fatal("refresh should not have been called")
		return nil, nil
	}
}

// --- pure helpers ---

func TestTokenNeedsRefresh(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		e    *TokenEntry
		want bool
	}{
		{"no-expiry", &TokenEntry{ExpiresAt: 0}, false},
		{"already-expired", &TokenEntry{ExpiresAt: now.Add(-time.Minute).Unix()}, true},
		{"within-threshold", &TokenEntry{ExpiresAt: now.Add(RefreshThreshold / 2).Unix()}, true},
		{"healthy", &TokenEntry{ExpiresAt: now.Add(time.Hour).Unix()}, false},
		{
			"past-lifetime-fraction",
			&TokenEntry{
				LastRefresh: now.Add(-90 * time.Minute).Unix(),
				ExpiresAt:   now.Add(10 * time.Minute).Unix(), // 90/100 elapsed > 0.8
			},
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tokenNeedsRefresh(tc.e, now); got != tc.want {
				t.Errorf("tokenNeedsRefresh = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTimeUntilRefresh(t *testing.T) {
	now := time.Now()
	// healthy token: due in (1h - threshold)
	d := timeUntilRefresh(&TokenEntry{ExpiresAt: now.Add(time.Hour).Unix()}, now)
	if d <= 0 || d > time.Hour {
		t.Errorf("expected positive delay under an hour, got %v", d)
	}
	// at/!past threshold: floored to >= 1s (never zero to avoid requeue spin)
	d = timeUntilRefresh(&TokenEntry{ExpiresAt: now.Add(RefreshThreshold).Unix()}, now)
	if d < time.Second {
		t.Errorf("expected floored delay >= 1s, got %v", d)
	}
}
