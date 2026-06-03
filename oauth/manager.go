// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"context"
	"net/http"
	"os"

	"github.com/go-core-stack/core/db"
	"github.com/go-core-stack/core/errors"
	coresync "github.com/go-core-stack/core/sync"
	"github.com/go-core-stack/core/table"
	"github.com/go-core-stack/core/utils"
)

// NewOAuthManager is the single initialization entry point for the OAuth client
// library. It wires persistence (4 tables), distributed locking (2 lock tables),
// field-level encryption, the pending-state TTL index, the default HTTP client,
// and the two background reconcilers, returning a fully wired *OAuthManager.
//
// The caller owns the MongoDB connection and chooses which database backs the
// OAuth manager: a db.Store handle is supplied directly (the consumer resolves
// it via its own db.StoreClient.GetDataStore). Distributed locking relies on the
// core sync owner infrastructure, which the consuming service must initialize
// (sync.InitializeOwner) before calling this; otherwise lock-table setup fails
// with a descriptive error.
//
// ctx is used only to create the pending-state TTL index during initialization.
// It does NOT govern the lifetime of the background reconcilers and lock-table
// watchers: those run on core-managed contexts and are torn down with the core
// sync owner infrastructure, not by canceling this ctx.
func NewOAuthManager(ctx context.Context, store db.Store, cfg OAuthConfig) (*OAuthManager, error) {
	if store == nil {
		return nil, errors.Wrap(errors.InvalidArgument, "oauth: db store must not be nil")
	}

	m := &OAuthManager{
		config: cfg,
		db:     store,
	}

	// 1. Encryptor — resolve and register the provider-scoped key BEFORE any
	//    table I/O so the configured key (not the default) encrypts data at
	//    rest. Fails closed when no key is configured (see initManagerEncryptor).
	enc, err := m.initManagerEncryptor(cfg)
	if err != nil {
		return nil, err
	}
	m.encryptor = enc

	// 2. HTTP client default (30s timeout) used by the httpDo helper.
	m.httpClient = cfg.HTTPClient
	if m.httpClient == nil {
		m.httpClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}

	// 3. Pending-state TTL index FIRST. Creating it before any table is
	//    initialized means an index failure fails fast — before core/table
	//    starts the background change-stream watchers (which it has no API to
	//    unwind), shrinking the partially-initialized-watcher window.
	pendingCol := store.GetCollection(PendingAuthStatesCollection)
	if err := pendingCol.EnsureIndexes(ctx, []db.IndexDefinition{
		{
			Name:   "pending-auth-state-ttl",
			Fields: []db.IndexField{{Field: "createdAt", IndexType: db.IndexAscending}},
			TTL:    PendingStateTTL,
		},
	}); err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err), "oauth: failed to ensure pending-auth-state TTL index: %s", err)
	}

	// 4. Tables (each Initialize starts a change-stream watcher).
	m.serverTable = &table.Table[ServerKey, ServerEntry]{}
	if err := m.serverTable.Initialize(store.GetCollection(ServersCollection)); err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err), "oauth: failed to initialize server table: %s", err)
	}
	m.clientTable = &table.Table[ClientKey, ClientEntry]{}
	if err := m.clientTable.Initialize(store.GetCollection(ClientsCollection)); err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err), "oauth: failed to initialize client table: %s", err)
	}
	m.tokenTable = &table.Table[TokenKey, TokenEntry]{}
	if err := m.tokenTable.Initialize(store.GetCollection(TokensCollection)); err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err), "oauth: failed to initialize token table: %s", err)
	}
	m.pendingTable = &table.Table[PendingAuthStateKey, PendingAuthState]{}
	if err := m.pendingTable.Initialize(pendingCol); err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err), "oauth: failed to initialize pending-auth-state table: %s", err)
	}

	// 5. Lock tables (distributed locking across instances).
	m.registrationLocks, err = coresync.LocateLockTable[RegistrationLockKey](store, RegistrationLockTable)
	if err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err),
			"oauth: failed to initialize registration lock table (is sync owner infra initialized?): %s", err)
	}
	m.tokenRefreshLocks, err = coresync.LocateLockTable[TokenRefreshLockKey](store, TokenRefreshLockTable)
	if err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err),
			"oauth: failed to initialize token-refresh lock table (is sync owner infra initialized?): %s", err)
	}

	// 6. Reconcilers. Registering a controller on a table starts its pipeline
	//    and schedules all existing keys for reconciliation via the table's
	//    ReconcilerGetAllKeys() — so tokens are scheduled on startup with no
	//    cold-start gap, and table change notifications enqueue new entries
	//    automatically thereafter.
	m.pendingReconciler = &pendingStateReconciler{table: m.pendingTable}
	if err := m.pendingTable.Register(pendingStateReconcilerName, m.pendingReconciler); err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err), "oauth: failed to start stale-state reconciler: %s", err)
	}
	m.tokenReconciler = &tokenRefreshReconciler{
		tokens:  m.tokenTable,
		locks:   m.tokenRefreshLocks,
		refresh: m.refreshToken,
	}
	if err := m.tokenTable.Register(tokenRefreshReconcilerName, m.tokenReconciler); err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err), "oauth: failed to start token-refresh reconciler: %s", err)
	}

	return m, nil
}

// initManagerEncryptor resolves the field-encryption key with precedence
// OAuthConfig.EncryptorKey > ENCRYPTOR_KEY env, and fails closed when neither is
// set rather than silently using the built-in default key — protecting access /
// refresh / ID tokens, client secrets, and PKCE verifiers at rest.
//
// This is the security hardening carried over from the AUTH-0002 review
// (CodeRabbit Major / Codex P1 on PR #25): for the manager-driven path we
// deliberately override AUTH-0002's default-key fallback. The resolved key is
// registered on the package-scoped "OAuthLibrary" provider that the entry-type
// BSON marshalers consume, so the configured key encrypts data. Because that
// provider is process-global, the first manager's key wins; a second manager
// configured with a different key reuses the first (documented limitation —
// see OPEN-POINTS).
func (m *OAuthManager) initManagerEncryptor(cfg OAuthConfig) (utils.IOEncryptor, error) {
	key := cfg.EncryptorKey
	if key == "" {
		key = os.Getenv(EncryptorKeyEnvVar)
	}
	if key == "" {
		return nil, errors.Wrap(errors.InvalidArgument,
			"oauth: encryption key not configured; set OAuthConfig.EncryptorKey or the ENCRYPTOR_KEY environment variable")
	}
	enc, err := initEncryptor(key)
	if err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err), "oauth: failed to initialize encryptor: %s", err)
	}
	return enc, nil
}

// httpDo executes an HTTP request using the manager's configured client. It is
// the single chokepoint for outbound HTTP so timeout/retry policy can evolve in
// one place; discovery, registration, and token exchange (AUTH-0004..0007) use
// it.
func (m *OAuthManager) httpDo(req *http.Request) (*http.Response, error) {
	return m.httpClient.Do(req)
}
