# OAuth Client Library

Library-level OAuth client for `github.com/go-core-stack/auth/oauth`:
discovery, dynamic registration, Authorization Code + PKCE, and token lifecycle.

---

## 1. Overview

### 1.1 Problem

`go-core-stack/auth` has no client-side OAuth support. Services that must
authenticate *outbound* to a remote OAuth/OIDC authorization server each
re-implement discovery, registration, PKCE, token persistence, refresh, and
encryption — error-prone and security sensitive.

### 1.2 Proposal

Add an `oauth/` package providing a single `OAuthManager` entry point that wires
MongoDB-backed tables, distributed locks, a field-level encryptor, and two
background reconcilers, and exposes a function-based API for the full client
lifecycle. The library hosts **no** HTTP endpoints — the consumer owns the
callback endpoint and the frontend redirect.

### 1.3 Scope

| In Scope | Out of Scope |
|----------|--------------|
| Server discovery (RFC 9728 / 8414 / OIDC) | Hosting HTTP callback/initiate endpoints |
| Dynamic client registration (RFC 7591), public clients | Confidential-client secret rotation |
| Static client registration (consumer-provided credentials) | Consumer's UI / redirect rendering |
| Multiple clients per server via `ClientRef` (multi-tenant) | Provider-specific business logic |
| Authorization Code + PKCE (RFC 7636) | |
| Token persist / refresh / revoke (RFC 7009) | |
| Field-level encryption at rest | |
| Cross-replica locking + reconciler refresh | |

---

## 2. Package Structure

```
auth/
├── client/          # existing — HMAC-signed HTTP client
├── context/         # existing — AuthInfo context propagation
├── hash/            # existing — HMAC generator/validator
├── model/           # existing — Route model
├── route/           # existing — RouteTable
├── oauth/           # ← NEW
│   ├── const.go         # db/collection names, defaults, well-known paths
│   ├── types.go         # all types + enums
│   ├── encryption.go    # provider-scoped encryptor + BSON marshal/unmarshal helpers
│   ├── discovery.go     # RFC 9728 + RFC 8414 discovery
│   ├── registration.go  # RFC 7591 dynamic registration
│   ├── authorization.go # PKCE auth-code helpers, code exchange, pending state
│   ├── token.go         # persistence, refresh, revocation, session state
│   ├── reconciler.go    # stale-state cleanup + proactive token refresh
│   ├── manager.go       # OAuthManager: wires tables/locks/encryptor/reconcilers + public API
│   └── manager_test.go  # unit tests (mocked Table/HTTP)
├── go.mod
└── go.sum
```

---

## 3. Storage Design

### 3.1 Database & Collections

| Collection            | Key                                 | Purpose                                            |
|-----------------------|-------------------------------------|----------------------------------------------------|
| `servers`             | `ServerURL` (string)                | Cached discovery metadata per remote server        |
| `clients`             | `{ServerURL, ClientRef}`            | Registered OAuth client per (server × client-ref)  |
| `tokens`              | `{ServerURL, ClientRef, AccountID}` | OAuth tokens per (server × client-ref × account)    |
| `pending_auth_states` | `State` (string)                    | Transient PKCE/CSRF state for in-flight flows      |

`ClientRef` is a consumer-defined opaque label that disambiguates multiple
clients registered against the same server (see §3.5). Dynamic registrations use
the empty `ClientRef` (`""`), which `omitempty` omits from the stored key — so
single-client deployments and existing data are unaffected.

These collections live in the `db.Store` the consumer supplies to
`NewOAuthManager` — the consuming service owns the connection and chooses the
backing database (resolving it via its own `db.StoreClient.GetDataStore`). The
`pending_auth_states` collection uses a MongoDB TTL
index on `createdAt` (10-minute expiry) configured via `IndexDefinition.TTL` in
`core/db.EnsureIndexes`. Entries are also deleted explicitly on successful use
in `HandleCallback`, and actively cleaned by the stale-state reconciler (§6.1).

### 3.2 Key & Entry Types

```go
// --- servers ---
type ServerKey struct {
    ServerURL string `bson:"serverUrl"`
}

type ServerEntry struct {
    // Protected Resource Metadata (RFC 9728)
    Resource             string   `bson:"resource,omitempty"`
    AuthorizationServers []string `bson:"authorizationServers,omitempty"`
    ScopesSupported      []string `bson:"scopesSupported,omitempty"`

    // Authorization Server Metadata (RFC 8414)
    Issuer                string   `bson:"issuer,omitempty"`
    AuthorizationEndpoint string   `bson:"authorizationEndpoint,omitempty"`
    TokenEndpoint         string   `bson:"tokenEndpoint,omitempty"`
    RevocationEndpoint    string   `bson:"revocationEndpoint,omitempty"`
    RegistrationEndpoint  string   `bson:"registrationEndpoint,omitempty"`
    GrantTypesSupported   []string `bson:"grantTypesSupported,omitempty"`

    DiscoveredAt int64 `bson:"discoveredAt,omitempty"`
}

// --- clients ---
type ClientKey struct {
    ServerURL string `bson:"serverUrl"`
    ClientRef string `bson:"clientRef,omitempty"` // consumer label; "" = dynamic
}

type ClientEntry struct {
    ClientID                string   `bson:"clientId"`
    ClientSecret            string   `bson:"clientSecret,omitempty"`            // encrypted at rest
    ClientSecretExpiresAt   int64    `bson:"clientSecretExpiresAt,omitempty"`
    RegistrationURI         string   `bson:"registrationClientUri,omitempty"`   // RFC 7592
    RegistrationAccessToken string   `bson:"registrationAccessToken,omitempty"` // encrypted at rest
    RedirectURIs            []string `bson:"redirectUris,omitempty"`
    Scopes                  []string `bson:"scopes,omitempty"`
    ClientType              string   `bson:"clientType"`       // "public" | "confidential"
    RegistrationType        string   `bson:"registrationType"` // "dynamic" | "static"
    RegisteredAt            int64    `bson:"registeredAt,omitempty"`
}

// --- tokens ---
type TokenKey struct {
    ServerURL string `bson:"serverUrl"`
    ClientRef string `bson:"clientRef,omitempty"` // consumer label; "" = dynamic
    AccountID string `bson:"accountId"`
}

type TokenEntry struct {
    AccessToken  string       `bson:"accessToken"`            // encrypted at rest
    TokenType    string       `bson:"tokenType,omitempty"`
    RefreshToken string       `bson:"refreshToken,omitempty"` // encrypted at rest
    ExpiresAt    int64        `bson:"expiresAt,omitempty"`
    Scopes       []string     `bson:"scopes,omitempty"`
    IDToken      string       `bson:"idToken,omitempty"`      // encrypted at rest
    State        SessionState `bson:"state"`
    LastRefresh  int64        `bson:"lastRefresh,omitempty"`
    ErrorReason  string       `bson:"errorReason,omitempty"`
}

type SessionState string

const (
    SessionActive  SessionState = "active"
    SessionExpired SessionState = "expired"  // token expired, refresh needed
    SessionRevoked SessionState = "revoked"  // explicitly revoked or refresh failed permanently
    SessionFailed  SessionState = "failed"   // refresh failed (transient — retryable)
)

// --- pending_auth_states ---
type PendingAuthStateKey struct {
    State string `bson:"state"`
}

type PendingAuthState struct {
    ServerURL    string    `bson:"serverUrl"`
    ClientRef    string    `bson:"clientRef,omitempty"` // recovered by HandleCallback to build the TokenKey
    AccountID    string    `bson:"accountId"`
    CodeVerifier string    `bson:"codeVerifier"` // encrypted at rest
    RedirectURI  string    `bson:"redirectUri"`
    Scopes       []string  `bson:"scopes,omitempty"`
    CreatedAt    time.Time `bson:"createdAt"`    // TTL index field (10 min)
}
```

### 3.3 Encryption at Rest

Sensitive fields are encrypted following the `auth-gateway` table encryptor
pattern, using `utils.IOEncryptor` from `go-core-stack/core/utils`.

- A provider-scoped encryptor is initialized with provider name `"OAuthLibrary"`.
- Key sourced from `OAuthConfig.EncryptorKey`, else the `ENCRYPTOR_KEY` env var
  with a default fallback. Initialized during `NewOAuthManager`.
- Encryption/decryption happen in custom `MarshalBSON` / `UnmarshalBSON` methods
  on `TokenEntry`, `ClientEntry`, and `PendingAuthState`.

| Collection            | Encrypted Fields                          |
|-----------------------|-------------------------------------------|
| `tokens`              | `AccessToken`, `RefreshToken`, `IDToken`  |
| `clients`             | `ClientSecret`, `RegistrationAccessToken` |
| `pending_auth_states` | `CodeVerifier`                            |

### 3.4 Locking

`sync.LockTable` from `go-core-stack/core/sync`:

```go
type RegistrationLockKey struct {
    ServerURL string `bson:"serverUrl"`
    ClientRef string `bson:"clientRef,omitempty"`
}

type TokenRefreshLockKey struct {
    ServerURL string `bson:"serverUrl"`
    ClientRef string `bson:"clientRef,omitempty"`
    AccountID string `bson:"accountId"`
}
```

Lock table names: `auth-library-registration-locks`,
`auth-library-token-refresh-locks`. Including `ClientRef` keeps registration and
refresh of one client from serializing on another client for the same server (or
the same `(server, account)` pair).

### 3.5 Multi-Client Support (`ClientRef`)

A single deployment can register **multiple OAuth clients against the same
server** — e.g. one static/confidential client per tenant, each with its own
credentials. They are disambiguated by `ClientRef`.

- **`ClientRef` is not `ClientID`.** `ClientEntry.ClientID` is the
  OAuth-protocol identifier issued by the authorization server. `ClientRef` is a
  *consumer-side* opaque label (tenant slug, config name, integration id) with no
  protocol meaning; it exists only to key storage and retrieval.
- **Key model.** `(ServerURL, ClientRef)` is unique per client;
  `(ServerURL, ClientRef, AccountID)` is unique per token. Every client- and
  token-resolving key carries `ClientRef`.
- **Dynamic vs static.** Dynamic registration uses `ClientRef == ""` (the
  implicit single-client slot). Static registration requires a non-empty
  `ClientRef`; `RegisterStaticClient` rejects `""` so a static client can never
  collide with the dynamic slot.
- **No migration.** `ClientRef` uses the `omitempty` BSON tag. Writes with `""`
  omit the field entirely, so new dynamic documents are byte-for-byte compatible
  with pre-multi-client data, and existing documents (which lack the field)
  decode to `ClientRef: ""`. No index changes are needed — the `core/table`
  layer builds indexes from the struct tags, including `omitempty` semantics.

```go
// Register a tenant's pre-provisioned client once.
err := mgr.RegisterStaticClient(ctx, "https://auth.example.com", "tenant-acme", oauth.ClientEntry{
    ClientID:     "acme-client-id",
    ClientSecret: "acme-client-secret",
    ClientType:   "confidential",
    RedirectURIs: []string{"https://app.example.com/callback"},
    Scopes:       []string{"openid", "profile"},
})

// Subsequent token operations reference the same ClientRef.
tok, err := mgr.GetToken(ctx, "https://auth.example.com", "tenant-acme", "user-123")

// Dynamic (single-client) callers pass "".
tok, err = mgr.GetToken(ctx, "https://auth.example.com", "", "user-123")
```

---

## 4. Public API

### 4.1 OAuthManager

```go
type OAuthConfig struct {
    RedirectURI  string       // consumer callback endpoint (default for flows)
    Scopes       []string     // default scopes
    ClientName   string       // for dynamic registration metadata
    EncryptorKey string       // optional, falls back to ENCRYPTOR_KEY env
    HTTPClient   *http.Client // optional, defaults to 30s-timeout client
}

func NewOAuthManager(ctx context.Context, store db.Store, cfg OAuthConfig) (*OAuthManager, error)
```

`NewOAuthManager` is the single init point: initialize 4 Tables + 2 LockTables,
set up the encryptor, configure the TTL index, and start both reconcilers.
Per-call methods pull defaults from config and allow per-call overrides.

### 4.2 Discovery

```go
func (m *OAuthManager) DiscoverServer(ctx context.Context, serverURL string) (*ServerEntry, error)
func (m *OAuthManager) RefreshServerMetadata(ctx context.Context, serverURL string) (*ServerEntry, error)
func (m *OAuthManager) GetCachedServer(ctx context.Context, serverURL string) (*ServerEntry, error)
```

### 4.3 Registration

```go
type RegisterClientOptions struct {
    ServerURL    string
    ClientRef    string   // consumer label; "" for the dynamic single-client slot
    ClientName   string   // defaults to OAuthConfig.ClientName
    RedirectURIs []string // defaults to []string{OAuthConfig.RedirectURI}
    Scopes       []string // defaults to OAuthConfig.Scopes
    // GrantTypes defaults to ["authorization_code", "refresh_token"]
}

func (m *OAuthManager) RegisterDynamicClient(ctx context.Context, opts RegisterClientOptions) (*ClientEntry, error)
func (m *OAuthManager) ReRegisterClient(ctx context.Context, opts RegisterClientOptions) (*ClientEntry, error)
func (m *OAuthManager) GetClient(ctx context.Context, serverURL, clientRef string) (*ClientEntry, error)
func (m *OAuthManager) RegisterStaticClient(ctx context.Context, serverURL, clientRef string, entry ClientEntry) error
```

`RegisterStaticClient` upserts a consumer-provided client under a **non-empty**
`ClientRef` (it rejects `""`), setting `RegistrationType = "static"`. `GetClient`
takes the `clientRef` selecting which client to retrieve for the server.

### 4.4 Authorization (PKCE)

```go
type AuthorizationParams struct {
    Endpoint            string
    ClientID            string
    RedirectURI         string
    ResponseType        string            // "code"
    Scope               string            // space-delimited
    State               string            // CSRF state (library-generated)
    CodeChallenge       string            // PKCE (library-generated)
    CodeChallengeMethod string            // "S256"
    ExtraParams         map[string]string // consumer-provided extras
}

type AuthorizeOptions struct {
    ServerURL   string
    ClientRef   string            // selects the client; "" for the dynamic slot
    AccountID   string            // consumer's opaque identifier — never sent to server
    RedirectURI string            // defaults to OAuthConfig.RedirectURI
    Scopes      []string          // defaults to OAuthConfig.Scopes
    ExtraParams map[string]string // e.g. {"resource": "https://mcp.vercel.com"}
}

func (m *OAuthManager) AuthorizationURL(ctx context.Context, opts AuthorizeOptions) (*AuthorizationParams, error)
func (m *OAuthManager) HandleCallback(ctx context.Context, state string, code string) (*TokenEntry, error)
```

`AuthorizationURL` returns **tokenized params**, not a full URL string — the
consumer's frontend reconstructs the redirect URL. The `state` value in the
callback URL is the session handle; there is no in-memory session object.
`AuthorizationURL` records `opts.ClientRef` in the persisted `PendingAuthState`,
and `HandleCallback` recovers it to store the resulting token under the correct
`TokenKey` — so neither signature needs a `clientRef` parameter.

### 4.5 Token Management

```go
func (m *OAuthManager) GetToken(ctx context.Context, serverURL, clientRef, accountID string) (*TokenEntry, error)        // near-expiry auto-refresh
func (m *OAuthManager) RefreshToken(ctx context.Context, serverURL, clientRef, accountID string) (*TokenEntry, error)    // forced
func (m *OAuthManager) RevokeToken(ctx context.Context, serverURL, clientRef, accountID string) error                    // RFC 7009
func (m *OAuthManager) DeleteToken(ctx context.Context, serverURL, clientRef, accountID string) error
func (m *OAuthManager) GetSessionState(ctx context.Context, serverURL, clientRef, accountID string) (SessionState, error)
func (m *OAuthManager) ListTokens(ctx context.Context, serverURL, clientRef string) ([]*TokenEntry, error)
```

Every token method takes `clientRef` (between `serverURL` and `accountID`;
`ListTokens` after `serverURL`). Dynamic callers pass `""`. `ListTokens` is
scoped to a **single** `ClientRef` — there is no wildcard/list-all mode; its
primary use is invalidating a static client's tokens when that client is removed.
The `""` case matches dynamic tokens via an absent-or-empty filter
(`$in:["", nil]`), since dynamic documents omit the `clientRef` field entirely.

---

## 5. Internal Flows

### 5.1 Discovery
```
DiscoverServer(serverURL)
  ├── cached in serverTable? → return
  └── else:
      ├── GET {serverURL}/.well-known/oauth-protected-resource   (RFC 9728)
      ├── authorization_servers[0] → {asURL}
      ├── GET {asURL}/.well-known/oauth-authorization-server     (RFC 8414)
      │     └── fallback: GET {asURL}/.well-known/openid-configuration
      ├── upsert serverTable
      └── return ServerEntry
```

### 5.2 Dynamic Registration
```
RegisterDynamicClient(opts)
  ├── merge opts with config defaults
  ├── clientTable has entry? → return (idempotent)
  └── else:
      ├── acquire registration lock (key={serverURL, clientRef})
      ├── double-check clientTable
      ├── DiscoverServer(serverURL)
      ├── POST {registrationEndpoint}  (RFC 7591, token_endpoint_auth_method:"none")
      ├── insert clientTable (encrypted via MarshalBSON)
      ├── release lock
      └── return ClientEntry
```

### 5.3 Authorization + Token Exchange
```
AuthorizationURL(opts)
  ├── merge defaults; GetClient + GetCachedServer
  ├── generate PKCE verifier/challenge (S256) + CSRF state
  ├── persist PendingAuthState (key=state, createdAt=now)
  └── return AuthorizationParams

HandleCallback(state, code)
  ├── look up PendingAuthState by state (not found → error)
  ├── retrieve verifier/serverUrl/accountId
  ├── POST {tokenEndpoint} with code + verifier + client_id + redirect_uri
  ├── persist TokenEntry (state=active, encrypted)
  ├── delete PendingAuthState
  └── return TokenEntry
```

### 5.4 Token Refresh
```
GetToken(serverURL, clientRef, accountID)
  ├── ExpiresAt > now + threshold → return as-is
  └── near expiry:
      ├── acquire refresh lock (key={serverURL, clientRef, accountID}); re-read token
      ├── POST {tokenEndpoint} grant_type=refresh_token
      │     success      → update, state=active
      │     transient    → state=failed, keep token
      │     invalid_grant→ state=revoked (re-authorize)
      │     invalid_client→ state=revoked (re-register)
      └── release lock; return token
```

---

## 6. Reconcilers

Two `core/reconciler` controllers with `RequeueAfter` semantics, started in
`NewOAuthManager`. `Table` embeds `reconciler.ManagerImpl` and fires
`NotifyCallback` on collection changes.

### 6.1 Stale-State Cleanup — `pending_auth_states`

Active complement to the TTL index for edge cases where the TTL background
thread hasn't run.

```
OnReconcile(PendingAuthStateKey):
  ├── read entry
  ├── CreatedAt + TTL < now → delete, return nil (no requeue)
  └── still valid → return &Result{RequeueAfter: remainingTTL}
```

### 6.2 Token Refresh — `tokens`

Proactively refreshes before expiry so consumers always read a fresh token.

```
OnReconcile(TokenKey):
  ├── state == revoked → return nil (dead token)
  ├── near expiry (within 80% lifetime or < 5 min):
  │     acquire lock; re-read; refresh
  │       success → update; Result{RequeueAfter: nextInterval}
  │       invalid_grant → state=revoked; return nil
  │       transient → return error (pipeline auto-requeues)
  └── healthy → Result{RequeueAfter: timeUntilThreshold}

Startup: ReconcilerGetAllKeys() schedules all existing tokens — no cold-start gap.
```

---

## 7. Error Handling & Session State

| Error Scenario | Session State | Recovery |
|---|---|---|
| Token near expiry | `active` → auto-refresh | Transparent |
| Refresh token expired / revoked | `revoked` | Consumer re-initiates flow |
| Client expired / invalid | `revoked` | `ReRegisterClient` then re-authorize |
| Transient network error on refresh | `failed` | Retried by reconciler / next `GetToken` |
| Explicit revocation | `revoked` | Consumer re-initiates flow |
| Pending state expired (TTL) | N/A | Consumer re-initiates flow |
| Invalid/unknown state in callback | N/A | `HandleCallback` errors; re-initiate |

---

## 8. Implementation Phases

| Phase | Description | Effort |
|-------|-------------|--------|
| 1 | Types, constants, encryption | M |
| 2 | OAuthManager init + tables/locks + reconcilers | L |
| 3 | Server discovery | M |
| 4 | Dynamic client registration | M |
| 5 | Authorization flow (PKCE) | M |
| 6 | Token lifecycle management | L |
| 7 | Unit tests | L |

---

## 9. Deferred Scope

The following are intentionally out of the initial implementation and revisited
when a consumer requires them:

| Item | Current Decision | Re-evaluate When |
|------|------------------|------------------|
| Confidential-client secret rotation | Static clients store provided credentials; no rotation flow | A consumer needs automated secret rotation |
| Client expiry detection | Reactive — re-register on `invalid_client` → `revoked` | Servers begin issuing short-lived client registrations |
| `ListTokens` wildcard / list-all mode | Scoped to a single `ClientRef`; no cross-ref listing | A consumer needs to enumerate every client's tokens for a server |

> **Now supported (was deferred):** static client registration and multiple
> clients per server — both delivered via the `ClientRef` key model (§3.5).

---

## 10. References

- RFC 9728 — OAuth 2.0 Protected Resource Metadata
- RFC 8414 — OAuth 2.0 Authorization Server Metadata
- RFC 7591 — OAuth 2.0 Dynamic Client Registration Protocol
- RFC 7592 — OAuth 2.0 Dynamic Client Registration Management Protocol
- RFC 7636 — Proof Key for Code Exchange (PKCE)
- RFC 7009 — OAuth 2.0 Token Revocation
- OpenID Connect Discovery 1.0
