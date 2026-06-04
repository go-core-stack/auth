// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"net/http"
	"time"

	"github.com/go-core-stack/core/db"
	coresync "github.com/go-core-stack/core/sync"
	"github.com/go-core-stack/core/table"
	"github.com/go-core-stack/core/utils"
)

// SessionState captures the lifecycle state of a stored token. It is an
// int-based enum: storage-efficient and robust to compare. SessionActive is
// the zero value and the correct default for a freshly issued token.
type SessionState int

const (
	// SessionActive indicates the token is valid and usable.
	SessionActive SessionState = iota // 0
	// SessionExpired indicates the token expired and a refresh is needed.
	SessionExpired // 1
	// SessionRevoked indicates the token was explicitly revoked or refresh
	// failed permanently; re-authorization is required.
	SessionRevoked // 2
	// SessionFailed indicates a transient refresh failure that is retryable.
	SessionFailed // 3
)

// ClientType distinguishes a public OAuth client (no secret) from a
// confidential one (authenticates with a secret). ClientTypePublic is the zero
// value.
type ClientType int

const (
	// ClientTypePublic is a public client with no client secret.
	ClientTypePublic ClientType = iota // 0
	// ClientTypeConfidential is a confidential client that authenticates with
	// a client secret.
	ClientTypeConfidential // 1
)

// RegistrationType records how a client was provisioned: via RFC 7591 dynamic
// registration or pre-provisioned statically by the consumer.
// RegistrationTypeDynamic is the zero value.
type RegistrationType int

const (
	// RegistrationTypeDynamic is a client created via RFC 7591 dynamic
	// registration.
	RegistrationTypeDynamic RegistrationType = iota // 0
	// RegistrationTypeStatic is a consumer-pre-provisioned client.
	RegistrationTypeStatic // 1
)

// RefreshPolicy records whether a stored token may be silently refreshed.
// RefreshPolicyRefreshable is the zero value. The TokenEntry.RefreshPolicy
// field and the set/check logic that consumes it land in AUTH-0017; this type
// is only defined here.
type RefreshPolicy int

const (
	// RefreshPolicyRefreshable allows the token to be proactively refreshed.
	RefreshPolicyRefreshable RefreshPolicy = iota // 0
	// RefreshPolicyNoRefresh marks a token that must not be auto-refreshed
	// (e.g. an offline token that should not be revoked on near-expiry).
	RefreshPolicyNoRefresh // 1
)

// --- servers ---

// ServerKey keys cached discovery metadata by remote server URL.
type ServerKey struct {
	ServerURL string `bson:"serverUrl"`
}

// ServerEntry holds the discovered metadata for a remote OAuth/OIDC server.
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

// ClientKey keys a registered OAuth client by remote server URL.
type ClientKey struct {
	ServerURL string `bson:"serverUrl"`
	// ClientRef is a consumer-defined opaque label disambiguating multiple
	// clients registered against the same authorization server (multi-tenant
	// static clients). It is NOT the OAuth-protocol ClientID (see
	// ClientEntry.ClientID); dynamic registration uses ClientRef "".
	ClientRef string `bson:"clientRef,omitempty"`
}

// ClientEntry holds a registered OAuth client for a remote server. Sensitive
// fields (ClientSecret, RegistrationAccessToken) are encrypted at rest via the
// custom BSON marshalers in encryption.go.
type ClientEntry struct {
	ClientID                string           `bson:"clientId"`
	ClientSecret            string           `bson:"clientSecret,omitempty"` // encrypted at rest
	ClientSecretExpiresAt   int64            `bson:"clientSecretExpiresAt,omitempty"`
	RegistrationURI         string           `bson:"registrationClientUri,omitempty"`   // RFC 7592
	RegistrationAccessToken string           `bson:"registrationAccessToken,omitempty"` // encrypted at rest
	RedirectURIs            []string         `bson:"redirectUris,omitempty"`
	Scopes                  []string         `bson:"scopes,omitempty"`
	ClientType              ClientType       `bson:"clientType"`
	RegistrationType        RegistrationType `bson:"registrationType"`
	RegisteredAt            int64            `bson:"registeredAt,omitempty"`
}

// --- tokens ---

// TokenKey keys a token by (server, account) pair.
type TokenKey struct {
	ServerURL string `bson:"serverUrl"`
	// ClientRef is a consumer-defined opaque label disambiguating multiple
	// clients registered against the same authorization server. It is NOT the
	// OAuth-protocol ClientID (see ClientEntry.ClientID); dynamic registration
	// uses ClientRef "".
	ClientRef string `bson:"clientRef,omitempty"`
	AccountID string `bson:"accountId"`
}

// TokenEntry holds the OAuth tokens for a (server, account) pair. Sensitive
// fields (AccessToken, RefreshToken, IDToken) are encrypted at rest via the
// custom BSON marshalers in encryption.go.
type TokenEntry struct {
	AccessToken  string       `bson:"accessToken"` // encrypted at rest
	TokenType    string       `bson:"tokenType,omitempty"`
	RefreshToken string       `bson:"refreshToken,omitempty"` // encrypted at rest
	ExpiresAt    int64        `bson:"expiresAt,omitempty"`
	Scopes       []string     `bson:"scopes,omitempty"`
	IDToken      string       `bson:"idToken,omitempty"` // encrypted at rest
	State        SessionState `bson:"state"`
	// RefreshPolicy records whether this token may be silently refreshed,
	// captured explicitly from the server response at exchange time rather than
	// inferred from an empty RefreshToken (a blanked field is not a reliable
	// signal). Legacy documents written before this field default to
	// RefreshPolicyRefreshable (the zero value) on decode, the correct default.
	RefreshPolicy RefreshPolicy `bson:"refreshPolicy"`
	LastRefresh   int64         `bson:"lastRefresh,omitempty"`
	ErrorReason   string        `bson:"errorReason,omitempty"`
}

// --- pending_auth_states ---

// PendingAuthStateKey keys a transient pending authorization state by its
// CSRF state value.
type PendingAuthStateKey struct {
	State string `bson:"state"`
}

// PendingAuthState holds transient PKCE/CSRF state for an in-flight
// authorization flow. CodeVerifier is encrypted at rest via the custom BSON
// marshalers in encryption.go.
type PendingAuthState struct {
	ServerURL string `bson:"serverUrl"`
	// ClientRef is a consumer-defined opaque label disambiguating multiple
	// clients registered against the same authorization server, so
	// HandleCallback can rebuild the correct TokenKey. It is NOT the
	// OAuth-protocol ClientID (see ClientID below); dynamic registration uses
	// ClientRef "".
	ClientRef    string    `bson:"clientRef,omitempty"`
	AccountID    string    `bson:"accountId"`
	ClientID     string    `bson:"clientId"`     // client that initiated the flow
	CodeVerifier string    `bson:"codeVerifier"` // encrypted at rest
	RedirectURI  string    `bson:"redirectUri"`
	Scopes       []string  `bson:"scopes,omitempty"`
	CreatedAt    time.Time `bson:"createdAt"` // TTL index field (10 min)
}

// --- lock keys ---

// RegistrationLockKey serializes dynamic registration per remote server.
type RegistrationLockKey struct {
	ServerURL string `bson:"serverUrl"`
	// ClientRef is a consumer-defined opaque label disambiguating multiple
	// clients registered against the same authorization server. It is NOT the
	// OAuth-protocol ClientID (see ClientEntry.ClientID); dynamic registration
	// uses ClientRef "".
	ClientRef string `bson:"clientRef,omitempty"`
}

// TokenRefreshLockKey serializes token refresh per (server, account) pair.
type TokenRefreshLockKey struct {
	ServerURL string `bson:"serverUrl"`
	// ClientRef is a consumer-defined opaque label disambiguating multiple
	// clients registered against the same authorization server. It is NOT the
	// OAuth-protocol ClientID (see ClientEntry.ClientID); dynamic registration
	// uses ClientRef "".
	ClientRef string `bson:"clientRef,omitempty"`
	AccountID string `bson:"accountId"`
}

// --- options / params ---

// OAuthConfig configures an OAuthManager. Only RedirectURI is conceptually
// required for flows; the remaining fields carry sensible defaults.
type OAuthConfig struct {
	RedirectURI  string       // consumer callback endpoint (default for flows)
	Scopes       []string     // default scopes
	ClientName   string       // for dynamic registration metadata
	EncryptorKey string       // optional, falls back to ENCRYPTOR_KEY env
	HTTPClient   *http.Client // optional, defaults to 30s-timeout client
}

// RegisterClientOptions parameterizes dynamic client registration.
type RegisterClientOptions struct {
	ServerURL string
	// ClientRef is a consumer-defined opaque label disambiguating multiple
	// clients registered against the same authorization server. It is NOT the
	// OAuth-protocol ClientID; dynamic registration uses ClientRef "".
	ClientRef    string
	ClientName   string   // defaults to OAuthConfig.ClientName
	RedirectURIs []string // defaults to []string{OAuthConfig.RedirectURI}
	Scopes       []string // defaults to OAuthConfig.Scopes
	// GrantTypes defaults to ["authorization_code", "refresh_token"]
}

// AuthorizeOptions parameterizes generation of an authorization request.
type AuthorizeOptions struct {
	ServerURL string
	// ClientRef is a consumer-defined opaque label disambiguating multiple
	// clients registered against the same authorization server. It is NOT the
	// OAuth-protocol ClientID; dynamic registration uses ClientRef "".
	ClientRef   string
	AccountID   string            // consumer's opaque identifier — never sent to server
	RedirectURI string            // defaults to OAuthConfig.RedirectURI
	Scopes      []string          // defaults to OAuthConfig.Scopes
	ExtraParams map[string]string // e.g. {"resource": "https://mcp.vercel.com"}
}

// AuthorizationParams are the tokenized authorization request parameters
// returned to the consumer, who reconstructs the redirect URL.
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

// OAuthManager is the single entry point wiring tables, locks, the encryptor,
// and reconcilers. Fields are populated by NewOAuthManager (AUTH-0003); methods
// are implemented in subsequent tasks. The fields are part of the mandated
// skeleton and are intentionally not yet referenced — they are wired in
// AUTH-0003, hence the per-field nolint:unused directives.
type OAuthManager struct {
	config OAuthConfig //nolint:unused // wired in AUTH-0003 (NewOAuthManager)

	db db.Store //nolint:unused // wired in AUTH-0003 (NewOAuthManager)

	serverTable  *table.Table[ServerKey, ServerEntry]                //nolint:unused // wired in AUTH-0003
	clientTable  *table.Table[ClientKey, ClientEntry]                //nolint:unused // wired in AUTH-0003
	tokenTable   *table.Table[TokenKey, TokenEntry]                  //nolint:unused // wired in AUTH-0003
	pendingTable *table.Table[PendingAuthStateKey, PendingAuthState] //nolint:unused // wired in AUTH-0003

	registrationLocks *coresync.LockTable[RegistrationLockKey] //nolint:unused // wired in AUTH-0003
	tokenRefreshLocks *coresync.LockTable[TokenRefreshLockKey] //nolint:unused // wired in AUTH-0003

	httpClient *http.Client //nolint:unused // wired in AUTH-0003 (NewOAuthManager)

	encryptor utils.IOEncryptor //nolint:unused // wired in AUTH-0003 (NewOAuthManager)

	pendingReconciler *pendingStateReconciler // wired in AUTH-0003 (NewOAuthManager)
	tokenReconciler   *tokenRefreshReconciler // wired in AUTH-0003 (NewOAuthManager)
}
