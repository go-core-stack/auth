// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import "time"

const (
	// Collection names within the database the consumer supplies via db.Store.
	ServersCollection           = "servers"
	ClientsCollection           = "clients"
	TokensCollection            = "tokens"
	PendingAuthStatesCollection = "pending_auth_states"

	// Distributed lock table names.
	RegistrationLockTable = "auth-library-registration-locks"
	TokenRefreshLockTable = "auth-library-token-refresh-locks"

	// Well-known discovery paths.
	WellKnownProtectedResource   = "/.well-known/oauth-protected-resource"   // RFC 9728
	WellKnownAuthorizationServer = "/.well-known/oauth-authorization-server" // RFC 8414
	WellKnownOpenIDConfiguration = "/.well-known/openid-configuration"       // OIDC Discovery

	// Encryptor configuration.
	//
	// EncryptorProvider is the provider name used to scope the
	// utils.IOEncryptor for this library. EncryptorKeyEnvVar is consulted
	// when no explicit key is supplied via OAuthConfig.EncryptorKey, and
	// DefaultEncryptorKey is the last-resort fallback.
	EncryptorProvider   = "OAuthLibrary"
	EncryptorKeyEnvVar  = "ENCRYPTOR_KEY"
	DefaultEncryptorKey = "MySuperSecretKey"

	// OAuth/PKCE protocol defaults.
	CodeChallengeMethodS256     = "S256"
	TokenEndpointAuthMethodNone = "none"
)

// Timing defaults.
const (
	// DefaultHTTPTimeout is the timeout applied to the default HTTP client
	// when OAuthConfig.HTTPClient is not provided.
	DefaultHTTPTimeout = 30 * time.Second

	// PendingStateTTL is how long a pending authorization state lives before
	// it is considered stale (MongoDB TTL index + reconciler cleanup).
	PendingStateTTL = 10 * time.Minute

	// RefreshThreshold is the minimum remaining lifetime below which a token
	// is proactively refreshed.
	RefreshThreshold = 5 * time.Minute

	// RefreshLifetimeFraction is the fraction of a token's total lifetime
	// after which it becomes eligible for proactive refresh (80%).
	RefreshLifetimeFraction = 0.8
)

// DefaultGrantTypes returns the grant types requested during dynamic client
// registration when the caller does not specify any. It returns a fresh slice
// on every call so callers can safely append to or mutate the result without
// corrupting the shared default.
func DefaultGrantTypes() []string {
	return []string{"authorization_code", "refresh_token"}
}
