// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"log"
	"os"
	"sync"

	"github.com/go-core-stack/core/utils"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Provider-scoped field encryptor for the OAuth library. Sensitive fields on
// TokenEntry, ClientEntry, and PendingAuthState are encrypted at rest via the
// custom BSON marshalers below. This follows the auth-gateway table encryptor
// pattern (auth-gateway/pkg/table/encryptor.go), using a package-level
// encryptor reference consumed by the marshalers.
var (
	encOnce   sync.Once
	encryptor utils.IOEncryptor
)

// resolveEncryptorKey picks the encryption key with the precedence:
// ENCRYPTOR_KEY env var > built-in default fallback. An explicit key (from
// OAuthConfig.EncryptorKey) is supplied directly to initEncryptor by the
// caller and takes precedence over this resolution.
func resolveEncryptorKey() string {
	if key, ok := os.LookupEnv(EncryptorKeyEnvVar); ok && key != "" {
		return key
	}
	log.Printf("oauth: encryptor key not configured, switching to default key")
	return DefaultEncryptorKey
}

// initEncryptor registers the provider-scoped encryptor for EncryptorProvider
// using the supplied key, falling back to ENCRYPTOR_KEY / the default when key
// is empty. It is idempotent: if the provider was already initialized (e.g. by
// a prior call or another component), the existing encryptor is returned and
// the supplied key is ignored — so a caller wanting a specific key (such as
// NewOAuthManager honoring OAuthConfig.EncryptorKey) must call this before the
// first BSON (un)marshal of an encrypted entry.
//
// Consumed by NewOAuthManager (AUTH-0003) with the resolved config key.
func initEncryptor(key string) (utils.IOEncryptor, error) {
	if key == "" {
		key = resolveEncryptorKey()
	}
	enc, err := utils.InitializeEncryptor(EncryptorProvider, key)
	if err != nil {
		// InitializeEncryptor fails with AlreadyExists when the provider was
		// already registered, but also with InvalidArgument (empty key) or
		// Unknown (AES cipher creation failure). Only fall back to the
		// existing encryptor if the provider is actually registered;
		// otherwise surface the original init error rather than a misleading
		// "not found" from GetObjectEncryptor.
		existing, getErr := utils.GetObjectEncryptor(EncryptorProvider)
		if getErr != nil {
			return nil, err
		}
		return existing, nil
	}
	return enc, nil
}

// getEncryptor lazily provides the provider-scoped encryptor for the marshalers.
// Initialization happens exactly once. If the provider was already initialized
// with an explicit key (e.g. by NewOAuthManager) that encryptor is reused as-is;
// otherwise it is initialized from ENCRYPTOR_KEY / the default fallback.
func getEncryptor() utils.IOEncryptor {
	encOnce.Do(func() {
		// Reuse an explicitly-configured provider encryptor without
		// re-resolving (and possibly mis-logging) a key.
		if existing, err := utils.GetObjectEncryptor(EncryptorProvider); err == nil {
			encryptor = existing
			return
		}
		enc, err := initEncryptor("")
		if err != nil {
			log.Panicf("oauth: failed to initialize encryptor: %s", err)
		}
		encryptor = enc
	})
	return encryptor
}

// --- TokenEntry: encrypt AccessToken, RefreshToken, IDToken ---

// MarshalBSON encrypts the sensitive fields before serialization.
func (e *TokenEntry) MarshalBSON() ([]byte, error) {
	type tokenAlias TokenEntry
	raw := tokenAlias(*e)

	enc := getEncryptor()
	var err error
	if e.AccessToken != "" {
		if raw.AccessToken, err = enc.EncryptString(e.AccessToken); err != nil {
			return nil, err
		}
	}
	if e.RefreshToken != "" {
		if raw.RefreshToken, err = enc.EncryptString(e.RefreshToken); err != nil {
			return nil, err
		}
	}
	if e.IDToken != "" {
		if raw.IDToken, err = enc.EncryptString(e.IDToken); err != nil {
			return nil, err
		}
	}
	return bson.Marshal(&raw)
}

// UnmarshalBSON decrypts the sensitive fields after deserialization.
func (e *TokenEntry) UnmarshalBSON(data []byte) error {
	type tokenAlias TokenEntry
	raw := &tokenAlias{}
	if err := bson.Unmarshal(data, raw); err != nil {
		return err
	}

	enc := getEncryptor()
	var err error
	if raw.AccessToken != "" {
		if raw.AccessToken, err = enc.DecryptString(raw.AccessToken); err != nil {
			return err
		}
	}
	if raw.RefreshToken != "" {
		if raw.RefreshToken, err = enc.DecryptString(raw.RefreshToken); err != nil {
			return err
		}
	}
	if raw.IDToken != "" {
		if raw.IDToken, err = enc.DecryptString(raw.IDToken); err != nil {
			return err
		}
	}
	*e = TokenEntry(*raw)
	return nil
}

// --- ClientEntry: encrypt ClientSecret, RegistrationAccessToken ---

// MarshalBSON encrypts the sensitive fields before serialization.
func (e *ClientEntry) MarshalBSON() ([]byte, error) {
	type clientAlias ClientEntry
	raw := clientAlias(*e)

	enc := getEncryptor()
	var err error
	if e.ClientSecret != "" {
		if raw.ClientSecret, err = enc.EncryptString(e.ClientSecret); err != nil {
			return nil, err
		}
	}
	if e.RegistrationAccessToken != "" {
		if raw.RegistrationAccessToken, err = enc.EncryptString(e.RegistrationAccessToken); err != nil {
			return nil, err
		}
	}
	return bson.Marshal(&raw)
}

// UnmarshalBSON decrypts the sensitive fields after deserialization.
func (e *ClientEntry) UnmarshalBSON(data []byte) error {
	type clientAlias ClientEntry
	raw := &clientAlias{}
	if err := bson.Unmarshal(data, raw); err != nil {
		return err
	}

	enc := getEncryptor()
	var err error
	if raw.ClientSecret != "" {
		if raw.ClientSecret, err = enc.DecryptString(raw.ClientSecret); err != nil {
			return err
		}
	}
	if raw.RegistrationAccessToken != "" {
		if raw.RegistrationAccessToken, err = enc.DecryptString(raw.RegistrationAccessToken); err != nil {
			return err
		}
	}
	*e = ClientEntry(*raw)
	return nil
}

// --- PendingAuthState: encrypt CodeVerifier ---

// MarshalBSON encrypts the sensitive fields before serialization.
func (e *PendingAuthState) MarshalBSON() ([]byte, error) {
	type pendingAlias PendingAuthState
	raw := pendingAlias(*e)

	if e.CodeVerifier != "" {
		enc := getEncryptor()
		encrypted, err := enc.EncryptString(e.CodeVerifier)
		if err != nil {
			return nil, err
		}
		raw.CodeVerifier = encrypted
	}
	return bson.Marshal(&raw)
}

// UnmarshalBSON decrypts the sensitive fields after deserialization.
func (e *PendingAuthState) UnmarshalBSON(data []byte) error {
	type pendingAlias PendingAuthState
	raw := &pendingAlias{}
	if err := bson.Unmarshal(data, raw); err != nil {
		return err
	}

	if raw.CodeVerifier != "" {
		decrypted, err := getEncryptor().DecryptString(raw.CodeVerifier)
		if err != nil {
			return err
		}
		raw.CodeVerifier = decrypted
	}
	*e = PendingAuthState(*raw)
	return nil
}
