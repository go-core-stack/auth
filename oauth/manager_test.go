// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"context"
	"testing"

	"github.com/go-core-stack/core/db"
	"github.com/go-core-stack/core/errors"
)

// NOTE: a full NewOAuthManager happy-path test requires a real MongoDB because
// db.StoreCollection carries an unexported method (startEventLogger) and cannot
// be implemented outside the core/db package — table/lock initialization needs a
// genuine collection. That end-to-end wiring is exercised by the integration
// suite (AUTH-0008). Here we unit-test every part of initialization that does
// not require a live collection: fail-closed encryptor key handling, and the
// early-exit guards of NewOAuthManager (which run before any collection is
// touched).

// fakeStore lets us drive NewOAuthManager up to (but not into) collection
// access. GetCollection returns nil intentionally — the encryptor and guard
// checks under test all run before it would be dereferenced.
type fakeStore struct{ name string }

func (s fakeStore) GetCollection(string) db.StoreCollection { return nil }
func (s fakeStore) Name() string                            { return s.name }

func TestInitManagerEncryptor_FailsClosedWithoutKey(t *testing.T) {
	t.Setenv(EncryptorKeyEnvVar, "") // ensure no env key

	m := &OAuthManager{}
	if _, err := m.initManagerEncryptor(OAuthConfig{}); err == nil {
		t.Fatal("expected fail-closed error when no key configured")
	} else if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}

func TestInitManagerEncryptor_ConfigKey(t *testing.T) {
	t.Setenv(EncryptorKeyEnvVar, "")

	m := &OAuthManager{}
	enc, err := m.initManagerEncryptor(OAuthConfig{EncryptorKey: "an-explicit-key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enc == nil {
		t.Fatal("expected a non-nil encryptor")
	}
}

func TestInitManagerEncryptor_EnvKeyFallback(t *testing.T) {
	t.Setenv(EncryptorKeyEnvVar, "env-provided-key")

	m := &OAuthManager{}
	enc, err := m.initManagerEncryptor(OAuthConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enc == nil {
		t.Fatal("expected a non-nil encryptor")
	}
}

func TestNewOAuthManager_NilStore(t *testing.T) {
	if _, err := NewOAuthManager(context.Background(), nil, OAuthConfig{}); err == nil {
		t.Fatal("expected error for nil store")
	} else if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}

func TestNewOAuthManager_FailsClosedWithoutKey(t *testing.T) {
	t.Setenv(EncryptorKeyEnvVar, "")

	store := fakeStore{name: "auth-library-test"}
	// The encryptor check runs before any collection is accessed, so the nil
	// collection from fakeStore is never dereferenced.
	if _, err := NewOAuthManager(context.Background(), store, OAuthConfig{}); err == nil {
		t.Fatal("expected fail-closed error when no encryption key is configured")
	} else if !errors.IsInvalidArgument(err) {
		t.Errorf("expected InvalidArgument, got %v", err)
	}
}
