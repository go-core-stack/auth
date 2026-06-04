// Copyright © 2025-2026 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package oauth

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// storedString marshals v and returns the raw stored value of the given BSON
// field, i.e. the on-disk representation without decryption applied.
func storedString(t *testing.T, v interface{}, field string) string {
	t.Helper()
	data, err := bson.Marshal(v)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var raw bson.M
	if err := bson.Unmarshal(data, &raw); err != nil {
		t.Fatalf("raw unmarshal failed: %v", err)
	}
	val, ok := raw[field]
	if !ok {
		t.Fatalf("field %q not present in stored document", field)
	}
	s, ok := val.(string)
	if !ok {
		t.Fatalf("field %q is not a string in stored document: %T", field, val)
	}
	return s
}

func TestTokenEntryEncryptionRoundTrip(t *testing.T) {
	orig := &TokenEntry{
		AccessToken:  "super-secret-access-token",
		TokenType:    "Bearer",
		RefreshToken: "super-secret-refresh-token",
		IDToken:      "super-secret-id-token",
		ExpiresAt:    123456,
		Scopes:       []string{"read", "write"},
		State:        SessionActive,
	}

	data, err := bson.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Stored ciphertext must differ from plaintext.
	if got := storedString(t, orig, "accessToken"); got == orig.AccessToken {
		t.Errorf("accessToken stored as plaintext: %q", got)
	}
	if got := storedString(t, orig, "refreshToken"); got == orig.RefreshToken {
		t.Errorf("refreshToken stored as plaintext: %q", got)
	}
	if got := storedString(t, orig, "idToken"); got == orig.IDToken {
		t.Errorf("idToken stored as plaintext: %q", got)
	}

	// Round-trip recovers plaintext.
	var got TokenEntry
	if err := bson.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.AccessToken != orig.AccessToken {
		t.Errorf("accessToken: got %q, want %q", got.AccessToken, orig.AccessToken)
	}
	if got.RefreshToken != orig.RefreshToken {
		t.Errorf("refreshToken: got %q, want %q", got.RefreshToken, orig.RefreshToken)
	}
	if got.IDToken != orig.IDToken {
		t.Errorf("idToken: got %q, want %q", got.IDToken, orig.IDToken)
	}
	// Non-encrypted fields survive the round-trip.
	if got.TokenType != orig.TokenType || got.State != orig.State || got.ExpiresAt != orig.ExpiresAt {
		t.Errorf("non-encrypted fields not preserved: %+v", got)
	}
}

func TestClientEntryEncryptionRoundTrip(t *testing.T) {
	orig := &ClientEntry{
		ClientID:                "client-123",
		ClientSecret:            "super-secret-client-secret",
		RegistrationAccessToken: "super-secret-registration-token",
		ClientType:              ClientTypeConfidential,
		RegistrationType:        RegistrationTypeStatic,
	}

	data, err := bson.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	if got := storedString(t, orig, "clientSecret"); got == orig.ClientSecret {
		t.Errorf("clientSecret stored as plaintext: %q", got)
	}
	if got := storedString(t, orig, "registrationAccessToken"); got == orig.RegistrationAccessToken {
		t.Errorf("registrationAccessToken stored as plaintext: %q", got)
	}
	// ClientID must not be encrypted.
	if got := storedString(t, orig, "clientId"); got != orig.ClientID {
		t.Errorf("clientId should be stored as plaintext: got %q, want %q", got, orig.ClientID)
	}

	var got ClientEntry
	if err := bson.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.ClientSecret != orig.ClientSecret {
		t.Errorf("clientSecret: got %q, want %q", got.ClientSecret, orig.ClientSecret)
	}
	if got.RegistrationAccessToken != orig.RegistrationAccessToken {
		t.Errorf("registrationAccessToken: got %q, want %q", got.RegistrationAccessToken, orig.RegistrationAccessToken)
	}
	if got.ClientID != orig.ClientID {
		t.Errorf("clientId: got %q, want %q", got.ClientID, orig.ClientID)
	}
	// Int-enum fields survive the round-trip unchanged.
	if got.ClientType != orig.ClientType {
		t.Errorf("clientType: got %d, want %d", got.ClientType, orig.ClientType)
	}
	if got.RegistrationType != orig.RegistrationType {
		t.Errorf("registrationType: got %d, want %d", got.RegistrationType, orig.RegistrationType)
	}
}

func TestPendingAuthStateEncryptionRoundTrip(t *testing.T) {
	orig := &PendingAuthState{
		ServerURL:    "https://example.com",
		AccountID:    "account-1",
		CodeVerifier: "super-secret-code-verifier",
		RedirectURI:  "https://consumer.example/callback",
		Scopes:       []string{"read"},
		CreatedAt:    time.Unix(1700000000, 0),
	}

	data, err := bson.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	if got := storedString(t, orig, "codeVerifier"); got == orig.CodeVerifier {
		t.Errorf("codeVerifier stored as plaintext: %q", got)
	}

	var got PendingAuthState
	if err := bson.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.CodeVerifier != orig.CodeVerifier {
		t.Errorf("codeVerifier: got %q, want %q", got.CodeVerifier, orig.CodeVerifier)
	}
	if got.ServerURL != orig.ServerURL || got.AccountID != orig.AccountID {
		t.Errorf("non-encrypted fields not preserved: %+v", got)
	}
}
