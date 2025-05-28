// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package hash

import (
	"net/http/httptest"
	"testing"
	"time"
)

// TestGeneratorAndValidator demonstrates signing an HTTP request with Generator
// and validating it with Validator.
func TestGeneratorAndValidator(t *testing.T) {
	// Setup
	apiKeyID := "test-key"
	secret := "supersecret"
	validity := int64(60) // 60 seconds validity window

	// Create a new HTTP request
	req := httptest.NewRequest("GET", "https://api.example.com/resource", nil)

	// Sign the request using the Generator
	gen := NewGenerator(apiKeyID, secret)
	signedReq := gen.AddAuthHeaders(req)

	// Validate the signed request using the Validator
	validator := NewValidator(validity)
	ok, err := validator.Validate(signedReq, secret)
	if !ok {
		t.Fatalf("Validation failed: %v", err)
	}

	// Tamper with the signature to ensure validation fails
	signedReq.Header.Set("x-signature", "deadbeef")
	ok, err = validator.Validate(signedReq, secret)
	if ok || err == nil {
		t.Fatalf("Expected validation to fail for tampered signature")
	}

	// Tamper with the timestamp to simulate expiration
	signedReq = gen.AddAuthHeaders(req) // re-sign to get a valid signature
	oldTime := time.Now().Add(-2 * time.Minute).Format(time.RFC3339)
	signedReq.Header.Set("x-timestamp", oldTime)
	ok, err = validator.Validate(signedReq, secret)
	if ok || err == nil || err.Error() != "expired access" {
		t.Fatalf("Expected expired access error, got: %v", err)
	}
}
