// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>
//
// This file is part of the hash package, which provides cryptographic utilities
// for validating HMAC-SHA256 signatures and authenticating HTTP requests.

package hash

import (
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

/*
Package hash provides utilities for validating cryptographic signatures
on HTTP requests using HMAC-SHA256.

This file contains:
- An interface and implementation for validating authentication headers on HTTP requests.
- Logic to check the signature, timestamp, and expiration of requests.

# Usage

    import (
        "net/http"
        "yourmodule/hash"
    )

    func main() {
        // validity is the allowed time window (in seconds) for a request to be considered valid
        validator := hash.NewValidator(60) // 60 seconds validity

        // Assume req is an *http.Request with authentication headers
        ok, err := validator.Validate(req, "supersecret")
        if !ok {
            fmt.Println("Validation failed:", err)
            return
        }
        fmt.Println("Request is valid!")
    }

# Function Details

- Validator interface

  - Validate(r *http.Request, secret string) (bool, error)
    Validates the authentication headers on the provided HTTP request.

- NewValidator(validity int64) Validator

  - validity: Allowed time window (in seconds) for the request to be valid.

  Returns a Validator instance for validating HTTP requests.
*/

// Validator defines an interface for validating authentication headers on HTTP requests.
type Validator interface {
	// Validate checks the HMAC signature, timestamp, and expiration of the request.
	// Returns true if valid, false and an error otherwise.
	Validate(r *http.Request, secret string) (bool, error)
}

// validator is a concrete implementation of the Validator interface.
// It holds the allowed validity window (in seconds) for request timestamps.
type validator struct {
	validity int64 // Allowed time window (in seconds) for request validity
}

// Validate checks the HMAC signature, timestamp, and expiration of the HTTP request.
//
// Steps performed:
//  1. Ensures required headers are present: x-signature and x-timestamp.
//  2. Decodes the hex-encoded signature from the x-signature header.
//  3. Parses the timestamp from the x-timestamp header (RFC3339 format).
//  4. Checks if the request is within the allowed validity window.
//  5. Recomputes the expected HMAC signature and compares it to the provided signature.
//
// Parameters:
//   - r:      The HTTP request to validate.
//   - secret: The secret key used for HMAC validation.
//
// Returns:
//   - bool:  true if the request is valid, false otherwise.
//   - error: Reason for validation failure, if any.
func (v *validator) Validate(r *http.Request, secret string) (bool, error) {
	// Ensure headers are present
	if len(r.Header) == 0 {
		return false, fmt.Errorf("missing required headers")
	}

	// Retrieve the signature from the header
	sigStr := r.Header.Get("x-signature")
	if sigStr == "" {
		return false, fmt.Errorf("missing signature header")
	}

	// Decode the hex-encoded signature
	sig, err := hex.DecodeString(sigStr)
	if err != nil {
		return false, fmt.Errorf("invalid signature format")
	}

	// Retrieve the timestamp from the header
	timeStr := r.Header.Get("x-timestamp")
	if timeStr == "" {
		return false, fmt.Errorf("missing timestamp header")
	}

	// Parse the timestamp (RFC3339 format)
	timeStamp, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return false, fmt.Errorf("error parsing timestamp: %s", err)
	}

	// Check if the request is within the allowed validity window
	now := time.Now().Unix()
	if now >= (timeStamp.Unix() + v.validity) {
		return false, fmt.Errorf("expired access")
	}

	// Recompute the expected HMAC signature using the method, path, and timestamp
	if !hmac.Equal(sig, generateSHA256HMAC(secret, r.Method, r.URL.Path, timeStr)) {
		return false, fmt.Errorf("invalid hmac signature")
	}

	return true, nil
}

// NewValidator creates a new Validator instance for validating HTTP requests.
//
// Parameters:
//   - validity: Allowed time window (in seconds) for the request to be valid.
//
// Returns:
//   - Validator: An instance that can validate authentication headers on HTTP requests.
//
// Example:
//
//	validator := hash.NewValidator(60) // 60 seconds validity
//	ok, err := validator.Validate(req, "supersecret")
func NewValidator(validity int64) Validator {
	return &validator{
		validity: validity,
	}
}
