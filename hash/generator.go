// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package hash

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

/*
Package hash provides utilities for generating cryptographic hashes and
signing HTTP requests with HMAC-based authentication headers.

This file contains:
- Functions to generate a SHA-256 HMAC (Hash-based Message Authentication Code)
  from a secret and one or more input strings.
- An interface and implementation for attaching authentication headers to HTTP requests.

# Usage

Basic HMAC Generation:

    import (
        "fmt"
        "yourmodule/hash"
    )

    func main() {
        secret := "mysecretkey"
        message := "data to protect"
        signature := hash.GenerateSHA256HMAC(secret, message)
        fmt.Println("HMAC:", signature)
    }

Signing HTTP Requests:

    import (
        "net/http"
        "yourmodule/hash"
    )

    func main() {
        gen := hash.NewGenerator("api-key-id", "supersecret")
        req, _ := http.NewRequest("GET", "https://api.example.com/resource", nil)
        signedReq := gen.AddAuthHeaders(req)
        // signedReq now contains x-signature, x-api-key-id, and x-timestamp headers
    }

# Function Details

- GenerateSHA256HMAC(secret string, v ...string) string

  - secret: The secret key used for HMAC generation.
  - v:      Variadic string arguments to be concatenated and signed.

  Returns a hex-encoded string representing the HMAC-SHA256 signature.

- Generator interface

  - AddAuthHeaders(r *http.Request) *http.Request
    Adds authentication headers to the provided HTTP request.

- NewGenerator(id, secret string) Generator

  - id:     API key identifier.
  - secret: Secret key for HMAC signing.

  Returns a Generator instance for signing HTTP requests.
*/

// generateSHA256HMAC computes the raw SHA-256 HMAC for the concatenated input strings using the provided secret key.
// Returns the HMAC as a byte slice (not hex-encoded).
func generateSHA256HMAC(secret string, v ...string) []byte {
	// Concatenate all input strings into a single string
	raw := strings.Join(v, "")

	// Create a new HMAC hasher using SHA-256 and the provided secret key
	h := hmac.New(sha256.New, []byte(secret))

	// Write the concatenated string to the hasher
	h.Write([]byte(raw))

	// Return the raw HMAC bytes
	return h.Sum(nil)
}

// GenerateSHA256HMAC generates a SHA-256 HMAC signature for the given input strings using the provided secret key.
// The input strings are concatenated in the order provided, and the resulting string is signed.
// Returns the signature as a hex-encoded string.
//
// Parameters:
//   - secret: The secret key used for HMAC generation.
//   - v:      Variadic string arguments to be concatenated and signed.
//
// Example:
//
//	sig := GenerateSHA256HMAC("mysecret", "foo", "bar")
//	// sig now contains the hex-encoded HMAC of "foobar" using "mysecret" as the key.
func GenerateSHA256HMAC(secret string, v ...string) string {
	// Compute the HMAC and return it as a hex-encoded string
	return hex.EncodeToString(generateSHA256HMAC(secret, v...))
}

// Generator defines an interface for adding authentication headers to HTTP requests.
// Implementations should add at least a signature, API key ID, and timestamp.
type Generator interface {
	// AddAuthHeaders adds authentication headers to the provided HTTP request and returns it.
	AddAuthHeaders(r *http.Request) *http.Request
}

// generator is a concrete implementation of the Generator interface.
// It holds the API key ID and secret used for signing requests.
type generator struct {
	id     string // API key identifier
	secret string // Secret key for HMAC signing
}

// AddAuthHeaders attaches authentication headers to the given HTTP request.
// The following headers are added:
//   - x-signature: HMAC-SHA256 signature of the HTTP method, path, and timestamp
//   - x-api-key-id: The API key identifier
//   - x-timestamp: The current timestamp in RFC3339 format
//
// The signature is computed as HMAC(secret, method + path + timestamp).
func (g *generator) AddAuthHeaders(r *http.Request) *http.Request {
	// use RFC3339 format for the time stamp in the header
	timeStamp := time.Now().Format(time.RFC3339)

	// Compute the signature using HTTP method, path, and timestamp
	sig := GenerateSHA256HMAC(g.secret, r.Method, r.URL.Path, timeStamp)

	// Add the computed signature to the request headers
	r.Header.Add("x-signature", sig)

	// Add the API key ID to the request headers
	r.Header.Add("x-api-key-id", g.id)

	// add timestamp to header
	r.Header.Add("x-timestamp", timeStamp)
	return r
}

// NewGenerator creates a new Generator instance for signing HTTP requests.
//
// Parameters:
//   - id:     API key identifier
//   - secret: Secret key for HMAC signing
//
// Returns:
//   - Generator: An instance that can add authentication headers to HTTP requests.
//
// Example:
//
//	gen := hash.NewGenerator("api-key-id", "supersecret")
//	req, _ := http.NewRequest("GET", "https://api.example.com/resource", nil)
//	signedReq := gen.AddAuthHeaders(req)
func NewGenerator(id, secret string) Generator {
	return &generator{
		id:     id,
		secret: secret,
	}
}
