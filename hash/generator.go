// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package hash

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

/*
Package hash provides utilities for generating cryptographic hashes.

This file contains a function to generate a SHA-256 HMAC (Hash-based Message Authentication Code)
from a secret and one or more input strings.

# Usage

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

# Function Details

- GenerateSHA256HMAC(secret string, v ...string) string

  - secret: The secret key used for HMAC generation.
  - v:      Variadic string arguments to be concatenated and signed.

  Returns a hex-encoded string representing the HMAC-SHA256 signature.
*/

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
	// Concatenate all input strings into a single string
	raw := strings.Join(v, "")

	// Create a new HMAC hasher using SHA-256 and the provided secret key
	h := hmac.New(sha256.New, []byte(secret))

	// Write the concatenated string to the hasher
	h.Write([]byte(raw))

	// Compute the HMAC and return it as a hex-encoded string
	return hex.EncodeToString(h.Sum(nil))
}
