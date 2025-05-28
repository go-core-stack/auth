// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package hash

// Constants for HTTP authentication header keys used in HMAC-based signing and validation.
const (
	apiKeySignatureHeader = "x-signature"  // Header for the HMAC-SHA256 signature
	apiKeyTimestampHeader = "x-timestamp"  // Header for the request timestamp (RFC3339 format)
	apiKeyIdHeader        = "x-api-key-id" // Header for the API key identifier
)
