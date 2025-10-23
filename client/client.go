// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package client

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-core-stack/auth/hash"
)

/*
Package client provides a secure HTTP client that automatically signs requests
using HMAC-SHA256 authentication headers.

This client ensures:
- All outgoing requests are signed with the correct API key and secret.
- The endpoint is enforced and cannot be manipulated per request.
- Optionally allows insecure TLS connections for testing.

# Usage

    import (
        "github.com/go-core-stack/auth/client"
        "net/http"
    )

    func main() {
        cli, err := client.NewClient("https://api.example.com", "api-key-id", "supersecret", false)
        if err != nil {
            panic(err)
        }
        req, _ := http.NewRequest("GET", "/resource", nil)
        resp, err := cli.Do(req)
        if err != nil {
            panic(err)
        }
        defer resp.Body.Close()
        // Handle response...
    }

# Types

- Client interface
  - Do(*http.Request) (*http.Response, error): Sends a signed HTTP request.

- NewClient(endpoint, apiKey, secret string, allowInsecure bool) (Client, error)
  - endpoint:      Base API endpoint (scheme + host + optional path)
  - apiKey:        API key identifier
  - secret:        Secret key for HMAC signing
  - allowInsecure: If true, disables TLS certificate verification (for testing)
*/

type Client interface {
	// Do sends the HTTP request after signing it with authentication headers.
	Do(*http.Request) (*http.Response, error)
}

// client is a concrete implementation of the Client interface.
// It holds configuration for endpoint, credentials, and HTTP client.
type client struct {
	endpoint   string         // Base API endpoint
	apiKey     string         // API key identifier
	secret     string         // Secret key for HMAC signing
	url        *url.URL       // Parsed endpoint URL
	hClient    *http.Client   // Underlying HTTP client
	hGenerator hash.Generator // HMAC header generator
}

// Do signs the HTTP request with authentication headers and sends it.
// It enforces the configured endpoint, preventing endpoint manipulation.
//
// Steps:
//  1. Overwrites the request's scheme, host, and path with the configured endpoint.
//  2. Signs the request using the HMAC generator.
//  3. Sends the request using the underlying HTTP client.
//
// Returns the HTTP response or an error.
func (c *client) Do(req *http.Request) (*http.Response, error) {
	if c.url == nil {
		return nil, fmt.Errorf("Client not initialized")
	}
	// Ensure the request uses the configured endpoint, not what the caller set.
	req.URL.Scheme = c.url.Scheme
	req.URL.Host = c.url.Host
	//req.URL.Path = c.url.Path

	// Add authentication headers and send the request.
	return c.hClient.Do(c.hGenerator.AddAuthHeaders(req))
}

// NewClient creates a new HMAC-authenticated HTTP client.
//
// Parameters:
//   - endpoint:      Base API endpoint (e.g., "https://api.example.com")
//   - apiKey:        API key identifier
//   - secret:        Secret key for HMAC signing
//   - allowInsecure: If true, disables TLS certificate verification (for testing)
//
// Returns:
//   - Client: Secure HTTP client that signs all requests
//   - error:  If endpoint is invalid
func NewClient(endpoint, apiKey, secret string, allowInsecure bool) (Client, error) {
	uri, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	var hClient *http.Client
	if allowInsecure {
		hClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	} else {
		hClient = &http.Client{}
	}
	return &client{
		endpoint:   endpoint,
		apiKey:     apiKey,
		secret:     secret,
		url:        uri,
		hClient:    hClient,
		hGenerator: hash.NewGenerator(apiKey, secret),
	}, nil
}
