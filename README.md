# auth

A Go package for secure HMAC-SHA256-based authentication and validation of HTTP requests.

## Features

- **HMAC-SHA256 Generation:** Easily generate cryptographic signatures for your data.
- **HTTP Request Signing:** Attach authentication headers (`x-signature`, `x-api-key-id`, `x-timestamp`) to HTTP requests.
- **Request Validation:** Validate signed HTTP requests, including signature and timestamp checks.
- **Configurable Validity Window:** Control how long a signed request remains valid.

## Usage

### 1. Generate HMAC-SHA256 Signature

```go
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
```

### 2. Sign HTTP Requests

```go
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
```

### 3. Validate HTTP Requests

```go
import (
    "net/http"
    "yourmodule/hash"
    "fmt"
)

func main() {
    validator := hash.NewValidator(60) // 60 seconds validity
    // Assume req is an *http.Request with authentication headers
    ok, err := validator.Validate(req, "supersecret")
    if !ok {
        fmt.Println("Validation failed:", err)
        return
    }
    fmt.Println("Request is valid!")
}
```

## API

### `GenerateSHA256HMAC(secret string, v ...string) string`

- Generates a hex-encoded HMAC-SHA256 signature for the concatenated input strings.

### `Generator` interface

- `AddAuthHeaders(r *http.Request) *http.Request`: Adds authentication headers to the HTTP request.

### `NewGenerator(id, secret string) Generator`

- Returns a Generator for signing HTTP requests.

### `Validator` interface

- `Validate(r *http.Request, secret string) (bool, error)`: Validates the authentication headers on the HTTP request.

### `NewValidator(validity int64) Validator`

- Returns a Validator for validating HTTP requests. `validity` is the allowed time window (in seconds).

## Testing

Run all tests:

```sh
go test ./hash
```