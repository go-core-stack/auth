// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package hash

import (
	"testing"
)

func Test_HashGeneration(t *testing.T) {
	secret := "mysupersecretcode"
	method := "POST"
	path := "/api/service1/v1/scope/abc/test/test1"
	timestamp := "1748410688"

	sig := GenerateSHA256HMAC(secret, method, path, timestamp)

	if sig != "2c269d572fbd6b324b5f6eb1cf06bed60811b43a82642d5f7f438b65160caa08" {
		t.Errorf("generated HMAC signature doesn't match as expected")
	}
}
