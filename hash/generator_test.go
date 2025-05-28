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

	if sig != "04a41d00f2f133c8746d11c7d3d5bfc547fc514b583e3798b1df2c9c09204461" {
		t.Errorf("generated HMAC signature doesn't match as expected")
	}
}
