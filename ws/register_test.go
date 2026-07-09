// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package ws

import (
	"context"
	"testing"

	"github.com/go-core-stack/auth/route"
)

// NOTE: a full NewMux/Handle happy-path test (route persisted to the store)
// requires a real MongoDB, because db.StoreCollection carries an unexported
// method (startEventLogger) and cannot be implemented outside the core/db
// package — route table initialization needs a genuine collection. That wiring
// is exercised by the integration suite. Here we unit-test everything that runs
// before the collection is touched: Handle's argument guards, and the local
// mux registration (validation + duplicate rejection) that Handle now performs
// BEFORE it persists, so a bad route never reaches the store.

func TestHandle_ValidatesArguments(t *testing.T) {
	// newTestMux has a nil route store; these guards must return before it is
	// ever dereferenced.
	m := newTestMux()
	ctx := context.Background()

	if err := m.Handle(ctx, nil, func(ctx context.Context, wsc *WSContext) {}); err == nil {
		t.Error("nil route accepted, want error")
	}
	if err := m.Handle(ctx, NewRoute("/api/v1/ws/x", "r", "v", nil), nil); err == nil {
		t.Error("nil handler accepted, want error")
	}
}

func TestRegisterHandler(t *testing.T) {
	fn := func(ctx context.Context, wsc *WSContext) {}

	t.Run("succeeds once", func(t *testing.T) {
		m := newTestMux()
		if err := m.registerHandler("/api/v1/ws/a", route.GET, fn); err != nil {
			t.Fatalf("registerHandler: %v", err)
		}
	})

	t.Run("rejects duplicate pattern", func(t *testing.T) {
		m := newTestMux()
		if err := m.registerHandler("/api/v1/ws/dup", route.GET, fn); err != nil {
			t.Fatalf("first registration: %v", err)
		}
		// A duplicate would panic inside http.ServeMux; registerHandler must
		// recover it and surface an error so Handle can bail out before
		// persisting.
		if err := m.registerHandler("/api/v1/ws/dup", route.GET, fn); err == nil {
			t.Error("duplicate registration accepted, want error")
		}
	})

	t.Run("rejects malformed pattern", func(t *testing.T) {
		m := newTestMux()
		if err := m.registerHandler("/api/v1/ws/{unclosed", route.GET, fn); err == nil {
			t.Error("malformed pattern accepted, want error")
		}
	})
}
