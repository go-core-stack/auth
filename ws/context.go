// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package ws

import (
	"context"
	"net/http"

	actx "github.com/go-core-stack/auth/context"
)

// WSContext carries everything a WebSocket handler needs for a single
// connection. It is built by the Mux after authentication and the WebSocket
// upgrade succeed, and handed to the HandlerFunc.
//
// WSContext deliberately does NOT satisfy context.Context: the request
// scoped context.Context is passed as the first argument to the HandlerFunc,
// keeping WebSocket specific state out of functions that expect a plain
// context.
type WSContext struct {
	// AuthInfo is the authenticated identity extracted from the Auth-Info
	// header before the upgrade. It is always non-nil for a handler.
	AuthInfo *actx.AuthInfo

	// Conn is the WebSocket connection, abstracted from the underlying
	// WebSocket library.
	Conn Conn

	// PathParams holds the values of the variable path segments of the
	// matched route, keyed by name. For a route registered as
	// "/api/v1/ws/events/{eventId}" a request to
	// "/api/v1/ws/events/42" yields PathParams["eventId"] == "42".
	PathParams map[string]string

	// Request is the original HTTP upgrade request.
	Request *http.Request
}

// HandlerFunc is implemented by service authors to handle an authenticated
// WebSocket connection. The context.Context is scoped to the connection and
// is cancelled when the connection is closed or the underlying request is
// cancelled.
type HandlerFunc func(ctx context.Context, wsc *WSContext)
