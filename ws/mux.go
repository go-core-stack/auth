// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

/*
Package ws provides a mux-centric WebSocket library for services that sit
behind auth-gateway.

Auth-gateway authenticates incoming HTTP requests, sets the Auth-Info header
(a base64 encoded AuthInfo JSON document) and reverse-proxies to backend
services. For plain request/response HTTP this is transparent, but once a
connection is upgraded to WebSocket the backend only sees a raw tunnel. This
package gives backend service authors an authenticated WebSocket session with
minimal boilerplate.

A single Mux owns routing, auth extraction, the WebSocket upgrade and handler
dispatch. Authentication happens once, in ServeHTTP, before the upgrade: a
request without a valid Auth-Info header is rejected with 401 and never
reaches a handler. Each registered route is written to the shared route store
so auth-gateway learns to route (and authorize) it.

Handlers receive a *WSContext carrying the authenticated identity, the
connection, the extracted path parameters and the original request:

	wsMux, err := ws.NewMux(client, apiEndpoint, ws.WithPingInterval(30*time.Second))
	if err != nil {
		log.Fatal(err)
	}

	err = wsMux.Handle(ctx,
		ws.NewRoute("/api/v1/ws/events/{eventId}", "events", "watch", []string{"workspace"}),
		func(ctx context.Context, wsc *ws.WSContext) {
			defer wsc.Conn.Close()
			for {
				_, msg, err := wsc.Conn.ReadMessage()
				if err != nil {
					return
				}
				_ = msg // handle msg ...
			}
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/api/v1/ws/", wsMux)

The Mux implements http.Handler, so it can be mounted on any HTTP server with
a path prefix.
*/
package ws

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"

	actx "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/model"
	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/db"
	"github.com/go-core-stack/core/errors"
)

// Mux is the central WebSocket multiplexer. It owns path routing, auth
// extraction, the WebSocket upgrade and handler dispatch, and implements
// http.Handler.
type Mux struct {
	router      *http.ServeMux
	routes      *route.RouteTable
	apiEndpoint string
	opts        muxOptions
}

// NewMux creates a Mux.
//
// client is the datastore client used to register routes with auth-gateway;
// apiEndpoint is this backend service's endpoint recorded on each registered
// route so auth-gateway knows where to proxy.
//
// It returns an error if the route store cannot be located.
func NewMux(client db.StoreClient, apiEndpoint string, opts ...MuxOption) (*Mux, error) {
	routes, err := route.LocateRouteTable(client)
	if err != nil {
		return nil, errors.Wrapf(errors.GetErrCode(err), "failed to locate route table: %s", err)
	}

	options := defaultMuxOptions()
	for _, opt := range opts {
		opt(&options)
	}

	return &Mux{
		router:      http.NewServeMux(),
		routes:      routes,
		apiEndpoint: apiEndpoint,
		opts:        options,
	}, nil
}

// Handle registers a WebSocket endpoint. It:
//  1. adds the route to the internal router for path matching and path
//     parameter extraction, and
//  2. writes the route to the shared route store so auth-gateway registers
//     and authorizes it (one write per endpoint).
//
// It returns an error if the route store write fails or the route conflicts
// with an already registered pattern.
func (m *Mux) Handle(ctx context.Context, r *model.Route, fn HandlerFunc) error {
	if r == nil {
		return errors.Wrapf(errors.InvalidArgument, "route must not be nil")
	}
	if fn == nil {
		return errors.Wrapf(errors.InvalidArgument, "handler must not be nil")
	}

	// Register with the internal router first. This validates the pattern
	// and rejects a duplicate route, so a bad registration fails before we
	// persist anything and cannot leave the route store advertising an
	// endpoint the mux will not serve.
	if err := m.registerHandler(r.Url, r.Method, fn); err != nil {
		return err
	}

	// Persist the route so auth-gateway learns to route and authorize it.
	key := &route.Key{
		Url:    r.Url,
		Method: r.Method,
	}
	entry := &route.Route{
		Key:      key,
		Endpoint: m.apiEndpoint,
		Resource: r.Resource,
		Verb:     r.Verb,
		Scopes:   r.Scopes,
	}
	if err := m.routes.Locate(ctx, key, entry); err != nil {
		return errors.Wrapf(errors.GetErrCode(err), "failed to register route %q: %s", r.Url, err)
	}

	return nil
}

// registerHandler wires a handler into the internal router. ServeHTTP
// performs auth before dispatching here, so by the time this handler runs the
// AuthInfo is already attached to the request context.
//
// http.ServeMux panics on a malformed or duplicate pattern; that panic is
// recovered and returned as an error so route registration never crashes the
// caller.
func (m *Mux) registerHandler(path string, method route.MethodType, fn HandlerFunc) (err error) {
	paramNames := parseParamNames(path)
	pattern := methodString(method) + " " + path
	defer func() {
		if r := recover(); r != nil {
			err = errors.Wrapf(errors.InvalidArgument, "failed to register pattern %q: %v", pattern, r)
		}
	}()
	m.router.HandleFunc(pattern, func(w http.ResponseWriter, req *http.Request) {
		info, err := actx.GetAuthInfoFromContext(req.Context())
		if err != nil {
			// Should not happen: ServeHTTP guarantees auth ran first.
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		m.serve(w, req, info, paramNames, fn)
	})
	return nil
}

// ServeHTTP implements http.Handler. It authenticates the request before the
// WebSocket upgrade, then dispatches to the matching registered handler.
func (m *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Centralized auth, before the upgrade. A missing or invalid
	// Auth-Info header is rejected outright.
	info, err := actx.GetAuthInfoHeader(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// 2. Route the request. An unmatched path is a 404 (a matched path with
	// the wrong method yields the router's 405).
	_, pattern := m.router.Handler(r)
	if pattern == "" {
		http.NotFound(w, r)
		return
	}

	// 3. Attach the identity and dispatch. The registered handler reads the
	// AuthInfo from the context and performs the upgrade.
	ctx := actx.ContextWithAuthInfo(r.Context(), info)
	m.router.ServeHTTP(w, r.WithContext(ctx))
}

// serve upgrades the connection and runs the handler for its lifetime.
func (m *Mux) serve(w http.ResponseWriter, r *http.Request, info *actx.AuthInfo, paramNames []string, fn HandlerFunc) {
	// Custom origin validation runs before the upgrade so we can reject with
	// a plain 403 rather than a WebSocket close frame.
	if m.opts.originChecker != nil {
		if !m.opts.originChecker(r) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
	}

	// Services behind auth-gateway always see a rewritten Host header, so
	// coder/websocket's default same-origin check (Origin == Host) would
	// reject every legitimate upgrade. Disable it unconditionally and let
	// consumers opt in to origin validation via WithOriginChecker.
	acceptOpts := &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	}

	c, err := websocket.Accept(w, r, acceptOpts)
	if err != nil {
		// Accept has already written an error response.
		return
	}
	// CloseNow is a no-op if the handler closed gracefully; it guarantees
	// the connection is torn down on any exit path.
	defer c.CloseNow()

	if m.opts.maxMessageSize > 0 {
		c.SetReadLimit(m.opts.maxMessageSize)
	}

	// The connection lifecycle context is cancelled when the handler returns
	// or the underlying request is cancelled, unblocking the ping loop and
	// any in-flight reads/writes.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Actively close the connection when the context is cancelled — request
	// cancellation, a failed keepalive ping, or handler return. This tears
	// the socket down promptly even if the handler is blocked on something
	// other than a read/write when cancellation happens. Close is safe to
	// call concurrently with the handler and is idempotent, so a handler
	// that already closed gracefully makes this a no-op.
	go func() {
		<-ctx.Done()
		_ = c.Close(websocket.StatusGoingAway, "connection closing")
	}()

	if m.opts.pingInterval > 0 {
		go m.pingLoop(ctx, c, cancel)
	}

	params := make(map[string]string, len(paramNames))
	for _, name := range paramNames {
		params[name] = r.PathValue(name)
	}

	wsc := &WSContext{
		AuthInfo:   info,
		Conn:       newConn(c, ctx, m.opts),
		PathParams: params,
		Request:    r,
	}

	fn(ctx, wsc)

	// Graceful close once the handler is done, if it did not close already.
	_ = c.Close(websocket.StatusNormalClosure, "")
}

// pingLoop periodically pings the peer to keep the connection alive and to
// detect a dead peer. A failed ping cancels the connection context.
func (m *Mux) pingLoop(ctx context.Context, c *websocket.Conn, cancel context.CancelFunc) {
	ticker := time.NewTicker(m.opts.pingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.Ping(ctx); err != nil {
				cancel()
				return
			}
		}
	}
}

// parseParamNames extracts the names of the "{name}" variable segments from a
// ServeMux route pattern path. The "{$}" end-of-path marker is ignored and a
// trailing "..." wildcard suffix is stripped from the name.
func parseParamNames(path string) []string {
	var names []string
	for _, seg := range strings.Split(path, "/") {
		if len(seg) < 2 || seg[0] != '{' || seg[len(seg)-1] != '}' {
			continue
		}
		name := seg[1 : len(seg)-1]
		if name == "$" {
			continue
		}
		name = strings.TrimSuffix(name, "...")
		names = append(names, name)
	}
	return names
}

// methodString maps a route.MethodType to its HTTP method name for use in a
// ServeMux pattern.
func methodString(m route.MethodType) string {
	switch m {
	case route.HEAD:
		return http.MethodHead
	case route.POST:
		return http.MethodPost
	case route.PUT:
		return http.MethodPut
	case route.PATCH:
		return http.MethodPatch
	case route.DELETE:
		return http.MethodDelete
	case route.CONNECT:
		return http.MethodConnect
	case route.OPTIONS:
		return http.MethodOptions
	case route.TRACE:
		return http.MethodTrace
	default:
		return http.MethodGet
	}
}
