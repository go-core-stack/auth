// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package ws

import (
	"net/http"
	"time"
)

// Default values for the tunable connection parameters. They are chosen to
// be reasonable for long lived, low traffic control channels typical of the
// services behind auth-gateway.
const (
	defaultPingInterval   = 30 * time.Second
	defaultMaxMessageSize = int64(32 * 1024) // 32 KiB
	defaultReadTimeout    = 0                // no per-read deadline
	defaultWriteTimeout   = 10 * time.Second
)

// muxOptions holds the resolved configuration for a Mux. It is populated
// from defaults and mutated by the MuxOption functions.
type muxOptions struct {
	pingInterval   time.Duration
	maxMessageSize int64
	readTimeout    time.Duration
	writeTimeout   time.Duration
	originChecker  func(r *http.Request) bool
	// upgradeBufferSize is retained for API compatibility. The underlying
	// coder/websocket library manages its own buffers and does not expose a
	// tunable buffer size, so this value is currently advisory.
	upgradeBufferSize int
}

// defaultMuxOptions returns the option set with all defaults applied.
func defaultMuxOptions() muxOptions {
	return muxOptions{
		pingInterval:   defaultPingInterval,
		maxMessageSize: defaultMaxMessageSize,
		readTimeout:    defaultReadTimeout,
		writeTimeout:   defaultWriteTimeout,
	}
}

// MuxOption configures a Mux at construction time.
type MuxOption func(*muxOptions)

// WithPingInterval sets the interval between keepalive pings. A value <= 0
// disables server initiated pings.
func WithPingInterval(d time.Duration) MuxOption {
	return func(o *muxOptions) { o.pingInterval = d }
}

// WithMaxMessageSize sets the maximum size, in bytes, of a single inbound
// message. Messages larger than this cause the read to fail and the
// connection to be closed.
func WithMaxMessageSize(n int64) MuxOption {
	return func(o *muxOptions) { o.maxMessageSize = n }
}

// WithReadTimeout sets the maximum duration a single ReadMessage/ReadJSON
// call may block before failing. A value <= 0 disables the per-read deadline
// (reads block until a message arrives or the connection closes).
func WithReadTimeout(d time.Duration) MuxOption {
	return func(o *muxOptions) { o.readTimeout = d }
}

// WithWriteTimeout sets the maximum duration a single write may block before
// failing. A value <= 0 disables the per-write deadline.
func WithWriteTimeout(d time.Duration) MuxOption {
	return func(o *muxOptions) { o.writeTimeout = d }
}

// WithOriginChecker installs a custom Origin validation function that runs
// before the WebSocket upgrade. Returning false rejects the request with
// 403. When set, the library's built-in same-origin check is bypassed in
// favour of this function, so it must fully validate the Origin.
func WithOriginChecker(fn func(r *http.Request) bool) MuxOption {
	return func(o *muxOptions) { o.originChecker = fn }
}

// WithUpgradeBufferSize sets a hint for the upgrade read/write buffer size.
// See muxOptions.upgradeBufferSize for the current limitation.
func WithUpgradeBufferSize(n int) MuxOption {
	return func(o *muxOptions) { o.upgradeBufferSize = n }
}
