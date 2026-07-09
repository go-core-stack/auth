// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package ws

import (
	"context"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// Message types exchanged over a WebSocket connection. These mirror the
// underlying protocol opcodes so that consumers of this package never need
// to import the WebSocket library directly.
const (
	// TextMessage denotes a UTF-8 encoded text data message.
	TextMessage = int(websocket.MessageText)

	// BinaryMessage denotes a binary data message.
	BinaryMessage = int(websocket.MessageBinary)
)

// Conn hides the underlying WebSocket library from consumers. Handlers
// registered with the Mux interact with the connection exclusively through
// this interface and therefore never import the WebSocket library directly.
//
// All methods are safe for concurrent use except that a single connection
// must not be read from concurrently by more than one goroutine (a
// restriction of the underlying library).
type Conn interface {
	// ReadMessage blocks until a data message is received and returns its
	// message type (TextMessage or BinaryMessage) along with the payload.
	ReadMessage() (messageType int, p []byte, err error)

	// WriteMessage writes a data message of the given type to the peer.
	WriteMessage(messageType int, data []byte) error

	// WriteJSON marshals v to JSON and writes it as a text message.
	WriteJSON(v interface{}) error

	// ReadJSON reads the next message and unmarshals it as JSON into v.
	ReadJSON(v interface{}) error

	// Close closes the connection with a normal closure status.
	Close() error
}

// wsConn adapts *websocket.Conn (coder/websocket) to the Conn interface.
//
// coder/websocket is context native: every read/write takes a
// context.Context rather than a deadline set on the connection. wsConn holds
// the connection's lifecycle context and derives a per-call timeout from it
// when read/write timeouts are configured, presenting the deadline-free
// gorilla style API that the Conn interface exposes.
type wsConn struct {
	c            *websocket.Conn
	ctx          context.Context
	readTimeout  time.Duration
	writeTimeout time.Duration
}

// newConn wraps a coder/websocket connection using the mux options.
func newConn(c *websocket.Conn, ctx context.Context, opts muxOptions) *wsConn {
	return &wsConn{
		c:            c,
		ctx:          ctx,
		readTimeout:  opts.readTimeout,
		writeTimeout: opts.writeTimeout,
	}
}

// readCtx returns the context to use for a read, applying the read timeout
// when one is configured. The returned cancel func must always be called.
func (w *wsConn) readCtx() (context.Context, context.CancelFunc) {
	if w.readTimeout > 0 {
		return context.WithTimeout(w.ctx, w.readTimeout)
	}
	return context.WithCancel(w.ctx)
}

// writeCtx returns the context to use for a write, applying the write timeout
// when one is configured. The returned cancel func must always be called.
func (w *wsConn) writeCtx() (context.Context, context.CancelFunc) {
	if w.writeTimeout > 0 {
		return context.WithTimeout(w.ctx, w.writeTimeout)
	}
	return context.WithCancel(w.ctx)
}

func (w *wsConn) ReadMessage() (int, []byte, error) {
	ctx, cancel := w.readCtx()
	defer cancel()
	mt, data, err := w.c.Read(ctx)
	return int(mt), data, err
}

func (w *wsConn) WriteMessage(messageType int, data []byte) error {
	ctx, cancel := w.writeCtx()
	defer cancel()
	return w.c.Write(ctx, websocket.MessageType(messageType), data)
}

func (w *wsConn) WriteJSON(v interface{}) error {
	ctx, cancel := w.writeCtx()
	defer cancel()
	return wsjson.Write(ctx, w.c, v)
}

func (w *wsConn) ReadJSON(v interface{}) error {
	ctx, cancel := w.readCtx()
	defer cancel()
	return wsjson.Read(ctx, w.c, v)
}

func (w *wsConn) Close() error {
	return w.c.Close(websocket.StatusNormalClosure, "")
}
