// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package ws

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	actx "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/route"
)

func TestMessageTypeConstants(t *testing.T) {
	if TextMessage != int(websocket.MessageText) {
		t.Errorf("TextMessage = %d, want %d", TextMessage, websocket.MessageText)
	}
	if BinaryMessage != int(websocket.MessageBinary) {
		t.Errorf("BinaryMessage = %d, want %d", BinaryMessage, websocket.MessageBinary)
	}
}

func TestConnReadWriteJSON(t *testing.T) {
	type payload struct {
		Msg string `json:"msg"`
		N   int    `json:"n"`
	}

	m := newTestMux()
	m.registerHandler("/ws/json", route.GET, func(ctx context.Context, wsc *WSContext) {
		defer wsc.Conn.Close()
		var in payload
		if err := wsc.Conn.ReadJSON(&in); err != nil {
			return
		}
		// Echo back with N incremented to prove the round-trip.
		_ = wsc.Conn.WriteJSON(payload{Msg: in.Msg, N: in.N + 1})
	})

	srv := httptest.NewServer(m)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, _, err := websocket.Dial(ctx, dialURL(srv.URL, "/ws/json"), &websocket.DialOptions{
		HTTPHeader: authHeader(t, &actx.AuthInfo{UserName: "dave"}),
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.CloseNow()

	if err := wsjson.Write(ctx, c, payload{Msg: "ping", N: 1}); err != nil {
		t.Fatalf("write: %v", err)
	}
	var out payload
	if err := wsjson.Read(ctx, c, &out); err != nil {
		t.Fatalf("read: %v", err)
	}
	if out.Msg != "ping" || out.N != 2 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestReadCtxAppliesTimeout(t *testing.T) {
	base := context.Background()

	withTimeout := &wsConn{ctx: base, readTimeout: 50 * time.Millisecond}
	ctx, cancel := withTimeout.readCtx()
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Error("readCtx with readTimeout should carry a deadline")
	}

	noTimeout := &wsConn{ctx: base}
	ctx2, cancel2 := noTimeout.readCtx()
	defer cancel2()
	if _, ok := ctx2.Deadline(); ok {
		t.Error("readCtx without readTimeout should not carry a deadline")
	}
}
