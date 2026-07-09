// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package ws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	actx "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/route"
)

// newTestMux builds a Mux without a datastore by wiring handlers directly
// into the internal router, exercising the same auth/upgrade path as Handle
// without requiring a live route store.
func newTestMux(opts ...MuxOption) *Mux {
	options := defaultMuxOptions()
	for _, opt := range opts {
		opt(&options)
	}
	return &Mux{
		router: http.NewServeMux(),
		opts:   options,
	}
}

// authHeader builds an http.Header carrying a valid Auth-Info header for info.
func authHeader(t *testing.T, info *actx.AuthInfo) http.Header {
	t.Helper()
	r := &http.Request{Header: http.Header{}}
	if err := actx.SetAuthInfoHeader(r, info); err != nil {
		t.Fatalf("SetAuthInfoHeader: %v", err)
	}
	return r.Header
}

// dialURL converts an httptest server URL to a ws:// URL.
func dialURL(serverURL, path string) string {
	return "ws" + strings.TrimPrefix(serverURL, "http") + path
}

func TestServeHTTP_EchoWithAuthAndPathParams(t *testing.T) {
	type captured struct {
		user   string
		id     string
		params map[string]string
	}
	got := make(chan captured, 1)

	m := newTestMux()
	m.registerHandler("/ws/echo/{id}", route.GET, func(ctx context.Context, wsc *WSContext) {
		defer wsc.Conn.Close()
		got <- captured{
			user:   wsc.AuthInfo.UserName,
			id:     wsc.PathParams["id"],
			params: wsc.PathParams,
		}
		mt, msg, err := wsc.Conn.ReadMessage()
		if err != nil {
			return
		}
		_ = wsc.Conn.WriteMessage(mt, msg)
	})

	srv := httptest.NewServer(m)
	defer srv.Close()

	info := &actx.AuthInfo{UserName: "alice", Realm: "test"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, _, err := websocket.Dial(ctx, dialURL(srv.URL, "/ws/echo/42"), &websocket.DialOptions{
		HTTPHeader: authHeader(t, info),
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.CloseNow()

	if err := c.Write(ctx, websocket.MessageText, []byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	mt, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if mt != websocket.MessageText || string(data) != "hello" {
		t.Fatalf("echo mismatch: type=%v data=%q", mt, data)
	}

	select {
	case cap := <-got:
		if cap.user != "alice" {
			t.Errorf("AuthInfo.UserName = %q, want alice", cap.user)
		}
		if cap.id != "42" {
			t.Errorf("PathParams[id] = %q, want 42", cap.id)
		}
		if len(cap.params) != 1 {
			t.Errorf("PathParams = %v, want single entry", cap.params)
		}
	case <-ctx.Done():
		t.Fatal("handler did not run")
	}
}

func TestServeHTTP_RejectsMissingAuth(t *testing.T) {
	m := newTestMux()
	m.registerHandler("/ws/x", route.GET, func(ctx context.Context, wsc *WSContext) {
		t.Error("handler must not run without auth")
	})

	srv := httptest.NewServer(m)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// No Auth-Info header: the upgrade must be rejected before it happens.
	c, resp, err := websocket.Dial(ctx, dialURL(srv.URL, "/ws/x"), nil)
	if err == nil {
		c.CloseNow()
		t.Fatal("Dial succeeded, want rejection")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %v, want 401", resp)
	}
}

func TestServeHTTP_NotFound(t *testing.T) {
	m := newTestMux()
	m.registerHandler("/ws/known", route.GET, func(ctx context.Context, wsc *WSContext) {})

	srv := httptest.NewServer(m)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Authenticated but unmatched path: expect 404, not an upgrade.
	c, resp, err := websocket.Dial(ctx, dialURL(srv.URL, "/ws/unknown"), &websocket.DialOptions{
		HTTPHeader: authHeader(t, &actx.AuthInfo{UserName: "bob"}),
	})
	if err == nil {
		c.CloseNow()
		t.Fatal("Dial succeeded, want 404")
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %v, want 404", resp)
	}
}

func TestServeHTTP_OriginCheckerRejects(t *testing.T) {
	m := newTestMux(WithOriginChecker(func(r *http.Request) bool {
		return r.Header.Get("Origin") == "https://allowed.example.com"
	}))
	m.registerHandler("/ws/o", route.GET, func(ctx context.Context, wsc *WSContext) {
		t.Error("handler must not run for rejected origin")
	})

	srv := httptest.NewServer(m)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h := authHeader(t, &actx.AuthInfo{UserName: "carol"})
	h.Set("Origin", "https://evil.example.com")
	c, resp, err := websocket.Dial(ctx, dialURL(srv.URL, "/ws/o"), &websocket.DialOptions{HTTPHeader: h})
	if err == nil {
		c.CloseNow()
		t.Fatal("Dial succeeded, want 403")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %v, want 403", resp)
	}
}

func TestServeHTTP_GracefulCloseWhenHandlerReturns(t *testing.T) {
	// The handler returns immediately and deliberately never calls
	// Conn.Close(): the mux is responsible for tearing the connection down
	// (via the lifecycle-cancellation watchdog and the trailing graceful
	// close), so the client must still observe a clean close frame.
	m := newTestMux(WithPingInterval(0))
	m.registerHandler("/ws/quick", route.GET, func(ctx context.Context, wsc *WSContext) {})

	srv := httptest.NewServer(m)
	defer srv.Close()

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, _, err := websocket.Dial(dialCtx, dialURL(srv.URL, "/ws/quick"), &websocket.DialOptions{
		HTTPHeader: authHeader(t, &actx.AuthInfo{UserName: "zoe"}),
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.CloseNow()

	// A read must fail with a websocket close status rather than hang or
	// return a raw connection-reset error.
	_, _, err = c.Read(dialCtx)
	if err == nil {
		t.Fatal("read succeeded, want close")
	}
	status := websocket.CloseStatus(err)
	if status != websocket.StatusNormalClosure && status != websocket.StatusGoingAway {
		t.Fatalf("close status = %v (err %v), want NormalClosure or GoingAway", status, err)
	}
}

func TestParseParamNames(t *testing.T) {
	cases := []struct {
		path string
		want []string
	}{
		{"/api/v1/ws/events/{eventId}", []string{"eventId"}},
		{"/a/{x}/b/{y}", []string{"x", "y"}},
		{"/static/path", nil},
		{"/files/{path...}", []string{"path"}},
		{"/exact/{$}", nil},
	}
	for _, tc := range cases {
		got := parseParamNames(tc.path)
		if len(got) != len(tc.want) {
			t.Errorf("parseParamNames(%q) = %v, want %v", tc.path, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parseParamNames(%q) = %v, want %v", tc.path, got, tc.want)
				break
			}
		}
	}
}
