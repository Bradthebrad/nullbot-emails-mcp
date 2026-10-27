package safe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Bradthebrad/tinychain/mcp"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testClient(t *testing.T) *Client {
	t.Helper()
	c, e := New(`[{"id":"work","service":"gmail","fields":{"access_token":"secret-token-123","unknown_password":"other-private-value"}}]`)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestConfiguration(t *testing.T) {
	for _, raw := range []string{`null`, `{}`, `[{"id":"../bad","service":"gmail"}]`, `[{"id":"x","service":"gmail"},{"id":"x","service":"gmail"}]`, `[{"id":"x","service":"gmail","fields":{"access_token":"secret\r\ninject"}}]`, strings.Repeat("x", 1024*1024+1)} {
		if _, e := New(raw); e == nil || strings.Contains(e.Error(), "secret") {
			t.Fatalf("unsafe config error: %v", e)
		}
	}
	for _, raw := range []string{"", "[]"} {
		c, e := New(raw)
		if e != nil || len(c.Accounts) != 0 {
			t.Fatal(e)
		}
	}
}
func TestSecretRedaction(t *testing.T) {
	c := testClient(t)
	c.Protect("local-http-token-12345678901234567890")
	v := map[string]any{"secret-token-123": []any{"prefix secret-token-123", "other-private-value", base64.StdEncoding.EncodeToString([]byte("secret-token-123")), "local-http-token-12345678901234567890"}}
	r, e := c.Result(v, nil)
	b, _ := json.Marshal(r)
	if e != nil || strings.Contains(string(b), "secret-token") || strings.Contains(string(b), "other-private") || strings.Contains(string(b), "local-http-token") {
		t.Fatalf("leak: %s %v", b, e)
	}
	r, _ = c.Result(nil, errors.New("secret-token-123"))
	if !r.IsError || strings.Contains(r.Content[0].Text, "secret-token") {
		t.Fatal(r)
	}
}
func TestRequestSafety(t *testing.T) {
	c := testClient(t)
	a := c.Accounts[0]
	calls := 0
	c.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Scheme != "https" || r.URL.Host != "gmail.googleapis.com" || r.Header.Get("Authorization") != "Bearer secret-token-123" {
			t.Fatal("unexpected destination/auth")
		}
		d, ok := r.Context().Deadline()
		if !ok || time.Until(d) > 21*time.Second {
			t.Fatal("missing timeout")
		}
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://evil.example/steal"}}, Body: io.NopCloser(strings.NewReader("secret-token-123 raw upstream failure")), Request: r}, nil
	})
	var out any
	e := c.Request(context.Background(), a, "gmail.googleapis.com", "GET", "/messages", nil, nil, "", &out)
	if e == nil || calls != 1 || strings.Contains(e.Error(), "secret-token") || strings.Contains(e.Error(), "raw upstream") {
		t.Fatalf("redirect/error leak: %v calls %d", e, calls)
	}
	for _, p := range []string{"/../x", "/x?y", "/x#y", "/x\\y"} {
		if c.Request(context.Background(), a, "gmail.googleapis.com", "GET", p, nil, nil, "", nil) == nil {
			t.Fatal("invalid path accepted")
		}
	}
	if c.Request(context.Background(), a, "evil.example", "GET", "/", nil, nil, "", nil) == nil || calls != 1 {
		t.Fatal("invalid host contacted")
	}
}
func TestResponseFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		status int
		fail   bool
	}{{"oversize", strings.Repeat("x", MaxResponse+1), 200, false}, {"badjson", "secret-token-123", 200, false}, {"empty", "", 200, false}, {"status", "secret-token-123", 403, false}, {"network", "", 200, true}} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t)
			c.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
				if tc.fail {
					return nil, errors.New("secret-token-123")
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
			})
			var out any
			e := c.Request(context.Background(), c.Accounts[0], "gmail.googleapis.com", "GET", "/", nil, nil, "", &out)
			if e == nil || strings.Contains(e.Error(), "secret-token") {
				t.Fatalf("unsafe failure %v", e)
			}
		})
	}
	c := testClient(t)
	r, _ := c.Result(strings.Repeat("x", MaxOutput+1), nil)
	if !r.IsError {
		t.Fatal("missing output cap")
	}
}
func TestWriteGateAndLimit(t *testing.T) {
	for _, allow := range []bool{false, true} {
		for _, v := range []any{nil, false, true, "true", float64(1)} {
			e := WriteAllowed(Account{AllowWrite: allow}, map[string]any{"confirmed": v})
			want := allow && v == true
			if (e == nil) != want {
				t.Fatalf("gate allow=%v confirm=%v", allow, v)
			}
		}
	}
	for _, v := range []any{float64(0), float64(26), float64(1.5), "5", nil} {
		if _, e := Limit(map[string]any{"limit": v}); e == nil {
			t.Fatal("invalid limit accepted")
		}
	}
}
func TestHTTPGuard(t *testing.T) {
	token := strings.Repeat("t", 32)
	called := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		_, e := io.ReadAll(r.Body)
		if e != nil {
			http.Error(w, "too large", 413)
			return
		}
		w.WriteHeader(204)
	})
	h := Guard(next, "127.0.0.1:8791", token)
	for _, tc := range []struct {
		host, auth, origin, body string
		code                     int
	}{{"127.0.0.1:8791", "", "", "", 401}, {"evil.example", "Bearer " + token, "", "", 403}, {"127.0.0.1:8791", "Bearer " + token, "https://evil.example", "", 403}, {"127.0.0.1:8791", "Bearer " + token, "", "", 204}, {"127.0.0.1:8791", "Bearer " + token, "", strings.Repeat("x", 65537), 413}} {
		r := httptest.NewRequest("POST", "http://"+tc.host+"/mcp", strings.NewReader(tc.body))
		r.Header.Set("Authorization", tc.auth)
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatalf("got %d want %d", w.Code, tc.code)
		}
	}
	if called != 2 {
		t.Fatal("unauthorized request reached handler")
	}
}
func TestUnsafeListenersRejected(t *testing.T) {
	s := mcp.NewServer("test")
	for _, tc := range []struct{ transport, addr, path, token string }{{"http", "0.0.0.0:8791", "/mcp", strings.Repeat("t", 32)}, {"http", "localhost:8791", "/mcp", strings.Repeat("t", 32)}, {"http", "127.0.0.1:8791", "/mcp", ""}, {"http", "127.0.0.1:8791", "/mcp?x", strings.Repeat("t", 32)}, {"sse", "127.0.0.1:8791", "/mcp", strings.Repeat("t", 32)}} {
		if Serve(context.Background(), s, tc.transport, tc.addr, tc.path, tc.token) == nil {
			t.Fatal("unsafe listener accepted")
		}
	}
}
