package safe

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bradthebrad/tinychain/mcp"
)

const MaxResponse = 256 * 1024
const MaxOutput = 64 * 1024

type Account struct {
	ID         string            `json:"id"`
	Service    string            `json:"service"`
	Label      string            `json:"label"`
	Fields     map[string]string `json:"fields"`
	AllowWrite bool              `json:"allow_write"`
}

type Client struct {
	Accounts []Account
	HTTP     *http.Client
	secrets  []string
}

// Parse never includes raw configuration or parser errors in errors.
func New(raw string) (*Client, error) {
	c := &Client{HTTP: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if strings.TrimSpace(raw) == "" {
		return c, nil
	}
	if len(raw) > 1024*1024 || !strings.HasPrefix(strings.TrimSpace(raw), "[") {
		return nil, errors.New("invalid account configuration")
	}
	if json.Unmarshal([]byte(raw), &c.Accounts) != nil || len(c.Accounts) > 100 {
		return nil, errors.New("invalid account configuration")
	}
	seen := map[string]bool{}
	for _, a := range c.Accounts {
		if !Identifier(a.ID, 128) || a.Service == "" || len(a.Label) > 256 || seen[a.ID] || len(a.Fields) > 32 {
			return nil, errors.New("invalid account configuration")
		}
		seen[a.ID] = true
		if a.Fields["account_sid"] != "" && a.Fields["auth_token"] != "" {
			c.Protect(base64.StdEncoding.EncodeToString([]byte(a.Fields["account_sid"] + ":" + a.Fields["auth_token"])))
		}
		for key, v := range a.Fields {
			if len(v) > 16384 || strings.ContainsAny(v, "\r\n\x00") {
				return nil, errors.New("invalid account configuration")
			}
			// Public routing fields must remain usable in results; redact all other fields conservatively.
			switch key {
			case "from", "phone_number_id", "api_version":
			default:
				c.Protect(v)
			}
		}
	}
	return c, nil
}

func Identifier(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '=') {
			return false
		}
	}
	return true
}
func (c *Client) Account(id string, services ...string) (Account, error) {
	for _, a := range c.Accounts {
		if a.ID == id {
			for _, s := range services {
				if a.Service == s {
					return a, nil
				}
			}
			return Account{}, errors.New("account service not supported by this server")
		}
	}
	return Account{}, errors.New("account not found")
}
func Require(a Account, keys ...string) error {
	for _, k := range keys {
		if strings.TrimSpace(a.Fields[k]) == "" {
			return errors.New("account is missing required credentials")
		}
	}
	return nil
}
func WriteAllowed(a Account, args map[string]any) error {
	confirmed, ok := args["confirmed"].(bool)
	if !a.AllowWrite || !ok || !confirmed {
		return errors.New("send denied: account allow_write and explicit confirmed=true are both required; ask the user before sending")
	}
	return nil
}

// Request accepts only a caller-selected, fixed HTTPS host. Redirects are always
// disabled, even with an injected test client. Provider bodies/errors are private.
func (c *Client) Request(ctx context.Context, a Account, host, method, path string, q url.Values, body io.Reader, contentType string, out any) error {
	if !allowedHost(a.Service, host) || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\?#\r\n") || strings.Contains(path, "..") {
		return errors.New("invalid provider endpoint")
	}
	u := url.URL{Scheme: "https", Host: host, Path: path, RawQuery: q.Encode()}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return errors.New("invalid provider request")
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if a.Service == "twilio" {
		req.SetBasicAuth(a.Fields["account_sid"], a.Fields["auth_token"])
	} else {
		req.Header.Set("Authorization", "Bearer "+a.Fields["access_token"])
	}
	if a.Service == "outlook" {
		req.Header.Set("Prefer", `outlook.body-content-type="text"`)
	}
	client := *c.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 20 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("provider request failed (details withheld); send outcome may be unknown; do not retry automatically")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("provider returned HTTP %d (details withheld)", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if err != nil {
		return errors.New("provider response could not be read; send outcome may be unknown")
	}
	if len(b) > MaxResponse {
		return errors.New("provider response exceeds size limit; send outcome may be unknown")
	}
	if out != nil {
		if json.Unmarshal(b, out) != nil {
			return errors.New("invalid provider response; send outcome may be unknown")
		}
	}
	return nil
}
func allowedHost(service, host string) bool {
	switch service {
	case "gmail":
		return host == "gmail.googleapis.com"
	case "outlook":
		return host == "graph.microsoft.com"
	case "twilio":
		return host == "api.twilio.com"
	case "whatsapp":
		return host == "graph.facebook.com"
	}
	return false
}

// Result recursively redacts configured secrets before serializing; never emit raw provider JSON.
func (c *Client) Result(v any, err error) (mcp.ToolResult, error) {
	if err != nil {
		r := mcp.Text(c.redact(err.Error()))
		r.IsError = true
		return r, nil
	}
	b, e := json.Marshal(v)
	if e != nil {
		r := mcp.Text("result encoding failed")
		r.IsError = true
		return r, nil
	}
	var decoded any
	if json.Unmarshal(b, &decoded) != nil {
		return mcp.ToolResult{}, errors.New("result encoding failed")
	}
	b, e = json.Marshal(c.scrub(decoded))
	if e != nil || len(b) > MaxOutput {
		r := mcp.Text("result exceeds output limit; request fewer items or a smaller message")
		r.IsError = true
		return r, nil
	}
	return mcp.Text(string(b)), nil
}
func (c *Client) redact(s string) string {
	for _, v := range c.secrets {
		s = strings.ReplaceAll(s, v, "[REDACTED]")
	}
	return s
}
func (c *Client) scrub(v any) any {
	switch x := v.(type) {
	case string:
		return c.redact(x)
	case []any:
		for i := range x {
			x[i] = c.scrub(x[i])
		}
		return x
	case map[string]any:
		y := map[string]any{}
		for k, z := range x {
			y[c.redact(k)] = c.scrub(z)
		}
		return y
	}
	return v
}
func String(args map[string]any, key string, max int, required bool) (string, error) {
	v, ok := args[key]
	if !ok && !required {
		return "", nil
	}
	s, ok := v.(string)
	if !ok || len(s) > max || strings.ContainsRune(s, 0) || (required && strings.TrimSpace(s) == "") {
		return "", fmt.Errorf("invalid %s", key)
	}
	return s, nil
}
func Limit(args map[string]any) (int, error) {
	v, ok := args["limit"]
	if !ok {
		return 10, nil
	}
	n, ok := v.(float64)
	if !ok || n < 1 || n > 25 || n != float64(int(n)) {
		return 0, errors.New("limit must be an integer from 1 to 25")
	}
	return int(n), nil
}
func Validate(args map[string]any, properties map[string]any) error {
	for k := range args {
		if _, ok := properties[k]; !ok {
			return errors.New("unknown argument")
		}
	}
	return nil
}
func Schema(properties map[string]any, required ...string) map[string]any {
	return map[string]any{"type": "object", "properties": properties, "required": append([]string{}, required...), "additionalProperties": false}
}
func Prop(kind, description string) map[string]any {
	return map[string]any{"type": kind, "description": description}
}

// Serve preserves tinychain protocol handling while securing its optional local
// HTTP transport. Network transport requires a separate bearer token, no Origins,
// numeric loopback binding, bounded requests, and server timeouts.
func Serve(ctx context.Context, s *mcp.Server, transport, addr, path, token string) error {
	if transport == "stdio" {
		return s.Run(ctx, mcp.WithTransport("stdio"))
	}
	h, port, e := net.SplitHostPort(addr)
	ip := net.ParseIP(h)
	pn, pe := strconv.Atoi(port)
	if e != nil || ip == nil || !ip.IsLoopback() || pe != nil || pn < 1 || pn > 65535 {
		return errors.New("network transport requires a numeric loopback address and valid port")
	}
	if len(token) < 32 || strings.ContainsAny(token, "\r\n\x00") {
		return errors.New("network transport requires NULLBOT_MCP_AUTH_TOKEN of at least 32 characters")
	}
	if !validPath(path) {
		return errors.New("invalid transport path")
	}
	var handler http.Handler
	switch transport {
	case "http", "streamable-http":
		handler = s.Handler(path)
	default:
		return errors.New("unsupported transport")
	}
	server := &http.Server{Addr: addr, Handler: Guard(handler, addr, token), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(c)
		case <-done:
		}
	}()
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return errors.New("local MCP listener failed")
	}
	return nil
}
func validPath(p string) bool {
	if !strings.HasPrefix(p, "/") || len(p) > 128 {
		return false
	}
	for _, r := range p {
		if !(r == '/' || r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
func Guard(next http.Handler, addr, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != addr || len(r.Header.Values("Origin")) != 0 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// Protect prevents configured values and common wire encodings from appearing in results.
func (c *Client) Protect(value string) {
	if value == "" {
		return
	}
	c.secrets = append(c.secrets, value, url.QueryEscape(value), base64.StdEncoding.EncodeToString([]byte(value)), base64.RawURLEncoding.EncodeToString([]byte(value)))
	sort.Slice(c.secrets, func(i, j int) bool { return len(c.secrets[i]) > len(c.secrets[j]) })
}
