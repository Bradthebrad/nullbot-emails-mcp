package emails

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Bradthebrad/tinychain/mcp"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func service(t *testing.T, provider string, allow bool, fn roundTrip) *Service {
	t.Helper()
	raw, _ := json.Marshal([]any{map[string]any{"id": "work", "service": provider, "allow_write": allow, "fields": map[string]string{"access_token": "test-private-token"}}})
	s, e := New(string(raw))
	if e != nil {
		t.Fatal(e)
	}
	s.Client.HTTP.Transport = fn
	return s
}
func call(t *testing.T, s *Service, name string, args map[string]any) mcp.ToolResult {
	t.Helper()
	for _, tool := range s.Tools() {
		if tool.Name == name {
			r, e := tool.Handler(context.Background(), args)
			if e != nil {
				t.Fatal(e)
			}
			return r
		}
	}
	t.Fatal("missing tool", name)
	return mcp.ToolResult{}
}
func reply(r *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}
}
func TestNoNetworkForStatusAndRejectedInputs(t *testing.T) {
	for _, provider := range []string{"gmail", "outlook", "yahoo", "icloud_mail"} {
		s := service(t, provider, true, func(*http.Request) (*http.Response, error) { t.Fatal("unexpected network"); return nil, nil })
		if r := call(t, s, "email_accounts", nil); r.IsError || strings.Contains(r.Content[0].Text, "test-private-token") {
			t.Fatal(r)
		}
		for _, tc := range []struct {
			name string
			args map[string]any
		}{{"email_list", map[string]any{"account_id": "work", "limit": 1.5}}, {"email_list", map[string]any{"account_id": "work", "extra": true}}, {"email_get", map[string]any{"account_id": "work", "message_id": "../escape"}}, {"email_send", map[string]any{"account_id": "work", "to": "x@example.com", "subject": "Hi", "body": "hello", "confirmed": "true"}}, {"email_send", map[string]any{"account_id": "work", "to": "x@example.com", "subject": "Hi\r\nBcc: victim@example.com", "body": "hello", "confirmed": true}}, {"email_send", map[string]any{"account_id": "work", "to": "x@example.com, y@example.com", "subject": "Hi", "body": "hello", "confirmed": true}}} {
			if r := call(t, s, tc.name, tc.args); !r.IsError {
				t.Fatalf("accepted invalid %s: %v", tc.name, r)
			}
		}
	}
	s := service(t, "gmail", false, func(*http.Request) (*http.Response, error) { t.Fatal("write gate bypass"); return nil, nil })
	if r := call(t, s, "email_send", map[string]any{"account_id": "work", "to": "x@example.com", "subject": "Hi", "body": "hello", "confirmed": true}); !r.IsError {
		t.Fatal(r)
	}
}
func TestGmailListAndGet(t *testing.T) {
	calls := 0
	s := service(t, "gmail", false, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Host != "gmail.googleapis.com" {
			t.Fatal(r.URL)
		}
		if strings.HasSuffix(r.URL.Path, "/messages") {
			if r.URL.Query().Get("maxResults") != "1" || r.URL.Query().Get("q") != "is:unread" {
				t.Fatal(r.URL)
			}
			return reply(r, `{"messages":[{"id":"a"},{"id":"b"}],"nextPageToken":"private-next-token"}`), nil
		}
		if r.URL.Path != "/gmail/v1/users/me/messages/a" {
			t.Fatal(r.URL)
		}
		return reply(r, `{"id":"a","payload":{"mimeType":"multipart/mixed","headers":[{"name":"Subject","value":"Hi"}],"parts":[{"mimeType":"text/plain","body":{"data":"aGVsbG8"}},{"mimeType":"text/html","body":{"data":"PGI-aGk8L2I-"}},{"filename":"x.txt","body":{"attachmentId":"secret-attachment"}}]}}`), nil
	})
	r := call(t, s, "email_list", map[string]any{"account_id": "work", "limit": float64(1), "query": "is:unread"})
	if r.IsError || strings.Contains(r.Content[0].Text, `"id":"b"`) || strings.Contains(r.Content[0].Text, "private-next-token") {
		t.Fatal(r)
	}
	r = call(t, s, "email_get", map[string]any{"account_id": "work", "message_id": "a"})
	if r.IsError || !strings.Contains(r.Content[0].Text, `"text":"hello"`) || !strings.Contains(r.Content[0].Text, `"attachment_count":1`) || strings.Contains(r.Content[0].Text, "secret-attachment") {
		t.Fatal(r)
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}
func TestMockSendPayloads(t *testing.T) {
	for _, provider := range []string{"gmail", "outlook"} {
		t.Run(provider, func(t *testing.T) {
			calls := 0
			s := service(t, provider, true, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer test-private-token" {
					t.Fatal("bad request")
				}
				b, _ := io.ReadAll(r.Body)
				var payload map[string]any
				if json.Unmarshal(b, &payload) != nil {
					t.Fatal("bad JSON")
				}
				if provider == "gmail" {
					if r.URL.Path != "/gmail/v1/users/me/messages/send" {
						t.Fatal(r.URL)
					}
					raw, e := base64.RawURLEncoding.DecodeString(payload["raw"].(string))
					if e != nil || !strings.Contains(string(raw), "To: x@example.com\r\n") || !strings.Contains(string(raw), "Content-Transfer-Encoding: base64") {
						t.Fatal(string(raw), e)
					}
					return reply(r, `{"id":"sent"}`), nil
				}
				if r.URL.Host != "graph.microsoft.com" || r.URL.Path != "/v1.0/me/sendMail" || !strings.Contains(string(b), `"contentType":"Text"`) {
					t.Fatal(r.URL, string(b))
				}
				return &http.Response{StatusCode: 202, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
			})
			r := call(t, s, "email_send", map[string]any{"account_id": "work", "to": "x@example.com", "subject": "Hi", "body": "hello", "confirmed": true})
			if r.IsError || calls != 1 || !strings.Contains(r.Content[0].Text, `"delivery_confirmed":false`) {
				t.Fatal(r, calls)
			}
		})
	}
}
func TestOutlookReadContract(t *testing.T) {
	s := service(t, "outlook", false, func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Prefer") != `outlook.body-content-type="text"` || r.URL.Host != "graph.microsoft.com" {
			t.Fatal("missing text preference")
		}
		return reply(r, `{"id":"abc=","body":{"contentType":"text","content":"hello"}}`), nil
	})
	r := call(t, s, "email_get", map[string]any{"account_id": "work", "message_id": "abc="})
	if r.IsError || !strings.Contains(r.Content[0].Text, "hello") {
		t.Fatal(r)
	}
}
