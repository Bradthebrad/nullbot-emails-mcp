package emails

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// In-memory scripted sockets: no listeners, DNS, external accounts or real sends.
type mailMock struct {
	input    *strings.Reader
	output   bytes.Buffer
	deadline time.Time
	closed   bool
}

func (m *mailMock) Read(p []byte) (int, error)         { return m.input.Read(p) }
func (m *mailMock) Write(p []byte) (int, error)        { return m.output.Write(p) }
func (m *mailMock) Close() error                       { m.closed = true; return nil }
func (m *mailMock) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mailMock) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mailMock) SetDeadline(t time.Time) error      { m.deadline = t; return nil }
func (m *mailMock) SetReadDeadline(t time.Time) error  { return m.SetDeadline(t) }
func (m *mailMock) SetWriteDeadline(t time.Time) error { return m.SetDeadline(t) }

func imapService(t *testing.T, allow bool) *Service {
	t.Helper()
	raw, _ := json.Marshal([]any{map[string]any{"id": "work", "service": "gmail_imap", "allow_write": allow, "fields": map[string]string{"email": "sender@example.com", "app_password": "abcd efgh ijkl mnop", "host": "evil.invalid", "proxy": "evil.invalid"}}})
	s, e := New(string(raw))
	if e != nil {
		t.Fatal(e)
	}
	s.mailDial = func(context.Context, string, *tls.Config) (net.Conn, error) {
		t.Fatal("unexpected network")
		return nil, errors.New("unexpected")
	}
	return s
}

func mockMail(t *testing.T, s *Service, transcript string, smtp bool) *mailMock {
	t.Helper()
	m := &mailMock{input: strings.NewReader(transcript)}
	calls := 0
	s.mailDial = func(ctx context.Context, address string, config *tls.Config) (net.Conn, error) {
		calls++
		if calls > 1 {
			t.Fatal("automatic retry")
		}
		host, endpoint := "imap.gmail.com", "imap.gmail.com:993"
		if smtp {
			host, endpoint = "smtp.gmail.com", "smtp.gmail.com:465"
		}
		if address != endpoint || config.ServerName != host || config.InsecureSkipVerify || config.MinVersion != tls.VersionTLS12 || config.RootCAs != nil || config.VerifyConnection != nil || config.VerifyPeerCertificate != nil {
			t.Fatal("unsafe endpoint or TLS configuration")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > mailTimeout || time.Until(deadline) <= 0 {
			t.Fatal("missing bounded deadline")
		}
		return m, nil
	}
	return m
}

func inboxTranscript(count int, validity uint32) string {
	return fmt.Sprintf("* OK ready\r\nA001 OK logged in\r\n* %d EXISTS\r\n* OK [UIDVALIDITY %d] stable\r\nA002 OK [READ-ONLY] INBOX\r\n", count, validity)
}

func TestIMAPStatusAndRequiredCredentials(t *testing.T) {
	s := imapService(t, true)
	r := call(t, s, "email_accounts", nil)
	if r.IsError || !strings.Contains(r.Content[0].Text, `"configured":true`) || !strings.Contains(r.Content[0].Text, `"can_send":true`) || strings.Contains(r.Content[0].Text, "sender@example.com") || strings.Contains(r.Content[0].Text, "abcd") {
		t.Fatal(r)
	}
	for _, fields := range []map[string]string{
		{}, {"email": "sender@example.com"}, {"app_password": "password"},
		{"email": "Name <sender@example.com>", "app_password": "password"},
		{"email": "sender@example.com", "app_password": "    "},
		{"email": "sender@example.com", "app_password": "x\tbad"},
		{"email": "sender@example.com", "app_password": strings.Repeat("x", 257)},
	} {
		s.Client.Accounts[0].Fields = fields
		r = call(t, s, "email_accounts", nil)
		if r.IsError || !strings.Contains(r.Content[0].Text, `"configured":false`) {
			t.Fatal(r)
		}
		if r = call(t, s, "email_list", map[string]any{"account_id": "work"}); !r.IsError {
			t.Fatal(r)
		}
	}
	for _, value := range []string{"x\r\nA1 NOOP", "x\x00", "x\n"} {
		raw, _ := json.Marshal([]any{map[string]any{"id": "work", "service": "gmail_imap", "fields": map[string]string{"email": "sender@example.com", "app_password": value}}})
		if _, e := New(string(raw)); e == nil {
			t.Fatal("accepted control in credential")
		}
	}
}

func TestIMAPRejectInputsAndSendGatesBeforeDial(t *testing.T) {
	s := imapService(t, true)
	for _, args := range []map[string]any{
		{"account_id": "work", "query": "is:unread"},
		{"account_id": "work", "query": "\r\nA1 STORE 1 +FLAGS (\\Seen)"},
		{"account_id": "work", "limit": float64(0)},
		{"account_id": "work", "limit": float64(26)},
		{"account_id": "work", "limit": 1.5},
		{"account_id": "work", "mailbox": "Trash"},
		{"account_id": "work", "host": "evil.invalid"},
	} {
		if r := call(t, s, "email_list", args); !r.IsError {
			t.Fatal(r)
		}
	}
	for _, id := range []string{"1", "gmailimap_0_1", "gmailimap_1_0", "gmailimap_01_2", "gmailimap_1_4294967296", "gmailimap_1_1_2", "gmailimap_1_1\r\nNOOP", "gmailimap_1_1:*", "gmailimap_-1_1"} {
		if r := call(t, s, "email_get", map[string]any{"account_id": "work", "message_id": id}); !r.IsError {
			t.Fatal(r)
		}
	}
	for _, allow := range []bool{false, true} {
		for _, confirmed := range []any{nil, false, "true", true} {
			if allow && confirmed == true {
				continue
			}
			s.Client.Accounts[0].AllowWrite = allow
			if r := call(t, s, "email_send", map[string]any{"account_id": "work", "to": "to@example.com", "subject": "Hello", "body": "body", "confirmed": confirmed}); !r.IsError {
				t.Fatal(r)
			}
		}
	}
	s.Client.Accounts[0].AllowWrite = true
	for _, pair := range [][2]string{{"to", "x@example.com\r\nRCPT TO:<victim@example.com>"}, {"to", "x@example.com,y@example.com"}, {"to", "Name <x@example.com>"}, {"subject", "Hi\r\nBcc: x@example.com"}, {"subject", strings.Repeat("x", 999)}, {"body", strings.Repeat("x", 24001)}} {
		args := map[string]any{"account_id": "work", "to": "to@example.com", "subject": "Hello", "body": "body", "confirmed": true}
		args[pair[0]] = pair[1]
		if r := call(t, s, "email_send", args); !r.IsError {
			t.Fatal(r)
		}
	}
}

func TestIMAPListBoundedNewestUIDs(t *testing.T) {
	s := imapService(t, false)
	m := mockMail(t, s, inboxTranscript(1000000, 44)+"* 999999 FETCH (UID 1234)\r\n* 1000000 FETCH (UID 9999)\r\nA003 OK fetched\r\n", false)
	r := call(t, s, "email_list", map[string]any{"account_id": "work", "limit": float64(2)})
	if r.IsError || !strings.Contains(r.Content[0].Text, `"has_more":true`) || !strings.Contains(r.Content[0].Text, `"messages":[{"id":"gmailimap_44_9999"},{"id":"gmailimap_44_1234"}]`) {
		t.Fatal(r)
	}
	want := "A001 LOGIN \"sender@example.com\" \"abcdefghijklmnop\"\r\nA002 EXAMINE INBOX\r\nA003 FETCH 999999:1000000 (UID)\r\n"
	if m.output.String() != want || !m.closed || m.deadline.IsZero() {
		t.Fatal("unexpected IMAP command contract or lifecycle")
	}
	s = imapService(t, false)
	m = mockMail(t, s, inboxTranscript(0, 44), false)
	r = call(t, s, "email_list", map[string]any{"account_id": "work"})
	if r.IsError || !strings.Contains(r.Content[0].Text, `"messages":[]`) || strings.Contains(m.output.String(), "FETCH") {
		t.Fatal(r)
	}
}

func TestIMAPGetPEEKAndUIDValidity(t *testing.T) {
	raw := "From: friend@example.com\r\nSubject: =?UTF-8?B?SGVsbG8=?=\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\naGk="
	for _, uidAfterBody := range []bool{false, true} {
		s := imapService(t, false)
		prefix := fmt.Sprintf("* 7 FETCH (UID 55 RFC822.SIZE %d BODY[]<0> {%d}\r\n", len(raw), len(raw))
		tail := ")\r\n"
		if uidAfterBody {
			prefix = fmt.Sprintf("* 7 FETCH (BODY[]<0> {%d}\r\n", len(raw))
			tail = fmt.Sprintf(" UID 55 RFC822.SIZE %d)\r\n", len(raw))
		}
		m := mockMail(t, s, inboxTranscript(7, 44)+prefix+raw+tail+"A003 OK fetched\r\n", false)
		r := call(t, s, "email_get", map[string]any{"account_id": "work", "message_id": "gmailimap_44_55"})
		if r.IsError || !strings.Contains(r.Content[0].Text, `"text":"hi"`) || !strings.Contains(r.Content[0].Text, `"subject":"Hello"`) {
			t.Fatal(r)
		}
		if !strings.Contains(m.output.String(), "UID FETCH 55 (UID RFC822.SIZE BODY.PEEK[]<0.262145>)\r\n") || strings.Contains(m.output.String(), "SELECT") || strings.Contains(m.output.String(), "STORE") {
			t.Fatal("mutating read or missing bound")
		}
	}
	s := imapService(t, false)
	m := mockMail(t, s, inboxTranscript(7, 45), false)
	if r := call(t, s, "email_get", map[string]any{"account_id": "work", "message_id": "gmailimap_44_55"}); !r.IsError || !strings.Contains(r.Content[0].Text, "UIDVALIDITY changed") {
		t.Fatal(r)
	}
	if strings.Contains(m.output.String(), "FETCH") {
		t.Fatal("stale ID used")
	}
	s = imapService(t, false)
	mockMail(t, s, inboxTranscript(7, 44)+"A003 OK absent\r\n", false)
	if r := call(t, s, "email_get", map[string]any{"account_id": "work", "message_id": "gmailimap_44_55"}); !r.IsError {
		t.Fatal(r)
	}
}

func TestIMAPProtocolFailuresAndBounds(t *testing.T) {
	for name, response := range map[string]string{
		"bad greeting":        "* PREAUTH private credential\r\n",
		"auth failure":        "* OK ready\r\nA001 NO abcdefghijklmnop sender@example.com\r\n",
		"continuation":        "* OK ready\r\n+ send more secrets\r\n",
		"missing validity":    "* OK ready\r\nA001 OK login\r\n* 1 EXISTS\r\nA002 OK [READ-ONLY] done\r\n",
		"not read only":       "* OK ready\r\nA001 OK login\r\n* OK [UIDVALIDITY 44] valid\r\nA002 OK [READ-WRITE] done\r\n",
		"long line":           strings.Repeat("x", mailLineLimit+1) + "\r\n",
		"too many lines":      "* OK ready\r\n" + strings.Repeat("* OK info\r\n", mailLineCount+1),
		"too many bytes":      "* OK ready\r\n" + strings.Repeat("* OK "+strings.Repeat("x", 8000)+"\r\n", 50),
		"bye":                 inboxTranscript(2, 44) + "* BYE private\r\n",
		"too many results":    inboxTranscript(2, 44) + "* 1 FETCH (UID 1)\r\n* 2 FETCH (UID 2)\r\nA003 OK done\r\n",
		"duplicate uid":       inboxTranscript(1, 44) + "* 1 FETCH (UID 1 UID 2)\r\nA003 OK done\r\n",
		"bad uid":             inboxTranscript(1, 44) + "* 1 FETCH (UID 0)\r\nA003 OK done\r\n",
		"unsolicited literal": inboxTranscript(1, 44) + "* OK {99999999}\r\n",
		"expunge race":        inboxTranscript(1, 44) + "* 1 EXPUNGE\r\nA003 OK done\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			s := imapService(t, false)
			mockMail(t, s, response, false)
			r := call(t, s, "email_list", map[string]any{"account_id": "work", "limit": float64(1)})
			if !r.IsError || strings.Contains(r.Content[0].Text, "abcdefghijklmnop") || strings.Contains(r.Content[0].Text, "sender@example.com") {
				t.Fatal(r)
			}
		})
	}
	for _, fetch := range []string{
		"* 1 FETCH (UID 55 RFC822.SIZE 262145 BODY[]<0> {262145}\r\n",
		"* 1 FETCH (UID 55 RFC822.SIZE 9 BODY[]<0> {3}\r\nabc)\r\nA003 OK done\r\n",
		"* 1 FETCH (UID 55 RFC822.SIZE 9 BODY[]<0> {9}\r\nabc",
		"* 1 FETCH (UID 55 BODY[]<0> {3}\r\nabc)\r\nA003 OK done\r\n",
		"* 1 FETCH (UID 55 RFC822.SIZE 3 BODY[]<0> {3}\r\nabc UID 66)\r\nA003 OK done\r\n",
	} {
		s := imapService(t, false)
		mockMail(t, s, inboxTranscript(1, 44)+fetch, false)
		if r := call(t, s, "email_get", map[string]any{"account_id": "work", "message_id": "gmailimap_44_55"}); !r.IsError {
			t.Fatal(r)
		}
	}
}

func TestIMAPQuotedCredentialsAndRedaction(t *testing.T) {
	password := `abc"def\ghi`
	if got := imapQuote(password); got != `"abc\"def\\ghi"` {
		t.Fatalf("bad quoting: %q", got)
	}
	s := imapService(t, false)
	auth := base64.StdEncoding.EncodeToString([]byte("\x00sender@example.com\x00abcdefghijklmnop"))
	r, e := s.Client.Result(map[string]string{"text": "abcd efgh ijkl mnop abcdefghijklmnop " + auth + " sender@example.com"}, nil)
	if e != nil || strings.Contains(r.Content[0].Text, "abcd") || strings.Contains(r.Content[0].Text, auth) || strings.Contains(r.Content[0].Text, "sender@example.com") {
		t.Fatal(r, e)
	}
}

func TestMIMEExtractionAndBounds(t *testing.T) {
	raw := "Subject: hello\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n" +
		"--x\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nhello=20world\r\n" +
		"--x\r\nContent-Type: text/html\r\n\r\n<b>not output</b>\r\n" +
		"--x\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=private.txt\r\n\r\nattachment secret\r\n" +
		"--x\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\nomit charset\r\n--x--\r\n"
	v, e := extractIMAPMessage("gmailimap_1_1", []byte(raw))
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(v)
	if !strings.Contains(string(b), `"text":"hello world"`) || !strings.Contains(string(b), `"attachment_count":1`) || !strings.Contains(string(b), `"omitted_parts":2`) || strings.Contains(string(b), "attachment secret") || strings.Contains(string(b), "<b>") {
		t.Fatal(string(b))
	}
	for _, raw := range []string{
		"Subject: " + strings.Repeat("x", mimeHeaderLimit) + "\r\n\r\nbody",
		"Subject: hi\r\n\r\n" + strings.Repeat("x", mimeTextLimit+1),
		"Content-Type: multipart/mixed\r\n\r\nmissing boundary",
		"Content-Transfer-Encoding: base64\r\n\r\n!!!!",
		"Content-Type: text/plain; charset=utf-8\r\n\r\n\xff",
		"Subject: hi\r\n\r\n" + strings.Repeat("x", mailMessageLimit),
	} {
		if _, e := extractIMAPMessage("gmailimap_1_1", []byte(raw)); e == nil {
			t.Fatal("accepted oversized/malformed MIME")
		}
	}
	parts := "Content-Type: multipart/mixed; boundary=x\r\n\r\n" + strings.Repeat("--x\r\nContent-Type: text/plain\r\n\r\nx\r\n", mimePartLimit+1) + "--x--\r\n"
	if _, e := extractIMAPMessage("id", []byte(parts)); e == nil {
		t.Fatal("unbounded part count")
	}
	nested := "Content-Type: text/plain\r\n\r\ntext"
	for i := 0; i < mimeDepthLimit+2; i++ {
		boundary := fmt.Sprintf("b%d", i)
		nested = "Content-Type: multipart/mixed; boundary=" + boundary + "\r\n\r\n--" + boundary + "\r\n" + nested + "\r\n--" + boundary + "--\r\n"
	}
	if _, e := extractIMAPMessage("id", []byte(nested)); e == nil {
		t.Fatal("unbounded MIME depth")
	}
	// Tool serialization still fails closed on JSON expansion beyond 64 KiB.
	s := imapService(t, false)
	v, e = extractIMAPMessage("id", []byte("Subject: hi\r\n\r\n"+strings.Repeat("\x01", mimeTextLimit)))
	if e != nil {
		t.Fatal(e)
	}
	r, _ := s.Client.Result(v, nil)
	if !r.IsError {
		t.Fatal("unbounded output")
	}
}

func TestSMTPFixedTLSAuthAndPlainTextSend(t *testing.T) {
	s := imapService(t, true)
	m := mockMail(t, s, "220 ready\r\n250-server\r\n250 AUTH PLAIN LOGIN\r\n235 authenticated\r\n250 sender\r\n250 recipient\r\n354 data\r\n250 queued\r\n", true)
	body := "hello\r\n.\r\nRCPT TO:<not-a-recipient@example.com>"
	r := call(t, s, "email_send", map[string]any{"account_id": "work", "to": "to@example.com", "subject": "Hello 世界", "body": body, "confirmed": true})
	if r.IsError || !strings.Contains(r.Content[0].Text, `"accepted":true`) || !strings.Contains(r.Content[0].Text, `"delivery_confirmed":false`) || !m.closed {
		t.Fatal(r)
	}
	auth := base64.StdEncoding.EncodeToString([]byte("\x00sender@example.com\x00abcdefghijklmnop"))
	prefix := "EHLO localhost\r\nAUTH PLAIN " + auth + "\r\nMAIL FROM:<sender@example.com>\r\nRCPT TO:<to@example.com>\r\nDATA\r\n"
	if !strings.HasPrefix(m.output.String(), prefix) || !strings.HasSuffix(m.output.String(), "\r\n.\r\n") || strings.Contains(m.output.String(), "RCPT TO:<not-a-recipient") {
		t.Fatal("unsafe SMTP wire contract")
	}
	raw := strings.TrimSuffix(strings.TrimPrefix(m.output.String(), prefix), ".\r\n")
	v, e := extractIMAPMessage("id", []byte(raw))
	if e != nil {
		t.Fatal(e)
	}
	message := v.(map[string]any)
	if message["text"] != body || message["headers"].(map[string]string)["subject"] != "Hello 世界" {
		t.Fatal(message)
	}
	long := smtpMessage("sender@example.com", "to@example.com", strings.Repeat("界", 330), strings.Repeat("x", 24000))
	for _, line := range strings.Split(long, "\r\n") {
		if len(line) > 998 {
			t.Fatal("unbounded SMTP line")
		}
	}
}

func TestSMTPRejectRepliesAndNeverLeak(t *testing.T) {
	for _, reply := range []string{
		"535 abcdefghijklmnop sender@example.com\r\n",
		"220 " + strings.Repeat("x", mailLineLimit) + "\r\n",
		"220 ready\r\n250 AUTH LOGIN\r\n",
		"220 ready\r\n250 AUTH PLAIN\r\n535 abcdefghijklmnop\r\n",
		"220 ready\r\n250 AUTH PLAIN\r\n235 ok\r\n250 ok\r\n550 bad recipient\r\n",
		"220 ready\r\n250 AUTH PLAIN\r\n235 ok\r\n250 ok\r\n250 ok\r\n354 data\r\n",
		"220 ready\r\n" + strings.Repeat("250-more\r\n", 65),
	} {
		s := imapService(t, true)
		mockMail(t, s, reply, true)
		r := call(t, s, "email_send", map[string]any{"account_id": "work", "to": "to@example.com", "subject": "Hi", "body": "body", "confirmed": true})
		if !r.IsError || !strings.Contains(r.Content[0].Text, "do not retry automatically") || strings.Contains(r.Content[0].Text, "abcdefghijklmnop") || strings.Contains(r.Content[0].Text, "sender@example.com") {
			t.Fatal(r)
		}
	}
}

func TestMailCancellationAndParentDeadline(t *testing.T) {
	s := imapService(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e := s.openMail(ctx, false); e == nil {
		t.Fatal("canceled context dialed")
	}
	// net.Pipe blocks reads and is released by the cancellation watcher.
	client, server := net.Pipe()
	defer server.Close()
	s.mailDial = func(context.Context, string, *tls.Config) (net.Conn, error) { return client, nil }
	ctx, cancel = context.WithCancel(context.Background())
	conn, cleanup, e := s.openMail(ctx, false)
	if e != nil {
		t.Fatal(e)
	}
	defer cleanup()
	done := make(chan error, 1)
	go func() { var b [1]byte; _, e := conn.Read(b[:]); done <- e }()
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("read unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt blocked read")
	}
	s = imapService(t, false)
	m := mockMail(t, s, "", false)
	deadline := time.Now().Add(time.Second)
	ctx, cancel = context.WithDeadline(context.Background(), deadline)
	defer cancel()
	_, cleanup, e = s.openMail(ctx, false)
	if e != nil {
		t.Fatal(e)
	}
	if !m.deadline.Equal(deadline) {
		cleanup()
		t.Fatal("parent deadline not honored")
	}
	cleanup()
}

// Exercise real crypto/tls handshakes over net.Pipe. Trust is added only to the
// local test copy; production uses the system roots and cannot override TLS.
func TestMailTLSVerificationOffline(t *testing.T) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "imap.gmail.com"}, DNSNames: []string{"imap.gmail.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name    string
		trusted bool
		host    string
		version uint16
		wantOK  bool
	}{
		{"valid TLS12", true, "imap.gmail.com", tls.VersionTLS12, true},
		{"valid TLS13", true, "imap.gmail.com", tls.VersionTLS13, true},
		{"untrusted", false, "imap.gmail.com", tls.VersionTLS12, false},
		{"wrong hostname", true, "smtp.gmail.com", tls.VersionTLS12, false},
		{"obsolete TLS", true, "imap.gmail.com", tls.VersionTLS11, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			_ = left.SetDeadline(time.Now().Add(2 * time.Second))
			_ = right.SetDeadline(time.Now().Add(2 * time.Second))
			server := tls.Server(right, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS10, MaxVersion: tc.version})
			config := gmailTLS(tc.host)
			config.RootCAs = x509.NewCertPool()
			if tc.trusted {
				config.RootCAs.AddCert(cert)
			}
			client := tls.Client(left, config)
			var wg sync.WaitGroup
			wg.Add(1)
			go func() { defer wg.Done(); _ = server.Handshake() }()
			e := client.Handshake()
			if (e == nil) != tc.wantOK {
				t.Fatalf("TLS acceptance=%v, want %v", e == nil, tc.wantOK)
			}
			left.Close()
			right.Close()
			wg.Wait()
		})
	}
}

func TestMailDialErrorsSanitized(t *testing.T) {
	s := imapService(t, false)
	s.mailDial = func(context.Context, string, *tls.Config) (net.Conn, error) {
		return nil, fmt.Errorf("private address and password %s", "abcdefghijklmnop")
	}
	if r := call(t, s, "email_list", map[string]any{"account_id": "work"}); !r.IsError || strings.Contains(r.Content[0].Text, "private address") || strings.Contains(r.Content[0].Text, "abcdefghijklmnop") {
		t.Fatal(r)
	}
	// Immediate EOF is a protocol failure, never a successful empty response.
	m := &mailMock{input: strings.NewReader("")}
	if _, e := newMailWire(m).line(); e == nil || e == io.EOF {
		t.Fatal("raw I/O error escaped")
	}
}
