package emails

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bradthebrad/nullbot-emails-mcp/internal/safe"
)

const (
	mailTimeout      = 20 * time.Second
	mailLineLimit    = 8192
	mailWireLimit    = 320 * 1024
	mailLineCount    = 1024
	mailMessageLimit = 256 * 1024
)

var errMailProtocol = errors.New("mail provider response invalid or exceeds limits (details withheld)")
var errMailRead = errors.New("mail provider read failed (details withheld)")
var errMailSend = errors.New("SMTP send failed (details withheld); outcome may be unknown; do not retry automatically")

type mailDialFunc func(context.Context, string, *tls.Config) (net.Conn, error)

func gmailTLS(host string) *tls.Config {
	return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
}

func imapPassword(a safe.Account) string {
	// Google displays app passwords in groups separated by spaces.
	return strings.ReplaceAll(a.Fields["app_password"], " ", "")
}

func imapCredentials(a safe.Account) error {
	if safe.Require(a, "email", "app_password") != nil {
		return errors.New("gmail_imap requires email and app_password")
	}
	address := a.Fields["email"]
	parsed, e := mail.ParseAddress(address)
	if e != nil || parsed.Address != address || len(address) > 254 || !strings.Contains(address, "@") {
		return errors.New("invalid gmail_imap email credential")
	}
	for _, r := range address {
		if r < 33 || r > 126 {
			return errors.New("invalid gmail_imap email credential")
		}
	}
	password := imapPassword(a)
	if len(password) == 0 || len(password) > 256 {
		return errors.New("invalid gmail_imap app_password credential")
	}
	for _, r := range password {
		if r < 33 || r > 126 {
			return errors.New("invalid gmail_imap app_password credential")
		}
	}
	return nil
}

// Each operation owns one direct implicit-TLS connection, deadline and cancellation
// watcher. No HTTP transport, proxy environment, account endpoint or tool host is used.
func (s *Service) openMail(parent context.Context, smtp bool) (net.Conn, func(), error) {
	ctx, cancel := context.WithTimeout(parent, mailTimeout)
	host, address := "imap.gmail.com", "imap.gmail.com:993"
	if smtp {
		host, address = "smtp.gmail.com", "smtp.gmail.com:465"
	}
	dial := s.mailDial
	if dial == nil {
		dial = func(ctx context.Context, address string, config *tls.Config) (net.Conn, error) {
			d := tls.Dialer{NetDialer: &net.Dialer{Timeout: mailTimeout}, Config: config}
			return d.DialContext(ctx, "tcp", address)
		}
	}
	if ctx.Err() != nil {
		cancel()
		return nil, nil, errMailRead
	}
	conn, e := dial(ctx, address, gmailTLS(host))
	if e != nil {
		cancel()
		return nil, nil, errMailRead
	}
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		conn.Close()
		cancel()
		return nil, nil, errMailRead
	}
	closeNow := func() {
		// Abort TLS close-notify writes too; cancellation must not wait for a peer.
		_ = conn.SetDeadline(time.Now())
		_ = conn.Close()
	}
	stop := context.AfterFunc(ctx, closeNow)
	cleanup := func() {
		stop()
		closeNow()
		cancel()
	}
	return conn, cleanup, nil
}

type mailWire struct {
	conn      net.Conn
	reader    *bufio.Reader
	remaining int
	lines     int
}

func newMailWire(conn net.Conn) *mailWire {
	return &mailWire{conn: conn, reader: bufio.NewReaderSize(conn, mailLineLimit), remaining: mailWireLimit}
}

func (w *mailWire) line() (string, error) {
	if w.lines >= mailLineCount || w.remaining <= 0 {
		return "", errMailProtocol
	}
	b, e := w.reader.ReadSlice('\n')
	w.remaining -= len(b)
	w.lines++
	if e != nil || len(b) > mailLineLimit || w.remaining < 0 || len(b) < 2 || b[len(b)-2] != '\r' {
		return "", errMailProtocol
	}
	return string(b[:len(b)-2]), nil
}

func (w *mailWire) literal(n int) ([]byte, error) {
	if n < 0 || n > mailMessageLimit || n > w.remaining {
		return nil, errMailProtocol
	}
	w.remaining -= n
	b := make([]byte, n)
	if _, e := io.ReadFull(w.reader, b); e != nil {
		return nil, errMailProtocol
	}
	return b, nil
}

func (w *mailWire) write(text string) error {
	if n, e := io.WriteString(w.conn, text); e != nil || n != len(text) {
		return errMailRead
	}
	return nil
}

var imapFetchStart = regexp.MustCompile(`^\* ([0-9]+) FETCH \(`)
var imapBody = regexp.MustCompile(`BODY\[\](?:<0>)? \{([0-9]+)\}$`)
var imapValidity = regexp.MustCompile(`\[UIDVALIDITY ([0-9]+)\]`)

func parseFetchMetadata(line string, wantBody bool) (uint32, uint32, error) {
	prefix := imapFetchStart.FindStringIndex(line)
	if prefix == nil || !strings.HasSuffix(line, ")") {
		return 0, 0, errMailProtocol
	}
	fields := strings.Fields(line[prefix[1] : len(line)-1])
	want := 2
	if wantBody {
		want = 4
	}
	if len(fields) != want {
		return 0, 0, errMailProtocol
	}
	var uid, size uint32
	seen := map[string]bool{}
	for i := 0; i < len(fields); i += 2 {
		key := fields[i]
		if seen[key] || key != "UID" && (key != "RFC822.SIZE" || !wantBody) {
			return 0, 0, errMailProtocol
		}
		seen[key] = true
		n, e := positive32(fields[i+1])
		if e != nil {
			return 0, 0, e
		}
		if key == "UID" {
			uid = n
		} else {
			size = n
		}
	}
	if uid == 0 || wantBody && !seen["RFC822.SIZE"] {
		return 0, 0, errMailProtocol
	}
	return uid, size, nil
}

func positive32(s string) (uint32, error) {
	n, e := strconv.ParseUint(s, 10, 32)
	if e != nil || n == 0 || strconv.FormatUint(n, 10) != s {
		return 0, errMailProtocol
	}
	return uint32(n), nil
}

type imapFetch struct {
	uid  uint32
	size uint32
	body []byte
}

type imapSession struct {
	wire      *mailWire
	tag       int
	exists    uint32
	sawExists bool
	validity  uint32
}

// Only internally constructed commands reach this method. Unknown continuations,
// literals and excessive responses fail closed; nothing is interpolated from a query.
func (c *imapSession) command(command string, maxFetch int, wantBody bool) ([]imapFetch, string, error) {
	c.tag++
	tag := fmt.Sprintf("A%03d", c.tag)
	if e := c.wire.write(tag + " " + command + "\r\n"); e != nil {
		return nil, "", e
	}
	out := []imapFetch{}
	for {
		line, e := c.wire.line()
		if e != nil {
			return nil, "", e
		}
		if strings.HasPrefix(line, tag+" ") {
			if !strings.HasPrefix(line, tag+" OK ") && line != tag+" OK" {
				return nil, "", errMailRead
			}
			return out, line, nil
		}
		if !strings.HasPrefix(line, "* ") || strings.HasPrefix(line, "* BYE") {
			return nil, "", errMailProtocol
		}
		if imapFetchStart.MatchString(line) {
			if len(out) >= maxFetch {
				return nil, "", errMailProtocol
			}
			var body []byte
			if m := imapBody.FindStringSubmatch(line); m != nil {
				if !wantBody {
					return nil, "", errMailProtocol
				}
				n, e := strconv.ParseUint(m[1], 10, 32)
				if e != nil || n > mailMessageLimit {
					return nil, "", errMailProtocol
				}
				body, e = c.wire.literal(int(n))
				if e != nil {
					return nil, "", e
				}
				tail, e := c.wire.line()
				if e != nil || len(tail) > 256 || !strings.HasSuffix(tail, ")") || strings.ContainsAny(tail, "{\"\r\n") {
					return nil, "", errMailProtocol
				}
				line = line[:len(line)-len(m[0])] + " " + tail
			} else if wantBody || !strings.HasSuffix(line, ")") || strings.ContainsAny(line, "{\"") {
				return nil, "", errMailProtocol
			}
			uid, size, e := parseFetchMetadata(line, wantBody)
			if e != nil || wantBody && (size > mailMessageLimit || uint64(size) != uint64(len(body))) {
				return nil, "", errMailProtocol
			}
			out = append(out, imapFetch{uid: uid, size: size, body: body})
			continue
		}
		if strings.Contains(line, "{") || strings.HasSuffix(line, " EXPUNGE") {
			return nil, "", errMailProtocol
		}
		if m := imapValidity.FindStringSubmatch(line); m != nil {
			v, e := positive32(m[1])
			if e != nil || c.validity != 0 && c.validity != v {
				return nil, "", errMailProtocol
			}
			c.validity = v
		}
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[2] == "EXISTS" {
			n, e := strconv.ParseUint(fields[1], 10, 32)
			if e != nil {
				return nil, "", errMailProtocol
			}
			c.exists = uint32(n)
			c.sawExists = true
		}
	}
}

func imapQuote(s string) string {
	return "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(s) + "\""
}

func (s *Service) openInbox(ctx context.Context, a safe.Account) (*imapSession, func(), error) {
	conn, closeConn, e := s.openMail(ctx, false)
	if e != nil {
		return nil, nil, e
	}
	c := &imapSession{wire: newMailWire(conn)}
	greeting, e := c.wire.line()
	if e == nil && !strings.HasPrefix(greeting, "* OK ") {
		e = errMailProtocol
	}
	if e == nil {
		_, _, e = c.command("LOGIN "+imapQuote(a.Fields["email"])+" "+imapQuote(imapPassword(a)), 0, false)
	}
	if e == nil {
		var completion string
		c.validity, c.exists, c.sawExists = 0, 0, false
		_, completion, e = c.command("EXAMINE INBOX", 0, false)
		if e == nil && (c.validity == 0 || !c.sawExists || !strings.HasPrefix(completion, fmt.Sprintf("A%03d OK [READ-ONLY]", c.tag))) {
			e = errMailProtocol
		}
	}
	if e != nil {
		closeConn()
		return nil, nil, e
	}
	return c, closeConn, nil
}

func imapID(validity, uid uint32) string {
	return fmt.Sprintf("gmailimap_%d_%d", validity, uid)
}

func parseIMAPID(id string) (uint32, uint32, error) {
	parts := strings.Split(id, "_")
	if len(parts) != 3 || parts[0] != "gmailimap" {
		return 0, 0, errors.New("invalid gmail_imap message_id; use an ID from email_list")
	}
	v, e1 := positive32(parts[1])
	u, e2 := positive32(parts[2])
	if e1 != nil || e2 != nil {
		return 0, 0, errors.New("invalid gmail_imap message_id; use an ID from email_list")
	}
	return v, u, nil
}

func (s *Service) imapList(ctx context.Context, a safe.Account, limit int) (any, error) {
	c, cleanup, e := s.openInbox(ctx, a)
	if e != nil {
		return nil, e
	}
	defer cleanup()
	count := c.exists
	messages := []map[string]string{}
	if count != 0 {
		start := uint32(1)
		if count > uint32(limit) {
			start = count - uint32(limit) + 1
		}
		// Sequence range is bounded before asking for UIDs; never SEARCH ALL.
		items, _, e := c.command(fmt.Sprintf("FETCH %d:%d (UID)", start, count), limit, false)
		if e != nil {
			return nil, e
		}
		sort.Slice(items, func(i, j int) bool { return items[i].uid > items[j].uid })
		seen := map[uint32]bool{}
		for _, item := range items {
			if seen[item.uid] {
				return nil, errMailProtocol
			}
			seen[item.uid] = true
			messages = append(messages, map[string]string{"id": imapID(c.validity, item.uid)})
		}
	}
	return map[string]any{"messages": messages, "has_more": count > uint32(limit), "mailbox": "INBOX", "note": "Newest INBOX UIDs first; first page only, no query. IDs are bound to INBOX UIDVALIDITY; mailbox changes may require listing again."}, nil
}

func (s *Service) imapGet(ctx context.Context, a safe.Account, id string) (any, error) {
	validity, uid, e := parseIMAPID(id)
	if e != nil {
		return nil, e
	}
	c, cleanup, e := s.openInbox(ctx, a)
	if e != nil {
		return nil, e
	}
	defer cleanup()
	if c.validity != validity {
		return nil, errors.New("gmail_imap message_id expired: INBOX UIDVALIDITY changed; list again")
	}
	items, _, e := c.command(fmt.Sprintf("UID FETCH %d (UID RFC822.SIZE BODY.PEEK[]<0.%d>)", uid, mailMessageLimit+1), 1, true)
	if e != nil {
		return nil, e
	}
	if len(items) != 1 || items[0].uid != uid {
		return nil, errors.New("gmail_imap message not found in INBOX")
	}
	return extractIMAPMessage(id, items[0].body)
}
