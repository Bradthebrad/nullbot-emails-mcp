package emails

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Bradthebrad/nullbot-emails-mcp/internal/safe"
)

// A small fixed SMTP transaction avoids unbounded textproto/SMTP replies and
// exposes no general SMTP command surface. All replies and errors stay private.
func smtpReply(w *mailWire, expected int) ([]string, error) {
	lines := []string{}
	for i := 0; i < 64; i++ {
		line, e := w.line()
		if e != nil || len(line) < 4 {
			return nil, errMailSend
		}
		code, e := strconv.Atoi(line[:3])
		if e != nil || code != expected || line[3] != ' ' && line[3] != '-' {
			return nil, errMailSend
		}
		lines = append(lines, line[4:])
		if line[3] == ' ' {
			return lines, nil
		}
	}
	return nil, errMailSend
}

func smtpCommand(w *mailWire, command string, code int) ([]string, error) {
	if e := w.write(command + "\r\n"); e != nil {
		return nil, errMailSend
	}
	return smtpReply(w, code)
}

func smtpAddress(address string) bool {
	if strings.ContainsAny(address, "<>\r\n") {
		return false
	}
	for _, r := range address {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}

func smtpMessage(from, to, subject, body string) string {
	// Always encode/fold Subject, including long ASCII subjects. Split only at
	// UTF-8 boundaries and keep each encoded-word and physical line short.
	var header strings.Builder
	for len(subject) > 0 {
		n := len(subject)
		if n > 42 {
			n = 42
			for n > 0 && !utf8.RuneStart(subject[n]) {
				n--
			}
		}
		if header.Len() > 0 {
			header.WriteString("\r\n ")
		}
		header.WriteString("=?utf-8?B?" + base64.StdEncoding.EncodeToString([]byte(subject[:n])) + "?=")
		subject = subject[n:]
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	var text strings.Builder
	for len(encoded) > 76 {
		text.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	text.WriteString(encoded + "\r\n")
	return fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n%s", from, to, header.String(), text.String())
}

func (s *Service) smtpSend(ctx context.Context, a safe.Account, to, subject, body string) (any, error) {
	// The public handler has already checked allow_write + confirmed and lengths.
	// Keep the private helper's inputs bounded and enforce safe SMTP envelopes too.
	if !a.AllowWrite || !smtpAddress(to) || !smtpAddress(a.Fields["email"]) || len(to) > 254 || len(subject) > 998 || strings.ContainsAny(subject, "\r\n\x00") || !utf8.ValidString(subject) || len(body) > 24000 || !utf8.ValidString(body) {
		return nil, errMailSend
	}
	conn, cleanup, e := s.openMail(ctx, true)
	if e != nil {
		return nil, errMailSend
	}
	defer cleanup()
	w := newMailWire(conn)
	if _, e = smtpReply(w, 220); e != nil {
		return nil, e
	}
	capabilities, e := smtpCommand(w, "EHLO localhost", 250)
	if e != nil {
		return nil, e
	}
	plain := false
	for _, line := range capabilities {
		fields := strings.Fields(strings.ToUpper(line))
		if len(fields) > 1 && fields[0] == "AUTH" {
			for _, mechanism := range fields[1:] {
				plain = plain || mechanism == "PLAIN"
			}
		}
	}
	if !plain {
		return nil, errMailSend
	}
	auth := base64.StdEncoding.EncodeToString([]byte("\x00" + a.Fields["email"] + "\x00" + imapPassword(a)))
	if _, e = smtpCommand(w, "AUTH PLAIN "+auth, 235); e != nil {
		return nil, e
	}
	if _, e = smtpCommand(w, "MAIL FROM:<"+a.Fields["email"]+">", 250); e != nil {
		return nil, e
	}
	if _, e = smtpCommand(w, "RCPT TO:<"+to+">", 250); e != nil {
		return nil, e
	}
	if _, e = smtpCommand(w, "DATA", 354); e != nil {
		return nil, e
	}
	// Every body line is base64 and every header line begins with a field name
	// or folding space; no line can be the SMTP dot terminator.
	if e = w.write(smtpMessage(a.Fields["email"], to, subject, body) + ".\r\n"); e != nil {
		return nil, errMailSend
	}
	if _, e = smtpReply(w, 250); e != nil {
		return nil, e
	}
	// Do not turn an accepted DATA reply into an uncertain send on QUIT failure.
	// Closing this owned connection is sufficient; no retries, RSET or fallback.
	return map[string]any{"accepted": true, "delivery_confirmed": false}, nil
}
