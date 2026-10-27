package emails

import (
	"fmt"
	"strings"
	"testing"
)

func TestIMAPDefaultAndMaximumPage(t *testing.T) {
	for _, limit := range []int{10, 25} {
		s := imapService(t, false)
		var response strings.Builder
		response.WriteString(inboxTranscript(30, 9))
		for i := 31 - limit; i <= 30; i++ {
			fmt.Fprintf(&response, "* %d FETCH (UID %d)\r\n", i, i+100)
		}
		response.WriteString("A003 OK done\r\n")
		m := mockMail(t, s, response.String(), false)
		args := map[string]any{"account_id": "work", "query": ""}
		if limit == 25 {
			args["limit"] = float64(limit)
		}
		r := call(t, s, "email_list", args)
		if r.IsError || strings.Count(r.Content[0].Text, `"id":`) != limit || !strings.Contains(m.output.String(), fmt.Sprintf("FETCH %d:30 (UID)", 31-limit)) {
			t.Fatal(r)
		}
	}
}

func TestIMAPStrictFetchMetadata(t *testing.T) {
	for _, line := range []string{
		"* 1 FETCH (UID 1junk)",
		"* 1 FETCH (UID 1 UID 2)",
		"* 1 FETCH (XUID 1)",
		"* 1 FETCH (UID 4294967296)",
		"* 1 FETCH (UID 01)",
		"* 1 FETCH (UID 1 FLAGS (\\Seen))",
		"* 1 FETCH (UID 1))",
	} {
		if _, _, e := parseFetchMetadata(line, false); e == nil {
			t.Fatal("accepted malformed metadata", line)
		}
	}
	uid, size, e := parseFetchMetadata("* 1 FETCH (RFC822.SIZE 262144 UID 4294967295)", true)
	if e != nil || uid != 4294967295 || size != mailMessageLimit {
		t.Fatal(uid, size, e)
	}
}

func TestMailExactLiteralAndTextBounds(t *testing.T) {
	m := &mailMock{input: strings.NewReader(strings.Repeat("x", mailMessageLimit))}
	w := newMailWire(m)
	if b, e := w.literal(mailMessageLimit); e != nil || len(b) != mailMessageLimit {
		t.Fatal("exact raw limit rejected", e)
	}
	if _, e := w.literal(mailMessageLimit + 1); e == nil {
		t.Fatal("oversized literal accepted")
	}
	m = &mailMock{input: strings.NewReader("abcd")}
	w = newMailWire(m)
	w.remaining = 3
	if _, e := w.literal(4); e == nil {
		t.Fatal("wire budget bypass")
	}
	raw := "Content-Type: text/plain; charset=utf-8\r\n\r\n" + strings.Repeat("x", mimeTextLimit)
	v, e := extractIMAPMessage("gmailimap_1_1", []byte(raw))
	if e != nil || len(v.(map[string]any)["text"].(string)) != mimeTextLimit {
		t.Fatal("exact text limit rejected", e)
	}
	for _, transcript := range []string{
		"* OK ready\r\nA001 OK login\r\n* OK [UIDVALIDITY 44] stable\r\nA002 OK [READ-ONLY] missing EXISTS\r\n",
		inboxTranscript(1, 44) + "* OK [UIDVALIDITY 45] changed\r\nA003 OK done\r\n",
		inboxTranscript(1, 44) + "* 1 FETCH (UID 1)\nA003 OK done\r\n",
	} {
		s := imapService(t, false)
		mockMail(t, s, transcript, false)
		if r := call(t, s, "email_list", map[string]any{"account_id": "work"}); !r.IsError {
			t.Fatal(r)
		}
	}
}
