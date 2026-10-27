package emails

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"unicode/utf8"
)

const (
	mimeTextLimit   = 24000
	mimeHeaderLimit = 16 * 1024
	mimePartLimit   = 64
	mimeDepthLimit  = 12
)

type mimeText struct {
	text        []string
	bytes       int
	parts       int
	attachments int
	omitted     int
}

func extractIMAPMessage(id string, raw []byte) (any, error) {
	if len(raw) > mailMessageLimit {
		return nil, errMailProtocol
	}
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headerEnd < 0 || headerEnd > mimeHeaderLimit {
		return nil, errors.New("message header invalid or exceeds limit")
	}
	message, e := mail.ReadMessage(bytes.NewReader(raw))
	if e != nil {
		return nil, errors.New("invalid MIME message (details withheld)")
	}
	headers := map[string]string{}
	decoder := &mime.WordDecoder{}
	for _, name := range []string{"From", "To", "Subject", "Date"} {
		value := message.Header.Get(name)
		if len(value) > 2048 {
			return nil, errors.New("message header exceeds limit")
		}
		if decoded, e := decoder.DecodeHeader(value); e == nil {
			value = decoded
		}
		headers[strings.ToLower(name)] = value
	}
	collector := &mimeText{}
	if e := collector.collect(textproto.MIMEHeader(message.Header), message.Body, 0); e != nil {
		return nil, e
	}
	return map[string]any{"id": id, "mailbox": "INBOX", "headers": headers, "text": strings.Join(collector.text, "\n"), "attachment_count": collector.attachments, "omitted_parts": collector.omitted, "note": "Only inline text/plain UTF-8/US-ASCII MIME parts returned. HTML, attachments and unsupported charsets omitted. Raw message transfer is bounded; no flags changed."}, nil
}

func (c *mimeText) collect(header textproto.MIMEHeader, reader io.Reader, depth int) error {
	c.parts++
	if depth > mimeDepthLimit || c.parts > mimePartLimit {
		return errors.New("MIME structure exceeds limits")
	}
	headerBytes := 0
	for key, values := range header {
		headerBytes += len(key)
		for _, value := range values {
			headerBytes += len(value)
		}
	}
	if headerBytes > mimeHeaderLimit {
		return errors.New("MIME header exceeds limit")
	}
	kind := "text/plain"
	params := map[string]string{}
	var e error
	if value := header.Get("Content-Type"); value != "" {
		kind, params, e = mime.ParseMediaType(value)
		if e != nil {
			return errors.New("invalid MIME content type")
		}
	}
	disposition, dispositionParams := "", map[string]string{}
	if value := header.Get("Content-Disposition"); value != "" {
		disposition, dispositionParams, e = mime.ParseMediaType(value)
		if e != nil {
			return errors.New("invalid MIME disposition")
		}
	}
	if disposition == "attachment" || dispositionParams["filename"] != "" || params["name"] != "" {
		c.attachments++
		return nil
	}
	if strings.HasPrefix(kind, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" || len(boundary) > 200 {
			return errors.New("invalid MIME boundary")
		}
		if encoding := strings.ToLower(header.Get("Content-Transfer-Encoding")); encoding != "" && encoding != "7bit" && encoding != "8bit" && encoding != "binary" {
			return errors.New("unsupported multipart transfer encoding")
		}
		parts := multipart.NewReader(reader, boundary)
		for {
			part, e := parts.NextRawPart()
			if e == io.EOF {
				return nil
			}
			if e != nil {
				return errors.New("invalid MIME multipart (details withheld)")
			}
			if e := c.collect(part.Header, part, depth+1); e != nil {
				return e
			}
			if e := part.Close(); e != nil {
				return errors.New("invalid MIME part (details withheld)")
			}
		}
	}
	charset := strings.ToLower(params["charset"])
	if kind != "text/plain" || charset != "" && charset != "utf-8" && charset != "us-ascii" {
		c.omitted++
		return nil
	}
	switch strings.ToLower(header.Get("Content-Transfer-Encoding")) {
	case "", "7bit", "8bit", "binary":
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding, reader)
	case "quoted-printable":
		reader = quotedprintable.NewReader(reader)
	default:
		return errors.New("unsupported MIME transfer encoding")
	}
	body, e := io.ReadAll(io.LimitReader(reader, int64(mimeTextLimit-c.bytes+1)))
	if e != nil || !utf8.Valid(body) {
		return errors.New("invalid MIME text encoding (details withheld)")
	}
	if charset == "us-ascii" {
		for _, b := range body {
			if b > 127 {
				return errors.New("invalid MIME ASCII text")
			}
		}
	}
	if len(c.text) > 0 {
		c.bytes++
	}
	c.bytes += len(body)
	if c.bytes > mimeTextLimit {
		return errors.New("MIME text exceeds output limit")
	}
	c.text = append(c.text, string(body))
	return nil
}
