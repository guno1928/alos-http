package core

import (
	"strconv"
	"strings"
	"time"
)

type SameSite uint8

const (
	SameSiteDefault SameSite = 0
	SameSiteLax     SameSite = 1
	SameSiteStrict  SameSite = 2
	SameSiteNone    SameSite = 3
)

type Cookie struct {
	Name     string
	Value    string
	Path     string
	Domain   string
	MaxAge   int
	Expires  time.Time
	Secure   bool
	HttpOnly bool
	SameSite SameSite
}

func parseCookieHeader(header string) []Cookie {
	var cookies []Cookie
	for len(header) > 0 {
		var pair string
		idx := strings.IndexByte(header, ';')
		if idx >= 0 {
			pair = header[:idx]
			header = header[idx+1:]
		} else {
			pair = header
			header = ""
		}
		pair = trimASCIISpace(pair)
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			continue
		}
		name := trimASCIISpace(pair[:eq])
		value := trimASCIISpace(pair[eq+1:])
		value = urlDecode(value)
		cookies = append(cookies, Cookie{Name: name, Value: value})
	}
	return cookies
}

func (c *Cookie) String() string {
	var b strings.Builder
	b.WriteString(c.Name)
	b.WriteByte('=')
	b.WriteString(c.Value)
	if c.Path != "" {
		b.WriteString("; Path=")
		b.WriteString(c.Path)
	}
	if c.Domain != "" {
		b.WriteString("; Domain=")
		b.WriteString(c.Domain)
	}
	if c.MaxAge > 0 {
		b.WriteString("; Max-Age=")
		b.WriteString(strconv.Itoa(c.MaxAge))
	} else if c.MaxAge < 0 {
		b.WriteString("; Max-Age=0")
	}
	if !c.Expires.IsZero() {
		b.WriteString("; Expires=")
		b.WriteString(c.Expires.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	}
	if c.HttpOnly {
		b.WriteString("; HttpOnly")
	}
	if c.Secure {
		b.WriteString("; Secure")
	}
	switch c.SameSite {
	case SameSiteLax:
		b.WriteString("; SameSite=Lax")
	case SameSiteStrict:
		b.WriteString("; SameSite=Strict")
	case SameSiteNone:
		b.WriteString("; SameSite=None")
	}
	return b.String()
}

func deleteCookieString(name, path, domain string) string {
	c := Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		Domain:   domain,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: false,
		Secure:   false,
	}
	return c.String()
}
