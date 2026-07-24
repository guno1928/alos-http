package core

import (
	"strconv"
	"strings"
	"time"
)

// SameSite controls the SameSite attribute emitted on a Set-Cookie header.
type SameSite uint8

// SameSite attribute values for Cookie.SameSite.
const (
	// SameSiteDefault omits the SameSite attribute entirely.
	SameSiteDefault SameSite = 0
	// SameSiteLax restricts the cookie to same-site requests and top-level navigations ("; SameSite=Lax").
	SameSiteLax SameSite = 1
	// SameSiteStrict restricts the cookie to same-site requests only ("; SameSite=Strict").
	SameSiteStrict SameSite = 2
	// SameSiteNone sends the cookie on cross-site requests and emits "; SameSite=None" (pair with Secure: true).
	SameSiteNone SameSite = 3
)

// Cookie is an HTTP cookie that serializes into a Set-Cookie header value via String.
//
// Name is the cookie name.
//
//	Example: Name: "session" emits "session=...".
//
// Value is the cookie value; it is written verbatim with CR, LF, and NUL bytes stripped.
//
//	Example: Value: "abc123" emits "session=abc123".
//
// Path scopes the cookie to a URL path; omitted when empty.
//
//	Example: Path: "/" emits "; Path=/".
//	Example: Path: "" omits the Path attribute.
//
// Domain scopes the cookie to a domain; omitted when empty.
//
//	Example: Domain: "example.com" emits "; Domain=example.com".
//
// MaxAge sets the Max-Age attribute in seconds.
//
//	Example: MaxAge: 3600 emits "; Max-Age=3600".
//	Example: MaxAge: -1 emits "; Max-Age=0" (expire immediately).
//	Example: MaxAge: 0 omits the Max-Age attribute.
//
// Expires sets an absolute expiry time; a zero time omits the attribute.
//
//	Example: Expires: time.Now().Add(24 * time.Hour) emits "; Expires=<GMT date>".
//	Example: Expires: time.Time{} omits the Expires attribute.
//
// Secure emits "; Secure" when true, restricting the cookie to HTTPS.
//
//	Example: Secure: true emits "; Secure".
//
// HttpOnly emits "; HttpOnly" when true, hiding the cookie from client-side scripts.
//
//	Example: HttpOnly: true emits "; HttpOnly".
//
// SameSite selects the SameSite attribute; see the SameSite constants.
//
//	Example: SameSite: SameSiteLax emits "; SameSite=Lax".
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

func cookieStripCTL(s string) string {
	if strings.IndexByte(s, '\r') < 0 && strings.IndexByte(s, '\n') < 0 && strings.IndexByte(s, 0) < 0 {
		return s
	}
	return strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(s)
}

// String serializes the cookie into a Set-Cookie header value, stripping CR, LF, and NUL bytes from Name, Value, Path, and Domain.
func (c *Cookie) String() string {
	var b strings.Builder
	b.WriteString(cookieStripCTL(c.Name))
	b.WriteByte('=')
	b.WriteString(cookieStripCTL(c.Value))
	if c.Path != "" {
		b.WriteString("; Path=")
		b.WriteString(cookieStripCTL(c.Path))
	}
	if c.Domain != "" {
		b.WriteString("; Domain=")
		b.WriteString(cookieStripCTL(c.Domain))
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
