package core

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
)

type CSRFConfig struct {
	TokenLength  int
	CookieName   string
	HeaderName   string
	FormField    string
	Secure       bool
	SameSite     SameSite
	MaxAge       int
	ErrorHandler func(*Request, *Response)
}

func CSRF(cfg CSRFConfig) MiddlewareFunc {
	if cfg.TokenLength <= 0 {
		cfg.TokenLength = 32
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "csrf_token"
	}
	if cfg.HeaderName == "" {
		cfg.HeaderName = "X-CSRF-Token"
	}
	if cfg.FormField == "" {
		cfg.FormField = "csrf_token"
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 43200
	}

	tokenLen := cfg.TokenLength
	cookieName := cfg.CookieName
	headerName := cfg.HeaderName
	formField := cfg.FormField
	secure := cfg.Secure
	sameSite := cfg.SameSite
	maxAge := cfg.MaxAge
	errorHandler := cfg.ErrorHandler

	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			token := req.Cookie(cookieName)
			if token == "" {
				b := make([]byte, tokenLen)
				_, _ = rand.Read(b)
				token = hex.EncodeToString(b)
				resp.SetCookie(Cookie{
					Name:     cookieName,
					Value:    token,
					Path:     "/",
					MaxAge:   maxAge,
					Secure:   secure,
					HttpOnly: false,
					SameSite: sameSite,
				})
			}

			req.Set("csrf_token", token)

			if isUnsafeMethod(req.Method) {
				clientToken := req.Header(headerName)
				if clientToken == "" {
					clientToken = extractFormField(req, formField)
				}

				if subtle.ConstantTimeCompare([]byte(token), []byte(clientToken)) != 1 {
					if errorHandler != nil {
						errorHandler(req, resp)
					} else {
						resp.Status(403).String("CSRF token mismatch")
					}
					return
				}
			}

			next(req, resp)
		}
	}
}

func isUnsafeMethod(method string) bool {
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

func extractFormField(req *Request, field string) string {
	ct := req.Header("Content-Type")
	if !hasPrefixFold(ct, "application/x-www-form-urlencoded") {
		return ""
	}
	body := req.Body
	fieldBytes := []byte(field)
	fieldLen := len(fieldBytes)

	i := 0
	for i < len(body) {
		keyStart := i
		eqPos := -1
		for i < len(body) && body[i] != '&' {
			if body[i] == '=' && eqPos == -1 {
				eqPos = i
			}
			i++
		}
		if eqPos >= 0 && eqPos-keyStart == fieldLen {
			match := true
			for j := 0; j < fieldLen; j++ {
				if body[keyStart+j] != fieldBytes[j] {
					match = false
					break
				}
			}
			if match {
				valStart := eqPos + 1
				return string(body[valStart:i])
			}
		}
		i++
	}
	return ""
}

func CSRFToken(req *Request) string {
	return req.GetString("csrf_token")
}
