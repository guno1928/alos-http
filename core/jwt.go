package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"time"

	"github.com/bytedance/sonic"
)

// JWTConfig configures the JWT middleware.
//
// Secret is the HMAC-SHA256 key used to verify token signatures; required.
//
//	Example: Secret: []byte("my-256-bit-secret") verifies tokens signed with that key.
//
// ContextKey is the request key under which validated claims are stored; defaults to "jwt_claims" when empty.
//
//	Example: ContextKey: "user" stores claims under req.Get("user") (and also "jwt_claims").
//	Example: ContextKey: "" stores claims under "jwt_claims".
//
// TokenLookup selects where the token is read, as "source:name"; defaults to "header:Authorization" when empty. Supported sources are "header" and "query".
//
//	Example: TokenLookup: "header:Authorization" reads a "Bearer <token>" Authorization header.
//	Example: TokenLookup: "query:token" reads the token from the "token" query parameter.
type JWTConfig struct {
	Secret      []byte
	ContextKey  string
	TokenLookup string
}

// JWT returns middleware that validates a signed JWT (HMAC-SHA256), rejecting requests whose token is missing, malformed, or expired with HTTP 401, and stores the claims on the request per cfg.ContextKey. See JWTConfig for defaults.
//
// Example: app.Use(JWT(JWTConfig{Secret: []byte("secret")}))
// Example: app.Use(JWT(JWTConfig{Secret: key, TokenLookup: "query:token"}))
// Example: app.Use(JWT(JWTConfig{Secret: key, ContextKey: "user"}))
func JWT(cfg JWTConfig) MiddlewareFunc {
	if cfg.ContextKey == "" {
		cfg.ContextKey = "jwt_claims"
	}

	lookupSource := "header"
	lookupName := "Authorization"
	if cfg.TokenLookup != "" {
		for i := 0; i < len(cfg.TokenLookup); i++ {
			if cfg.TokenLookup[i] == ':' {
				lookupSource = cfg.TokenLookup[:i]
				lookupName = cfg.TokenLookup[i+1:]
				break
			}
		}
	}

	contextKey := cfg.ContextKey
	secret := cfg.Secret

	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			var token string

			switch lookupSource {
			case "header":
				auth := req.Header(lookupName)
				if len(auth) > 7 && EqualFoldASCII(auth[:7], "bearer ") {
					token = auth[7:]
				}
			case "query":
				token = req.QueryParam(lookupName)
			}

			if token == "" {
				resp.Status(401).JSONString(`{"error":"missing or invalid token"}`)
				return
			}

			claims, ok := validateJWT(token, secret)
			if !ok {
				resp.Status(401).JSONString(`{"error":"invalid token"}`)
				return
			}

			exp, exists := claims["exp"]
			if !exists {
				resp.Status(401).JSONString(`{"error":"missing exp claim"}`)
				return
			}
			var expTime float64
			switch v := exp.(type) {
			case float64:
				expTime = v
			case int64:
				expTime = float64(v)
			default:
				resp.Status(401).JSONString(`{"error":"invalid exp claim"}`)
				return
			}
			if time.Now().Unix() > int64(expTime) {
				resp.Status(401).JSONString(`{"error":"token expired"}`)
				return
			}

			req.Set(contextKey, claims)
			if contextKey != "jwt_claims" {
				req.Set("jwt_claims", claims)
			}
			next(req, resp)
		}
	}
}

func validateJWT(token string, secret []byte) (map[string]any, bool) {
	firstDot := -1
	secondDot := -1
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			if firstDot == -1 {
				firstDot = i
			} else if secondDot == -1 {
				secondDot = i
			} else {
				return nil, false
			}
		}
	}
	if firstDot < 0 || secondDot < 0 {
		return nil, false
	}

	headerPart := token[:firstDot]
	payloadPart := token[firstDot+1 : secondDot]
	signaturePart := token[secondDot+1:]

	if len(headerPart) == 0 || len(payloadPart) == 0 || len(signaturePart) == 0 {
		return nil, false
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerPart)
	if err != nil {
		return nil, false
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := sonic.Unmarshal(headerBytes, &header); err != nil {
		return nil, false
	}
	if header.Alg != "HS256" {
		return nil, false
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(token[:secondDot]))
	expectedSig := mac.Sum(nil)

	expectedSigB64 := base64.RawURLEncoding.EncodeToString(expectedSig)

	if subtle.ConstantTimeCompare([]byte(signaturePart), []byte(expectedSigB64)) != 1 {
		return nil, false
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return nil, false
	}

	var claims map[string]any
	if err := sonic.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, false
	}

	return claims, true
}

// JWTClaims returns the validated claims attached to req by the JWT middleware, or nil if none are present.
//
// Example: claims := JWTClaims(req); if claims == nil { return }
// Example: sub, _ := JWTClaims(req)["sub"].(string)
func JWTClaims(req *Request) map[string]any {
	v, ok := req.Get("jwt_claims")
	if !ok {
		return nil
	}
	claims, _ := v.(map[string]any)
	return claims
}
