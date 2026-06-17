package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"time"

	"github.com/bytedance/sonic"
)

type JWTConfig struct {
	Secret      []byte
	ContextKey  string
	TokenLookup string

	// ExpectedIssuer, when non-empty, requires the token's "iss" claim to match
	// exactly. Left empty, the issuer is not checked.
	ExpectedIssuer string
	// ExpectedAudience, when non-empty, requires the token's "aud" claim to
	// contain this value. Left empty, the audience is not checked. This guards
	// against a token minted for one service being accepted by another.
	ExpectedAudience string

	// now is the time source used for exp/nbf checks. Injected for tests;
	// defaults to time.Now when nil.
	now func() time.Time
}

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

	if cfg.now == nil {
		cfg.now = time.Now
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

			if errMsg := verifyClaims(claims, cfg); errMsg != "" {
				resp.Status(401).JSONString(`{"error":"` + errMsg + `"}`)
				return
			}

			req.Set(contextKey, claims)
			next(req, resp)
		}
	}
}

// verifyClaims enforces the registered-claim policy after the signature is
// already verified. It returns "" on success or a short client-facing error
// message. Fails closed: exp is mandatory (a token without it would otherwise
// never expire), and configured iss/aud must match exactly.
func verifyClaims(claims map[string]any, cfg JWTConfig) string {
	now := cfg.now().Unix()

	exp, ok := numericClaim(claims["exp"])
	if !ok {
		// exp absent or malformed: without it a leaked token is valid forever.
		return "missing exp claim"
	}
	if now > exp {
		return "token expired"
	}

	if nbf, present := claims["nbf"]; present {
		nbfTime, ok := numericClaim(nbf)
		if !ok {
			return "invalid nbf claim"
		}
		if now < nbfTime {
			return "token not yet valid"
		}
	}

	if cfg.ExpectedIssuer != "" {
		iss, _ := claims["iss"].(string)
		if iss != cfg.ExpectedIssuer {
			return "invalid issuer"
		}
	}

	if cfg.ExpectedAudience != "" && !audienceMatches(claims["aud"], cfg.ExpectedAudience) {
		return "invalid audience"
	}

	return ""
}

// numericClaim coerces a JSON numeric claim (decoded as float64) to a Unix
// timestamp. Returns false for absent or non-numeric values.
func numericClaim(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	default:
		return 0, false
	}
}

// audienceMatches reports whether the "aud" claim contains want. Per RFC 7519
// aud may be a single string or an array of strings.
func audienceMatches(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, entry := range v {
			if s, ok := entry.(string); ok && s == want {
				return true
			}
		}
	}
	return false
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

func JWTClaims(req *Request) map[string]any {
	v, ok := req.Get("jwt_claims")
	if !ok {
		return nil
	}
	claims, _ := v.(map[string]any)
	return claims
}
