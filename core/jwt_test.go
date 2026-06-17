package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/bytedance/sonic"
)

var jwtFixedNow = time.Unix(1_000_000, 0)

func fixedNow() time.Time { return jwtFixedNow }

// mintToken builds a valid HMAC-SHA256 token for the given claims so tests can
// exercise the full validateJWT + verifyClaims path.
func mintToken(t *testing.T, secret []byte, claims map[string]any) string {
	t.Helper()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	payloadBytes, err := sonic.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig
}

func TestVerifyClaims(t *testing.T) {
	nowUnix := float64(jwtFixedNow.Unix())

	tests := []struct {
		name   string
		claims map[string]any
		cfg    JWTConfig
		want   string
	}{
		{
			name:   "valid token accepted",
			claims: map[string]any{"exp": nowUnix + 60},
			want:   "",
		},
		{
			name:   "missing exp rejected",
			claims: map[string]any{"sub": "user"},
			want:   "missing exp claim",
		},
		{
			name:   "non-numeric exp rejected",
			claims: map[string]any{"exp": "soon"},
			want:   "missing exp claim",
		},
		{
			name:   "expired token rejected",
			claims: map[string]any{"exp": nowUnix - 1},
			want:   "token expired",
		},
		{
			name:   "exp exactly now accepted",
			claims: map[string]any{"exp": nowUnix},
			want:   "",
		},
		{
			name:   "nbf in future rejected",
			claims: map[string]any{"exp": nowUnix + 60, "nbf": nowUnix + 30},
			want:   "token not yet valid",
		},
		{
			name:   "nbf in past accepted",
			claims: map[string]any{"exp": nowUnix + 60, "nbf": nowUnix - 30},
			want:   "",
		},
		{
			name:   "invalid nbf rejected",
			claims: map[string]any{"exp": nowUnix + 60, "nbf": "later"},
			want:   "invalid nbf claim",
		},
		{
			name:   "issuer mismatch rejected",
			claims: map[string]any{"exp": nowUnix + 60, "iss": "other"},
			cfg:    JWTConfig{ExpectedIssuer: "auth"},
			want:   "invalid issuer",
		},
		{
			name:   "issuer missing when expected rejected",
			claims: map[string]any{"exp": nowUnix + 60},
			cfg:    JWTConfig{ExpectedIssuer: "auth"},
			want:   "invalid issuer",
		},
		{
			name:   "issuer match accepted",
			claims: map[string]any{"exp": nowUnix + 60, "iss": "auth"},
			cfg:    JWTConfig{ExpectedIssuer: "auth"},
			want:   "",
		},
		{
			name:   "audience mismatch rejected",
			claims: map[string]any{"exp": nowUnix + 60, "aud": "service-a"},
			cfg:    JWTConfig{ExpectedAudience: "service-b"},
			want:   "invalid audience",
		},
		{
			name:   "audience string match accepted",
			claims: map[string]any{"exp": nowUnix + 60, "aud": "service-b"},
			cfg:    JWTConfig{ExpectedAudience: "service-b"},
			want:   "",
		},
		{
			name:   "audience array match accepted",
			claims: map[string]any{"exp": nowUnix + 60, "aud": []any{"service-a", "service-b"}},
			cfg:    JWTConfig{ExpectedAudience: "service-b"},
			want:   "",
		},
		{
			name:   "audience missing when expected rejected",
			claims: map[string]any{"exp": nowUnix + 60},
			cfg:    JWTConfig{ExpectedAudience: "service-b"},
			want:   "invalid audience",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.now = fixedNow
			if got := verifyClaims(tt.claims, tt.cfg); got != tt.want {
				t.Fatalf("verifyClaims = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateJWTRoundTrip(t *testing.T) {
	secret := []byte("test-secret")

	token := mintToken(t, secret, map[string]any{"exp": float64(jwtFixedNow.Unix() + 60), "sub": "user"})

	claims, ok := validateJWT(token, secret)
	if !ok {
		t.Fatal("validateJWT rejected a well-formed token")
	}
	if claims["sub"] != "user" {
		t.Fatalf("sub claim = %v, want user", claims["sub"])
	}

	if errMsg := verifyClaims(claims, JWTConfig{now: fixedNow}); errMsg != "" {
		t.Fatalf("verifyClaims on minted token = %q, want accepted", errMsg)
	}
}

func TestValidateJWTBadSignature(t *testing.T) {
	token := mintToken(t, []byte("right-secret"), map[string]any{"exp": float64(jwtFixedNow.Unix() + 60)})

	if _, ok := validateJWT(token, []byte("wrong-secret")); ok {
		t.Fatal("validateJWT accepted a token signed with a different secret")
	}
}
