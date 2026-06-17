package core

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/acme"
)

func TestValidChallengeToken(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  bool
	}{
		{"plain", "abc123_-token", true},
		{"empty", "", false},
		{"dot", ".", false},
		{"dotdot", "..", false},
		{"traversal", "../../etc/passwd", false},
		{"forward slash", "a/b", false},
		{"back slash", "a\\b", false},
		{"nul byte", "a\x00b", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validChallengeToken(tc.token); got != tc.want {
				t.Fatalf("validChallengeToken(%q) = %v, want %v", tc.token, got, tc.want)
			}
		})
	}
}

func TestReadChallengeFromDirConfinement(t *testing.T) {
	root := t.TempDir()

	// A secret living one level above the challenge root; a traversal must not
	// reach it.
	secret := filepath.Join(filepath.Dir(root), "secret.txt")
	if err := os.WriteFile(secret, []byte("top-secret"), 0600); err != nil {
		t.Fatal(err)
	}

	want := []byte("challenge-auth-key")
	if err := os.WriteFile(filepath.Join(root, "good-token"), want, 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("legitimate token served", func(t *testing.T) {
		got, err := readChallengeFromDir(root, "good-token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("traversal token confined", func(t *testing.T) {
		// os.Root must refuse to escape the root even though the relative path
		// resolves to the secret on a naive filepath.Join.
		got, err := readChallengeFromDir(root, "../secret.txt")
		if err == nil {
			t.Fatalf("traversal not blocked: read %q", got)
		}
	})

	t.Run("absolute path confined", func(t *testing.T) {
		got, err := readChallengeFromDir(root, secret)
		if err == nil {
			t.Fatalf("absolute path not blocked: read %q", got)
		}
	})
}

func TestAcmeAlreadyRegistered(t *testing.T) {
	t.Run("409 is already registered", func(t *testing.T) {
		err := &acme.Error{StatusCode: http.StatusConflict}
		if !acmeAlreadyRegistered(err) {
			t.Fatal("409 *acme.Error not recognized as already-registered")
		}
	})

	t.Run("wrapped 409 is already registered", func(t *testing.T) {
		err := errors.New("wrap")
		err = errors.Join(err, &acme.Error{StatusCode: http.StatusConflict})
		if !acmeAlreadyRegistered(err) {
			t.Fatal("wrapped 409 not recognized as already-registered")
		}
	})

	t.Run("other status propagates", func(t *testing.T) {
		err := &acme.Error{StatusCode: http.StatusInternalServerError}
		if acmeAlreadyRegistered(err) {
			t.Fatal("500 *acme.Error misread as already-registered")
		}
	})

	t.Run("message containing already does not count", func(t *testing.T) {
		// Guards against regressing to substring matching: a non-409 error whose
		// text mentions "already" must still propagate.
		err := errors.New("the request was already processed but then failed")
		if acmeAlreadyRegistered(err) {
			t.Fatal("plain error with 'already' substring misread as already-registered")
		}
	})

	t.Run("nil is not already registered", func(t *testing.T) {
		if acmeAlreadyRegistered(nil) {
			t.Fatal("nil error misread as already-registered")
		}
	})
}
