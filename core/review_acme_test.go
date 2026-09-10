package core

import (
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestACMEAccountKeyPersistsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	first := newACMEIntegration(ACMEConfig{CacheDir: dir, Domains: []string{"a.test"}}, nil)
	if first == nil {
		t.Fatal("first integration nil")
	}
	second := newACMEIntegration(ACMEConfig{CacheDir: dir, Domains: []string{"a.test"}}, nil)
	if second == nil {
		t.Fatal("second integration nil")
	}
	k1 := first.client.Key.(*ecdsa.PrivateKey)
	k2 := second.client.Key.(*ecdsa.PrivateKey)
	if !k1.Equal(k2) {
		t.Fatal("account key regenerated on restart; the ACME account would be orphaned")
	}
	info, err := os.Stat(filepath.Join(dir, acmeAccountKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		t.Fatalf("account key mode %v is readable by others", info.Mode().Perm())
	}
}

func TestACMEAccountKeyCorruptFileIsRejected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, acmeAccountKeyFile), []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateACMEAccountKey(filepath.Join(dir, acmeAccountKeyFile)); err == nil {
		t.Fatal("corrupt account key silently replaced")
	}
}

func TestEnableACMEStopsPreviousIntegration(t *testing.T) {
	dir := t.TempDir()
	s := New(Config{Addr: "127.0.0.1:0", HTTPAddr: "-", LogRequests: false})
	s.EnableACME(ACMEConfig{CacheDir: dir, Domains: []string{"a.test"}})
	old := s.acme.Load()
	if old == nil {
		t.Fatal("EnableACME did not install an integration")
	}
	s.EnableACME(ACMEConfig{CacheDir: dir, Domains: []string{"b.test"}})
	if s.acme.Load() == old {
		t.Fatal("second EnableACME did not replace the integration")
	}
	select {
	case <-old.stop:
	default:
		t.Fatal("previous ACME integration still running after EnableACME; its renewal loop and goroutines leak")
	}
	s.acme.Load().Stop()
}
