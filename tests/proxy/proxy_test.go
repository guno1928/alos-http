package proxy_test

import (
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/guno1928/alos-http/core"
)

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

func TestReverseProxyDomainLifecycleMatrix(t *testing.T) {
	engine := core.NewProxyEngine()
	defer engine.Stop()
	domains := make([]string, 96)
	for i := range domains {
		domains[i] = fmt.Sprintf("service-%03d.example.test", i)
		engine.AddDomain(core.DomainConfig{
			Domain: domains[i],
			Backends: []core.BackendConfig{
				{Addr: fmt.Sprintf("http://127.0.0.1:%d/path", 10000+i)},
				{Addr: fmt.Sprintf("https://backend-%d.internal/api", i), TLSSkipVerify: true},
			},
		})
	}
	for i, domain := range domains {
		t.Run(fmt.Sprintf("lookup_%03d", i), func(t *testing.T) {
			if engine.Lookup(domain) == nil || engine.Lookup(strings.ToUpper(domain)) == nil || engine.Lookup("missing."+domain) != nil {
				t.Fatalf("lookup mismatch for %q", domain)
			}
		})
	}
	listed := engine.ListDomains()
	sort.Strings(listed)
	want := append([]string(nil), domains...)
	sort.Strings(want)
	if fmt.Sprint(listed) != fmt.Sprint(want) {
		t.Fatalf("ListDomains mismatch: got %d want %d", len(listed), len(want))
	}
	for i, domain := range domains {
		t.Run(fmt.Sprintf("remove_%03d", i), func(t *testing.T) {
			engine.RemoveDomain(domain)
			if engine.Lookup(domain) != nil {
				t.Fatalf("domain still present: %q", domain)
			}
		})
	}
	if len(engine.ListDomains()) != 0 {
		t.Fatalf("domains retained: %v", engine.ListDomains())
	}
}

func TestReverseProxyDomainReplacement(t *testing.T) {
	engine := core.NewProxyEngine()
	defer engine.Stop()
	for i := 0; i < 32; i++ {
		domain := fmt.Sprintf("replace-%02d.example.test", i)
		t.Run(domain, func(t *testing.T) {
			engine.AddDomain(core.DomainConfig{Domain: domain, Backends: []core.BackendConfig{{Addr: "127.0.0.1:8000"}}})
			first := engine.Lookup(domain)
			engine.AddDomain(core.DomainConfig{Domain: domain, Backends: []core.BackendConfig{{Addr: "127.0.0.1:9000"}}})
			second := engine.Lookup(domain)
			if first == nil || second == nil || first == second {
				t.Fatalf("domain replacement failed: %p %p", first, second)
			}
		})
	}
}

func TestReverseProxyRejectsEmptyDomain(t *testing.T) {
	engine := core.NewProxyEngine()
	defer engine.Stop()
	for i, domain := range []string{"", ".", "   ", " \t "} {
		t.Run(fmt.Sprintf("empty_%d", i), func(t *testing.T) {
			engine.AddDomain(core.DomainConfig{Domain: domain})
			if engine.Lookup(domain) != nil {
				t.Fatalf("empty domain accepted: %q", domain)
			}
		})
	}
}
