//go:build linux && amd64

package core

import (
	"net/netip"
	"testing"
)

func TestSplitAuthority(t *testing.T) {
	cases := []struct {
		authority, scheme string
		host              string
		port              uint16
		bad               bool
	}{
		{authority: "origin.test", scheme: "http", host: "origin.test", port: 80},
		{authority: "origin.test", scheme: "https", host: "origin.test", port: 443},
		{authority: "origin.test:8080", scheme: "https", host: "origin.test", port: 8080},
		{authority: "10.0.0.7:9000", scheme: "http", host: "10.0.0.7", port: 9000},
		{authority: "[::1]", scheme: "https", host: "::1", port: 443},
		{authority: "[::1]:8443", scheme: "http", host: "::1", port: 8443},
		{authority: "[2001:db8::7]:80", scheme: "http", host: "2001:db8::7", port: 80},
		{authority: "::1", scheme: "http", host: "::1", port: 80},
		{authority: "", bad: true},
		{authority: "[::1", bad: true},
		{authority: "[::1]x", bad: true},
		{authority: "[::1]:", bad: true},
		{authority: "[]:80", bad: true},
		{authority: "origin.test:", bad: true},
		{authority: ":80", bad: true},
		{authority: "origin.test:0", bad: true},
		{authority: "origin.test:65536", bad: true},
		{authority: "origin.test:http", bad: true},
	}
	for _, tc := range cases {
		host, port, err := splitAuthority(tc.authority, tc.scheme)
		if tc.bad {
			if err == nil {
				t.Errorf("splitAuthority(%q) = %q %d, want an error", tc.authority, host, port)
			}
			continue
		}
		if err != nil || host != tc.host || port != tc.port {
			t.Errorf("splitAuthority(%q, %q) = %q %d %v, want %q %d", tc.authority, tc.scheme, host, port, err, tc.host, tc.port)
		}
	}
}

func TestParseUpstreamIP(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1":        "127.0.0.1",
		"::1":              "::1",
		"::ffff:10.0.0.1":  "10.0.0.1",
		"2001:db8::7":      "2001:db8::7",
		"fe80::1%eth0":     "",
		"010.0.0.1":        "",
		"origin.test":      "",
		"[::1]":            "",
		"":                 "",
		"256.1.1.1":        "",
		"1.2.3":            "",
		"2001:db8::7::1":   "",
		"::ffff:127.0.0.1": "127.0.0.1",
	} {
		addr, ok := parseUpstreamIP(in)
		if want == "" {
			if ok {
				t.Errorf("parseUpstreamIP(%q) = %v, want rejection", in, addr)
			}
			continue
		}
		if !ok || addr.String() != want {
			t.Errorf("parseUpstreamIP(%q) = %v %v, want %s", in, addr, ok, want)
		}
	}
}

func TestHostsTablePrefersIPv4(t *testing.T) {
	table := map[string]netip.Addr{}
	v4 := netip.MustParseAddr("127.0.0.1")
	v6 := netip.MustParseAddr("::1")
	other4 := netip.MustParseAddr("127.0.1.1")
	addHostsEntry(table, "localhost", v6)
	addHostsEntry(table, "localhost", v4)
	addHostsEntry(table, "localhost", v6)
	addHostsEntry(table, "localhost", other4)
	if table["localhost"] != v4 {
		t.Fatalf("localhost = %v, want the first IPv4 entry", table["localhost"])
	}
	addHostsEntry(table, "v6only", v6)
	if table["v6only"] != v6 {
		t.Fatalf("v6only = %v", table["v6only"])
	}
}

func dnsAnswer(id uint16, records ...[]byte) []byte {
	return dnsAnswerFor(id, dnsTypeA, records...)
}

func dnsAnswerFor(id, qtype uint16, records ...[]byte) []byte {
	msg := []byte{byte(id >> 8), byte(id), 0x81, 0x80, 0, 1, 0, byte(len(records)), 0, 0, 0, 0}
	msg = append(msg, 6, 'o', 'r', 'i', 'g', 'i', 'n', 4, 't', 'e', 's', 't', 0, byte(qtype>>8), byte(qtype), 0, 1)
	for _, rec := range records {
		msg = append(msg, rec...)
	}
	return msg
}

func dnsRecord(rtype uint16, ttl uint32, rdata []byte) []byte {
	rec := []byte{0xc0, 0x0c, byte(rtype >> 8), byte(rtype), 0, 1, byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl), byte(len(rdata) >> 8), byte(len(rdata))}
	return append(rec, rdata...)
}

func TestParseDNSResponse(t *testing.T) {
	v6 := netip.MustParseAddr("2001:db8::7").As16()
	cname := dnsRecord(5, 60, []byte{3, 'f', 'o', 'o', 0})
	a := dnsRecord(dnsTypeA, 120, []byte{10, 0, 0, 7})
	aaaa := dnsRecord(dnsTypeAAAA, 90, v6[:])
	malformedA := dnsRecord(dnsTypeA, 120, v6[:])

	cases := []struct {
		name    string
		msg     []byte
		qtype   uint16
		want    string
		ttl     uint32
		wantErr error
	}{
		{"A after CNAME", dnsAnswer(7, cname, a), dnsTypeA, "10.0.0.7", 120, nil},
		{"AAAA", dnsAnswerFor(7, dnsTypeAAAA, aaaa), dnsTypeAAAA, "2001:db8::7", 90, nil},
		{"A query answered only with AAAA", dnsAnswer(7, aaaa), dnsTypeA, "", 0, errFPDNSNoAddress},
		{"AAAA query answered only with A", dnsAnswerFor(7, dnsTypeAAAA, a), dnsTypeAAAA, "", 0, errFPDNSNoAddress},
		{"A record with 16 bytes of data", dnsAnswer(7, malformedA), dnsTypeA, "", 0, errFPDNSNoAddress},
		{"no answers", dnsAnswer(7), dnsTypeA, "", 0, errFPDNSNoAddress},
		{"wrong id", dnsAnswer(8, a), dnsTypeA, "", 0, errFPDNSUnrelated},
		{"truncated", dnsAnswer(7, a)[:40], dnsTypeA, "", 0, errFPDNSFailed},
	}
	for _, tc := range cases {
		addr, ttl, err := fpParseDNSResponse(tc.msg, 7, tc.qtype, "origin.test")
		if err != tc.wantErr {
			t.Errorf("%s: err %v, want %v", tc.name, err, tc.wantErr)
			continue
		}
		if tc.wantErr == nil && (addr.String() != tc.want || ttl != tc.ttl) {
			t.Errorf("%s: %v ttl %d, want %s ttl %d", tc.name, addr, ttl, tc.want, tc.ttl)
		}
	}
}

func TestResolveIPLiterals(t *testing.T) {
	for in, want := range map[string]string{"127.0.0.1": "127.0.0.1", "::1": "::1", "2001:db8::7": "2001:db8::7"} {
		addr, err := fpResolve(in)
		if err != nil || addr.String() != want {
			t.Errorf("fpResolve(%q) = %v %v, want %s", in, addr, err, want)
		}
	}
}

func TestParseDNSResponseUnmapsIPv4MappedAAAA(t *testing.T) {
	for _, mapped := range []string{"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:0.0.0.0"} {
		want := netip.MustParseAddr(mapped)
		data := want.As16()
		msg := dnsAnswerFor(7, dnsTypeAAAA, dnsRecord(dnsTypeAAAA, 90, data[:]))
		addr, _, err := fpParseDNSResponse(msg, 7, dnsTypeAAAA, "origin.test")
		if err != nil {
			t.Fatalf("%s: %v", mapped, err)
		}
		if !addr.Is4() || addr != want.Unmap() {
			t.Errorf("%s: parsed %v, want the unmapped %v", mapped, addr, want.Unmap())
		}
	}
}
