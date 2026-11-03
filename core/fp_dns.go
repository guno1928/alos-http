//go:build linux && amd64

package core

import (
	"crypto/rand"
	"errors"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guno1928/alosmap"
	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

const (
	dnsPort               = 53
	dnsAttemptTimeoutNano = int64(2e9)
	dnsMinTTLNano         = int64(30e9)
	dnsMaxTTLNano         = int64(300e9)
	dnsNegativeTTLNano    = int64(5e9)
)

type fpDNSEntry struct {
	ip      netip.Addr
	expires int64
}

const (
	dnsTypeA     = 1
	dnsTypeCNAME = 5
	dnsTypeAAAA  = 28
	dnsTypeOPT   = 41
	dnsClassIN   = 1

	dnsEDNSPayloadSize = 1232

	dnsHeaderLen        = 12
	dnsQuestionFixedLen = 4
	dnsRecordFixedLen   = 10
	dnsMaxLabelLen      = 63
	dnsMaxNameLen       = 253
	dnsMaxPointerHops   = 16
	dnsMaxCNAMEChain    = 8
	dnsPointerMask      = 0xC0
	dnsMaxDatagram      = 4096

	dnsFlagsRecursionDesired = 0x01
	dnsFlagResponse          = 0x80
	dnsFlagTruncated         = 0x02
	dnsOpcodeMask            = 0x78
	dnsRcodeMask             = 0x0F
)

var (
	errFPDNSNoAddress = errors.New("outbound: dns answer has no address record")
	errFPDNSUnrelated = errors.New("outbound: dns datagram does not answer the pending query")
)

type fpDNSQuery struct {
	host     string
	port     uint16
	server   int
	qtype    uint16
	id       uint16
	deadline int64
	waiters  []*backendConn
}

var (
	fpDNSCache      = alosmap.NewTypedSized[string, *fpDNSEntry](1024, 0, alosmap.WithCleanupInterval(60*time.Second)).Prealloc(128)
	fpDNSConfigOnce sync.Once
	fpDNSServers    []netip.AddrPort
	fpHostsTable    map[string]netip.Addr
	fpLoopbackIPv4  = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	fpStubResolver  = netip.AddrFrom4([4]byte{127, 0, 0, 53})
)

func parseUpstreamIP(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func addHostsEntry(table map[string]netip.Addr, name string, addr netip.Addr) {
	if prev, ok := table[name]; ok && (prev.Is4() || addr.Is6()) {
		return
	}
	table[name] = addr
}

func fpLoadDNSConfig() {
	fpHostsTable = make(map[string]netip.Addr)
	if data, err := os.ReadFile("/etc/hosts"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			addr, ok := parseUpstreamIP(fields[0])
			if !ok {
				continue
			}
			for _, name := range fields[1:] {
				addHostsEntry(fpHostsTable, strings.ToLower(name), addr)
			}
		}
	}
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "nameserver" {
				if addr, ok := parseUpstreamIP(fields[1]); ok {
					fpDNSServers = append(fpDNSServers, netip.AddrPortFrom(addr, dnsPort))
				}
			}
		}
	}
	if len(fpDNSServers) == 0 {
		fpDNSServers = append(fpDNSServers, netip.AddrPortFrom(fpStubResolver, dnsPort), netip.AddrPortFrom(fpLoopbackIPv4, dnsPort))
	}
}

func fpResolve(host string) (netip.Addr, error) {
	if addr, ok := parseUpstreamIP(host); ok {
		return addr, nil
	}
	fpDNSConfigOnce.Do(fpLoadDNSConfig)
	lower := strings.ToLower(host)
	if e, ok := fpDNSCache.Load(lower); ok && e.ip.IsValid() && turbo.UnixNano() < e.expires {
		return e.ip, nil
	}
	if addr, ok := fpHostsTable[lower]; ok {
		return addr, nil
	}
	if lower == "localhost" {
		return fpLoopbackIPv4, nil
	}
	return netip.Addr{}, nil
}

func fpStoreDNS(host string, ip netip.Addr, expires int64) {
	fpDNSCache.StoreWithTTL(host, &fpDNSEntry{ip: ip, expires: expires}, time.Duration(dnsMaxTTLNano))
}

func fpStoreDNSAnswer(host string, ip netip.Addr, ttl uint32, now int64) {
	ttlNano := min(max(int64(ttl)*int64(time.Second), dnsMinTTLNano), dnsMaxTTLNano)
	fpStoreDNS(host, ip, now+ttlNano)
}

func (l *beLoop) startResolve(c *backendConn, ex *Exchange) error {
	host, _, err := splitAuthority(ex.key.authority, "http")
	if err != nil {
		return errFPBadAuthority
	}
	host = strings.ToLower(host)
	if !fpValidDNSName(host) {
		return errFPDNSFailed
	}
	if e, ok := fpDNSCache.Load(host); ok && l.nowNano() < e.expires {
		if !e.ip.IsValid() {
			return errFPDNSFailed
		}
		return l.dialBackend(c, e.ip, ex.port)
	}
	fpDNSConfigOnce.Do(fpLoadDNSConfig)
	c.state = connResolving
	if querier := l.dnsInflight[host]; querier != nil {
		c.dns = &fpDNSQuery{host: host, port: ex.port, deadline: fpNoDeadline}
		querier.dns.waiters = append(querier.dns.waiters, c)
		return nil
	}
	c.dns = &fpDNSQuery{host: host, port: ex.port, qtype: dnsTypeA}
	l.dnsInflight[host] = c
	l.dnsAttempt(c)
	return nil
}

func (l *beLoop) dnsDetach(c *backendConn) []*backendConn {
	q := c.dns
	if l.dnsInflight[q.host] != c {
		return nil
	}
	delete(l.dnsInflight, q.host)
	waiters := q.waiters
	q.waiters = nil
	return waiters
}

func (l *beLoop) dnsAbandon(c *backendConn) {
	waiters := l.dnsDetach(c)
	for i, w := range waiters {
		if w.state != connResolving {
			continue
		}
		w.dns.server, w.dns.qtype = c.dns.server, c.dns.qtype
		w.dns.waiters = waiters[i+1:]
		l.dnsInflight[w.dns.host] = w
		l.dnsAttempt(w)
		return
	}
}

func (l *beLoop) dnsFail(c *backendConn, err error) {
	waiters := l.dnsDetach(c)
	l.closeConn(c, err)
	for _, w := range waiters {
		if w.state == connResolving {
			l.closeConn(w, err)
		}
	}
}

func (l *beLoop) sweepDNSWaiters(c *backendConn, now int64) {
	for _, w := range c.dns.waiters {
		if w.state == connResolving {
			l.sweepConn(w, now)
		}
	}
}

func (l *beLoop) dnsAttempt(c *backendConn) {
	q := c.dns
	for q.server < len(fpDNSServers) {
		if l.sendDNSQuery(c) == nil {
			return
		}
		q.server++
		q.qtype = dnsTypeA
	}
	l.dnsGiveUp(c)
}

func (l *beLoop) dnsNext(c *backendConn, noAddress bool) {
	q := c.dns
	if noAddress && q.qtype == dnsTypeA {
		q.qtype = dnsTypeAAAA
	} else {
		q.server++
		q.qtype = dnsTypeA
	}
	l.dnsAttempt(c)
}

func (l *beLoop) sendDNSQuery(c *backendConn) error {
	q := c.dns
	server := fpDNSServers[q.server]
	family, dst := upstreamSockaddr(server.Addr(), server.Port())
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return err
	}
	l.releaseSocket(c)
	if err := l.adoptSocket(c, fd, dnsSocketEvents); err != nil {
		return err
	}
	q.id = fpDNSQueryID()
	if err := unix.Sendto(fd, appendDNSQuery(nil, q.id, q.host, q.qtype), 0, dst); err != nil {
		return err
	}
	q.deadline = l.nowNano() + dnsAttemptTimeoutNano
	return nil
}

func (l *beLoop) dnsReadable(c *backendConn) {
	for c.state == connResolving {
		n, from, err := unix.Recvfrom(c.fd, l.scratch[:dnsMaxDatagram], 0)
		if err == unix.EAGAIN {
			return
		}
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			l.dnsNext(c, false)
			return
		}
		q := c.dns
		if !fpDNSFromServer(from, fpDNSServers[q.server]) {
			continue
		}
		addr, ttl, perr := fpParseDNSResponse(l.scratch[:n], q.id, q.qtype, q.host)
		switch perr {
		case nil:
			fpStoreDNSAnswer(q.host, addr, ttl, l.nowNano())
			l.dnsResolved(c, addr)
			return
		case errFPDNSUnrelated:
			continue
		default:
			l.dnsNext(c, perr == errFPDNSNoAddress)
			return
		}
	}
}

func (l *beLoop) dnsResolved(c *backendConn, addr netip.Addr) {
	port := c.dns.port
	waiters := l.dnsDetach(c)
	c.dns = nil
	l.releaseSocket(c)
	if err := l.dialBackend(c, addr, port); err != nil {
		l.closeConn(c, err)
	}
	for _, w := range waiters {
		if w.state == connResolving {
			l.dnsResolved(w, addr)
		}
	}
}

func (l *beLoop) dnsGiveUp(c *backendConn) {
	host := c.dns.host
	retryAfter := l.nowNano() + dnsNegativeTTLNano
	if e, ok := fpDNSCache.Load(host); ok && e.ip.IsValid() {
		fpStoreDNS(host, e.ip, retryAfter)
		l.dnsResolved(c, e.ip)
		return
	}
	fpStoreDNS(host, netip.Addr{}, retryAfter)
	l.dnsFail(c, errFPDNSFailed)
}

func fpDNSQueryID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return uint16(b[0])<<8 | uint16(b[1])
}

func fpDNSFromServer(from unix.Sockaddr, server netip.AddrPort) bool {
	switch sa := from.(type) {
	case *unix.SockaddrInet4:
		return server.Addr().Is4() && sa.Addr == server.Addr().As4() && sa.Port == int(server.Port())
	case *unix.SockaddrInet6:
		return server.Addr().Is6() && sa.Addr == server.Addr().As16() && sa.Port == int(server.Port())
	}
	return false
}

func fpValidDNSName(host string) bool {
	if host == "" || len(host) > dnsMaxNameLen {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > dnsMaxLabelLen {
			return false
		}
	}
	return true
}

func appendDNSQuery(dst []byte, id uint16, host string, qtype uint16) []byte {
	dst = append(dst, byte(id>>8), byte(id), dnsFlagsRecursionDesired, 0, 0, 1, 0, 0, 0, 0, 0, 1)
	for _, label := range strings.Split(host, ".") {
		dst = append(dst, byte(len(label)))
		dst = append(dst, label...)
	}
	dst = append(dst, 0, byte(qtype>>8), byte(qtype), 0, dnsClassIN)
	return append(dst, 0, 0, dnsTypeOPT, byte(dnsEDNSPayloadSize>>8), byte(dnsEDNSPayloadSize&0xff), 0, 0, 0, 0, 0, 0)
}

func fpParseDNSResponse(b []byte, wantID, qtype uint16, host string) (netip.Addr, uint32, error) {
	if len(b) < dnsHeaderLen || uint16(b[0])<<8|uint16(b[1]) != wantID || b[2]&dnsFlagResponse == 0 || b[2]&dnsOpcodeMask != 0 {
		return netip.Addr{}, 0, errFPDNSUnrelated
	}
	qd := int(b[4])<<8 | int(b[5])
	an := int(b[6])<<8 | int(b[7])
	if qd != 1 {
		return netip.Addr{}, 0, errFPDNSUnrelated
	}
	qname, pos := fpReadDNSName(b, dnsHeaderLen)
	if pos < 0 || pos+dnsQuestionFixedLen > len(b) || qname != host ||
		uint16(b[pos])<<8|uint16(b[pos+1]) != qtype || uint16(b[pos+2])<<8|uint16(b[pos+3]) != dnsClassIN {
		return netip.Addr{}, 0, errFPDNSUnrelated
	}
	pos += dnsQuestionFixedLen
	if b[3]&dnsRcodeMask != 0 {
		return netip.Addr{}, 0, errFPDNSFailed
	}
	var chain [dnsMaxCNAMEChain]string
	chain[0] = host
	links := 1
	for i := 0; i < an; i++ {
		owner, next := fpReadDNSName(b, pos)
		if next < 0 || next+dnsRecordFixedLen > len(b) {
			return netip.Addr{}, 0, errFPDNSFailed
		}
		rtype := uint16(b[next])<<8 | uint16(b[next+1])
		class := uint16(b[next+2])<<8 | uint16(b[next+3])
		ttl := uint32(b[next+4])<<24 | uint32(b[next+5])<<16 | uint32(b[next+6])<<8 | uint32(b[next+7])
		rdlen := int(b[next+8])<<8 | int(b[next+9])
		rdata := next + dnsRecordFixedLen
		if rdata+rdlen > len(b) {
			return netip.Addr{}, 0, errFPDNSFailed
		}
		pos = rdata + rdlen
		if class != dnsClassIN || !fpDNSChainHas(chain[:links], owner) {
			continue
		}
		if rtype == dnsTypeCNAME && links < len(chain) {
			target, end := fpReadDNSName(b, rdata)
			if end < 0 || end > pos {
				return netip.Addr{}, 0, errFPDNSFailed
			}
			chain[links] = target
			links++
			continue
		}
		if rtype == qtype {
			if addr, ok := netip.AddrFromSlice(b[rdata:pos]); ok && (rtype == dnsTypeA) == addr.Is4() {
				return addr.Unmap(), ttl, nil
			}
		}
	}
	if b[2]&dnsFlagTruncated != 0 {
		return netip.Addr{}, 0, errFPDNSFailed
	}
	return netip.Addr{}, 0, errFPDNSNoAddress
}

func fpDNSChainHas(chain []string, name string) bool {
	for _, link := range chain {
		if link == name {
			return true
		}
	}
	return false
}

func fpReadDNSName(b []byte, pos int) (string, int) {
	var name []byte
	next := -1
	for hops := 0; pos < len(b); {
		labelLen := int(b[pos])
		switch {
		case labelLen == 0:
			if next < 0 {
				next = pos + 1
			}
			return string(name), next
		case labelLen&dnsPointerMask == dnsPointerMask:
			if pos+1 >= len(b) || hops == dnsMaxPointerHops {
				return "", -1
			}
			if next < 0 {
				next = pos + 2
			}
			pos = (labelLen&^dnsPointerMask)<<8 | int(b[pos+1])
			hops++
		case labelLen&dnsPointerMask != 0:
			return "", -1
		default:
			if pos+1+labelLen > len(b) || len(name)+1+labelLen > dnsMaxNameLen+1 {
				return "", -1
			}
			if len(name) > 0 {
				name = append(name, '.')
			}
			for _, ch := range b[pos+1 : pos+1+labelLen] {
				name = append(name, asciiLower[ch])
			}
			pos += 1 + labelLen
		}
	}
	return "", -1
}

func splitAuthority(authority, scheme string) (string, uint16, error) {
	port := 80
	if scheme == "https" {
		port = 443
	}
	host, portStr, hasPort := authority, "", false
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return "", 0, errFPBadAuthority
		}
		host = authority[1:end]
		if rest := authority[end+1:]; rest != "" {
			if rest[0] != ':' {
				return "", 0, errFPBadAuthority
			}
			portStr, hasPort = rest[1:], true
		}
	} else if strings.Count(authority, ":") == 1 {
		host, portStr, hasPort = strings.Cut(authority, ":")
	}
	if hasPort {
		p, err := strconv.Atoi(portStr)
		if err != nil || p <= 0 || p > 65535 {
			return "", 0, errFPBadAuthority
		}
		port = p
	}
	if host == "" {
		return "", 0, errFPBadAuthority
	}
	return host, uint16(port), nil
}
