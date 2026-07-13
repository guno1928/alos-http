//go:build linux

package core

import (
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

const (
	dnsPort         = 53
	dnsQueryTimeout = 2
	dnsMinTTLNano   = int64(30e9)
	dnsMaxTTLNano   = int64(300e9)
)

type fpDNSEntry struct {
	ip      [4]byte
	expires int64
}

var (
	fpDNSCache      sync.Map
	fpDNSConfigOnce sync.Once
	fpDNSServers    [][4]byte
	fpHostsTable    map[string][4]byte
)

func parseIPv4(s string) ([4]byte, bool) {
	var ip [4]byte
	part := 0
	val := -1
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '.' {
			if val < 0 || part >= 3 {
				return ip, false
			}
			ip[part] = byte(val)
			part++
			val = -1
			continue
		}
		if ch < '0' || ch > '9' {
			return ip, false
		}
		if val < 0 {
			val = 0
		}
		val = val*10 + int(ch-'0')
		if val > 255 {
			return ip, false
		}
	}
	if val < 0 || part != 3 {
		return ip, false
	}
	ip[3] = byte(val)
	return ip, true
}

func fpLoadDNSConfig() {
	fpHostsTable = make(map[string][4]byte)
	if data, err := os.ReadFile("/etc/hosts"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			ip, ok := parseIPv4(fields[0])
			if !ok {
				continue
			}
			for _, name := range fields[1:] {
				fpHostsTable[strings.ToLower(name)] = ip
			}
		}
	}
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "nameserver" {
				if ip, ok := parseIPv4(fields[1]); ok {
					fpDNSServers = append(fpDNSServers, ip)
				}
			}
		}
	}
	if len(fpDNSServers) == 0 {
		fpDNSServers = append(fpDNSServers, [4]byte{127, 0, 0, 53}, [4]byte{8, 8, 8, 8})
	}
}

func fpResolveIPv4(host string) ([4]byte, error) {
	if ip, ok := parseIPv4(host); ok {
		return ip, nil
	}
	fpDNSConfigOnce.Do(fpLoadDNSConfig)
	lower := strings.ToLower(host)
	if v, ok := fpDNSCache.Load(lower); ok {
		e := v.(fpDNSEntry)
		if turbo.UnixNano() < e.expires {
			return e.ip, nil
		}
	}
	if ip, ok := fpHostsTable[lower]; ok {
		return ip, nil
	}
	if lower == "localhost" {
		return [4]byte{127, 0, 0, 1}, nil
	}
	for _, server := range fpDNSServers {
		ip, ttl, err := fpDNSQueryA(server, lower)
		if err == nil {
			ttlNano := int64(ttl) * int64(1e9)
			if ttlNano < dnsMinTTLNano {
				ttlNano = dnsMinTTLNano
			}
			if ttlNano > dnsMaxTTLNano {
				ttlNano = dnsMaxTTLNano
			}
			fpDNSCache.Store(lower, fpDNSEntry{ip: ip, expires: turbo.UnixNano() + ttlNano})
			return ip, nil
		}
	}
	if v, ok := fpDNSCache.Load(lower); ok {
		return v.(fpDNSEntry).ip, nil
	}
	return [4]byte{}, fpErrDNSFailed
}

func fpDNSQueryA(server [4]byte, host string) ([4]byte, uint32, error) {
	var zero [4]byte
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return zero, 0, err
	}
	defer unix.Close(fd)
	tv := unix.Timeval{Sec: dnsQueryTimeout}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	id := uint16(turbo.Uint32())
	msg := make([]byte, 0, 64)
	msg = append(msg, byte(id>>8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return zero, 0, fpErrDNSFailed
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0, 0, 1, 0, 1)

	dst := &unix.SockaddrInet4{Port: dnsPort}
	dst.Addr = server
	if err := unix.Sendto(fd, msg, 0, dst); err != nil {
		return zero, 0, err
	}

	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return zero, 0, err
	}
	return fpParseDNSResponse(buf[:n], id)
}

func fpParseDNSResponse(b []byte, wantID uint16) ([4]byte, uint32, error) {
	var zero [4]byte
	if len(b) < 12 {
		return zero, 0, fpErrDNSFailed
	}
	if uint16(b[0])<<8|uint16(b[1]) != wantID {
		return zero, 0, fpErrDNSFailed
	}
	qd := int(b[4])<<8 | int(b[5])
	an := int(b[6])<<8 | int(b[7])
	pos := 12
	for i := 0; i < qd; i++ {
		pos = fpSkipDNSName(b, pos)
		pos += 4
		if pos < 0 || pos > len(b) {
			return zero, 0, fpErrDNSFailed
		}
	}
	for i := 0; i < an; i++ {
		pos = fpSkipDNSName(b, pos)
		if pos < 0 || pos+10 > len(b) {
			return zero, 0, fpErrDNSFailed
		}
		rtype := uint16(b[pos])<<8 | uint16(b[pos+1])
		ttl := uint32(b[pos+4])<<24 | uint32(b[pos+5])<<16 | uint32(b[pos+6])<<8 | uint32(b[pos+7])
		rdlen := int(b[pos+8])<<8 | int(b[pos+9])
		pos += 10
		if pos+rdlen > len(b) {
			return zero, 0, fpErrDNSFailed
		}
		if rtype == 1 && rdlen == 4 {
			var ip [4]byte
			copy(ip[:], b[pos:pos+4])
			return ip, ttl, nil
		}
		pos += rdlen
	}
	return zero, 0, fpErrDNSFailed
}

func fpSkipDNSName(b []byte, pos int) int {
	for pos < len(b) {
		l := int(b[pos])
		if l == 0 {
			return pos + 1
		}
		if l&0xC0 == 0xC0 {
			return pos + 2
		}
		pos += 1 + l
	}
	return -1
}

func splitAuthority(authority, scheme string) (string, uint16, error) {
	host := authority
	port := 80
	if scheme == "https" {
		port = 443
	}
	if i := strings.LastIndexByte(authority, ':'); i >= 0 {
		p, err := strconv.Atoi(authority[i+1:])
		if err != nil || p <= 0 || p > 65535 {
			return "", 0, fpErrBadAuthority
		}
		host = authority[:i]
		port = p
	}
	if host == "" {
		return "", 0, fpErrBadAuthority
	}
	return host, uint16(port), nil
}
