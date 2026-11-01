//go:build linux && amd64

package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

const handshakeRecordDomain = "fragment.test"

func handshakeRecordFixture(t testing.TB, large bool, usage x509.ExtKeyUsage) *ocspFixture {
	t.Helper()
	ca := newTestCA(t, "fragment issuer")
	names := []string{handshakeRecordDomain}
	if large {
		for i := 0; i < 512; i++ {
			names = append(names, fmt.Sprintf("fragment-%03d.padding.fragment.test", i))
		}
	}
	now := wallNow()
	leaf := ca.issue(t, leafSpec{cn: handshakeRecordDomain, dnsNames: names, usage: usage, notBefore: now.Add(-time.Hour), notAfter: now.Add(time.Hour)})
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if large && len(parsed.Raw) <= 16384 {
		t.Fatalf("large leaf contains only %d bytes", len(parsed.Raw))
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return &ocspFixture{ca: ca, leafCert: parsed,
		chainPEM: append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parsed.Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})...),
		keyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
}

func handshakeRecordServer(t *testing.T, fixture *ocspFixture, configure func(*Config), staple []byte) *testServer {
	t.Helper()
	cfg := Config{Addr: freeLoopbackAddr(t), HTTPAddr: "-", Listeners: 1, MaxConnsPerIP: -1, DisableOCSPStapling: true}
	if configure != nil {
		configure(&cfg)
	}
	server := New(cfg)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), harnessIOTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	})
	if err := server.AddCert(handshakeRecordDomain, fixture.chainPEM, fixture.keyPEM); err != nil {
		t.Fatal(err)
	}
	if staple != nil {
		if err := server.certStore.Lookup(handshakeRecordDomain).SetOCSPStaple(staple); err != nil {
			t.Fatal(err)
		}
	}
	server.Router.GET("/", func(req *Request, resp *Response) {
		who := "none"
		if certs := req.TLSPeerCertificates(); len(certs) > 0 {
			digest := sha256.New()
			for _, cert := range certs {
				digest.Write(cert.Raw)
			}
			who = fmt.Sprintf("%x", digest.Sum(nil))
		}
		resp.Status(200).String(who)
	})
	server.ensureTLSRuntime()
	result := make(chan error, 1)
	go func() { result <- server.ListenAndServeEpollTLS(cfg.Addr) }()
	waitFor(t, harnessIOTimeout, func() bool {
		select {
		case err := <-result:
			t.Fatalf("listener failed: %v", err)
		default:
		}
		probe, err := net.DialTimeout("tcp4", cfg.Addr, harnessPollInterval)
		if err != nil {
			return false
		}
		_ = probe.Close()
		return true
	})
	return &testServer{srv: server, addr: cfg.Addr, domain: handshakeRecordDomain, tls: true}
}

type handshakeWireCapture struct {
	net.Conn
	mu    sync.Mutex
	wire  []byte
	limit int
}

func (c *handshakeWireCapture) Read(dst []byte) (int, error) {
	n, err := c.Conn.Read(dst)
	c.mu.Lock()
	if len(c.wire)+n <= c.limit {
		c.wire = append(c.wire, dst[:n]...)
	}
	c.mu.Unlock()
	return n, err
}

func (c *handshakeWireCapture) snapshot() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.wire)
}

func handshakeRecordGet(t *testing.T, ts *testServer, cfg *tls.Config, fixture *ocspFixture, wantWho string) *tls.ConnectionState {
	t.Helper()
	var capture *handshakeWireCapture
	transport := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: cfg.NextProtos[0] == "h2", DisableKeepAlives: true}
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		capture = &handshakeWireCapture{Conn: raw, limit: 4*len(fixture.chainPEM) + 8*MaxRecordSize}
		conn := tls.Client(capture, cfg.Clone())
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: harnessIOTimeout}
	response, err := client.Get(ts.url("/"))
	if err != nil {
		if capture != nil && cfg.MinVersion == tls.VersionTLS12 {
			wire := capture.snapshot()
			var plaintext []byte
			var declaredCertificate, firstCertificate int
			for len(wire) >= 5 {
				size := int(wire[3])<<8 | int(wire[4])
				if len(wire) < 5+size {
					break
				}
				body := wire[5 : 5+size]
				if wire[0] == 22 {
					plaintext = append(plaintext, body...)
					if len(body) >= 4 && body[0] == 11 {
						declaredCertificate, firstCertificate = readU24(body[1:4])+4, size
					}
				}
				wire = wire[5+size:]
			}
			if declaredCertificate > firstCertificate && firstCertificate == 16384 && !bytes.Contains(plaintext, fixture.leafCert.Raw) {
				t.Logf("captured TLS1.2 truncation: declared Certificate=%d first fragment=%d full plaintext flight=%d; configured %d-byte leaf absent", declaredCertificate, firstCertificate, len(plaintext), len(fixture.leafCert.Raw))
			}
		}
		t.Fatalf("trusted %s %s handler request: %v", tls.VersionName(cfg.MinVersion), cfg.NextProtos[0], err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || string(body) != wantWho {
		t.Fatalf("handler response status=%d body=%q", response.StatusCode, body)
	}
	wantProto := 1
	if cfg.NextProtos[0] == "h2" {
		wantProto = 2
	}
	if response.ProtoMajor != wantProto || response.TLS == nil || response.TLS.Version != cfg.MinVersion || response.TLS.NegotiatedProtocol != cfg.NextProtos[0] {
		t.Fatalf("protocol=%s TLS=%v", response.Proto, response.TLS != nil)
	}
	state := response.TLS
	if len(state.PeerCertificates) != 2 || !bytes.Equal(state.PeerCertificates[0].Raw, fixture.leafCert.Raw) || !bytes.Equal(state.PeerCertificates[1].Raw, fixture.ca.cert.Raw) {
		t.Fatal("peer chain identity or order differs from the configured chain")
	}
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) != 2 || !bytes.Equal(state.VerifiedChains[0][0].Raw, fixture.leafCert.Raw) || !bytes.Equal(state.VerifiedChains[0][1].Raw, fixture.ca.cert.Raw) {
		t.Fatal("trusted chain was not verified")
	}
	return state
}

func handshakeRecordClient(fixture *ocspFixture, version uint16, alpn string) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(fixture.ca.cert)
	return &tls.Config{RootCAs: roots, ServerName: handshakeRecordDomain, MinVersion: version, MaxVersion: version, NextProtos: []string{alpn}}
}

func TestTLSLargeCertificateFlight(t *testing.T) {
	fixture := handshakeRecordFixture(t, true, x509.ExtKeyUsageServerAuth)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, alpn := range []string{"http/1.1", "h2"} {
			t.Run(tls.VersionName(version)+"/"+strings.ReplaceAll(alpn, "/", "-"), func(t *testing.T) {
				ts := handshakeRecordServer(t, fixture, nil, nil)
				handshakeRecordGet(t, ts, handshakeRecordClient(fixture, version, alpn), fixture, "none")
			})
		}
	}
}

func handshakeRecordNext(t testing.TB, wire []byte, wantType byte, maxPayload int) (body, rest []byte) {
	t.Helper()
	if len(wire) < 5 {
		t.Fatal("truncated record header")
	}
	length := int(wire[3])<<8 | int(wire[4])
	if wire[0] != wantType || wire[1] != 3 || wire[2] != 3 || length == 0 || length > maxPayload || length > len(wire)-5 {
		t.Fatalf("invalid record framing: type=%d length=%d remaining=%d maximum=%d", wire[0], length, len(wire)-5, maxPayload)
	}
	return wire[5 : 5+length], wire[5+length:]
}

func handshakeRecord13Decode(t testing.TB, reader *TrafficAEAD, wire []byte, innerType byte) ([]byte, int) {
	t.Helper()
	var content []byte
	count := 0
	for len(wire) > 0 {
		var encrypted []byte
		encrypted, wire = handshakeRecordNext(t, wire, 23, 16384+256)
		plain, err := reader.Decrypt(bytes.Clone(encrypted))
		if err != nil {
			t.Fatalf("record %d authentication: %v", count, err)
		}
		if len(plain) > 16385 || len(plain) < 2 || plain[len(plain)-1] != innerType {
			t.Fatalf("record %d inner plaintext length=%d or content type is invalid", count, len(plain))
		}
		content = append(content, plain[:len(plain)-1]...)
		count++
	}
	return content, count
}

func TestTLSSessionTicketRecordFragmentation(t *testing.T) {
	for _, large := range []bool{false, true} {
		fixture := handshakeRecordFixture(t, large, x509.ExtKeyUsageClientAuth)
		chain := [][]byte{fixture.leafCert.Raw, fixture.ca.cert.Raw}
		encoded := encodeCertChain(chain)
		if large && (len(encoded) <= 16384 || len(encoded)+8 >= maxHandshakeMessageLen) {
			t.Fatalf("large accepted client identity has invalid fixture size %d", len(encoded))
		}
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			t.Run(fmt.Sprintf("%s/large=%t", tls.VersionName(version), large), func(t *testing.T) {
				server := New(Config{})
				var message []byte
				if version == tls.VersionTLS13 {
					cs := FindSuiteByID(0x1301)
					secret := bytes.Repeat([]byte{7}, cs.HashLen)
					writer := tlsEpollFixAEAD(t, cs, secret)
					reader := tlsEpollFixAEAD(t, cs, secret)
					pending := newPendingTicket(cs, secret, secret, handshakeRecordDomain, "http/1.1", chain)
					conn := &epollConn{appWriter: writer, ticket: pending}
					conn.sendSessionTicket(server)
					var records int
					message, records = handshakeRecord13Decode(t, reader, conn.writeBuf, 22)
					if writer.seq != uint64(records) || reader.seq != uint64(records) || conn.ticket != nil {
						t.Fatal("ticket records did not consume one sequence each and release the pending ticket")
					}
					if large && records < 2 {
						t.Fatal("large ticket did not span encrypted records")
					}
					continuation := conn.sealTLSAppData(nil, []byte("after ticket"))
					plain, appRecords := handshakeRecord13Decode(t, reader, continuation, 23)
					if string(plain) != "after ticket" || appRecords != 1 || writer.seq != reader.seq || writer.seq != uint64(records+1) {
						t.Fatal("application record did not continue the ticket's application-key sequence")
					}
				} else {
					writer, reader := newTestTLS12Pair(t)
					st := &tls12State{suite: &tls12Suites[0], writer: writer, master: bytes.Repeat([]byte{8}, 48), peerChain: chain, issueTicket: true, transcript: tls12Suites[0].newHash()}
					conn := &epollConn{tls12: st, selectedALPN: "http/1.1"}
					wire := conn.appendTLS12ServerFinish(server, nil)
					records := 0
					for len(wire) > 0 && wire[0] == 22 {
						var payload []byte
						payload, wire = handshakeRecordNext(t, wire, 22, 16384)
						message = append(message, payload...)
						records++
					}
					ccs, rest := handshakeRecordNext(t, wire, 20, 16384)
					if !bytes.Equal(ccs, []byte{1}) || !st.serverCCSSent || writer.seq != 1 {
						t.Fatal("ticket fragmentation changed CCS placement or protected Finished sequence")
					}
					if len(rest) < 5 || len(rest) != 5+(int(rest[3])<<8|int(rest[4])) {
						t.Fatal("protected Finished has trailing or missing record bytes")
					}
					typ, finished, ok := reader.open(rest)
					if !ok || typ != 22 || len(finished) != 16 || finished[0] != 20 || reader.seq != 1 {
						t.Fatal("protected Finished after the plaintext ticket is invalid")
					}
					h := st.suite.newHash()
					h.Write(message)
					if !bytes.Equal(finished[4:], tls12Finished(st.suite.newHash, st.master, "server finished", h.Sum(nil))) {
						t.Fatal("Finished transcript does not contain the complete logical ticket exactly once")
					}
					if large && records < 2 {
						t.Fatal("large ticket did not span plaintext records")
					}
					continuation := buildTLS12AppDataRecords(nil, writer, []byte("after ticket"))
					appType, appPlain, appOK := reader.open(continuation)
					if !appOK || appType != 23 || string(appPlain) != "after ticket" || writer.seq != 2 || reader.seq != 2 {
						t.Fatal("application data did not follow the ticket and Finished in the expected epoch")
					}
				}
				if len(message) < 4 {
					t.Fatalf("truncated ticket header: %d bytes", len(message))
				}
				if message[0] != 4 || readU24(message[1:4]) != len(message)-4 || large && len(message) <= 16384 {
					t.Fatalf("ticket message was truncated: declared=%d actual=%d", readU24(message[1:4])+4, len(message))
				}
				body := message[4:]
				ticketOffset := 4
				if version == tls.VersionTLS13 {
					if len(body) < 9 || int(body[8])+9 > len(body) {
						t.Fatal("invalid ticket nonce field")
					}
					ticketOffset = 9 + int(body[8])
				}
				if ticketOffset+2 > len(body) {
					t.Fatal("missing ticket length")
				}
				ticketLen := int(body[ticketOffset])<<8 | int(body[ticketOffset+1])
				ticketOffset += 2
				if ticketLen > maxTicketWireLen || ticketOffset+ticketLen > len(body) || large && ticketLen <= 16384 {
					t.Fatalf("actual producer ticket length %d violates fixture preconditions", ticketLen)
				}
				ticket, ok := server.tickets.open(body[ticketOffset : ticketOffset+ticketLen])
				if !ok || !bytes.Equal(ticket.clientCert, encoded) || ticket.tlsVersion != version {
					t.Fatal("reassembled ticket lost authenticated client identity or protocol version")
				}
				t.Logf("identity=%d ticket=%d message=%d", len(encoded), ticketLen, len(message))
			})
		}
	}
}

func TestTLSLargeClientIdentityTicketResumption(t *testing.T) {
	serverFixture := handshakeRecordFixture(t, false, x509.ExtKeyUsageServerAuth)
	clientFixture := handshakeRecordFixture(t, true, x509.ExtKeyUsageClientAuth)
	clientPair, err := tls.X509KeyPair(clientFixture.chainPEM, clientFixture.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	encoded := encodeCertChain(clientPair.Certificate)
	digest := sha256.New()
	for _, der := range clientPair.Certificate {
		digest.Write(der)
	}
	wantIdentity := fmt.Sprintf("%x", digest.Sum(nil))
	if len(encoded) <= 16384 || len(encoded)+8 >= maxHandshakeMessageLen {
		t.Fatalf("client identity size %d does not reach the ticket boundary within the accepted message cap", len(encoded))
	}
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, alpn := range []string{"http/1.1", "h2"} {
			t.Run(tls.VersionName(version)+"/"+strings.ReplaceAll(alpn, "/", "-"), func(t *testing.T) {
				roots := x509.NewCertPool()
				roots.AddCert(clientFixture.ca.cert)
				ts := handshakeRecordServer(t, serverFixture, func(cfg *Config) {
					cfg.TLSClientAuth = RequireAndVerifyClientCert
					cfg.TLSClientCAs = roots
				}, nil)
				cfg := handshakeRecordClient(serverFixture, version, alpn)
				cfg.Certificates = []tls.Certificate{clientPair}
				cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
				if state := handshakeRecordGet(t, ts, cfg, serverFixture, wantIdentity); state.DidResume {
					t.Fatal("initial authenticated connection unexpectedly resumed")
				}
				session, ok := cfg.ClientSessionCache.Get(handshakeRecordDomain)
				if !ok {
					t.Fatal("first connection did not deliver a reusable ticket")
				}
				ticketBytes, _, err := session.ResumptionState()
				if err != nil || len(ticketBytes) <= 16384 || len(ticketBytes) > maxTicketWireLen {
					t.Fatalf("actual network ticket length=%d error=%v", len(ticketBytes), err)
				}
				ticket, ok := ts.srv.tickets.open(ticketBytes)
				if !ok || !bytes.Equal(ticket.clientCert, encoded) {
					t.Fatal("network ticket did not retain the accepted client identity")
				}
				if state := handshakeRecordGet(t, ts, cfg, serverFixture, wantIdentity); !state.DidResume {
					t.Fatal("new connection fell back to a full handshake instead of resuming")
				}
				t.Logf("accepted client identity=%d network ticket=%d", len(encoded), len(ticketBytes))
			})
		}
	}
}

func handshakeRecordPattern(size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(i*31 + i/251)
	}
	return out
}

func TestTLS13HandshakeRecordBoundaries(t *testing.T) {
	for _, cs := range SupportedSuites {
		for _, size := range []int{1, 16382, 16383, 16384, 16385, 32766, 32767, 32768, 32769, 65535, 65536, 65537} {
			for _, typ := range []byte{22, 23} {
				t.Run(fmt.Sprintf("suite=%x/size=%d/type=%d", cs.ID, size, typ), func(t *testing.T) {
					secret := bytes.Repeat([]byte{11}, cs.HashLen)
					writer := tlsEpollFixAEAD(t, &cs, secret)
					reader := tlsEpollFixAEAD(t, &cs, secret)
					inner := append(handshakeRecordPattern(size), typ)
					original := bytes.Clone(inner)
					prefix := []byte("prefix")
					wire := appendTLSInnerRecords(bytes.Clone(prefix), writer, inner)
					if !bytes.Equal(wire[:len(prefix)], prefix) || !bytes.Equal(inner, original) {
						t.Fatal("prefix or source content was modified")
					}
					got, records := handshakeRecord13Decode(t, reader, wire[len(prefix):], typ)
					wantRecords := (size + 16382) / 16383
					if !bytes.Equal(got, original[:size]) || records != wantRecords || writer.seq != uint64(wantRecords) || reader.seq != writer.seq {
						t.Fatalf("content/sequence loss: size=%d records=%d expected=%d writer=%d reader=%d", size, records, wantRecords, writer.seq, reader.seq)
					}
					if size <= 16383 {
						single := appendTLSInnerRecord(bytes.Clone(prefix), tlsEpollFixAEAD(t, &cs, secret), original)
						if !bytes.Equal(wire, single) {
							t.Fatal("record that fits one TLS record changed its wire bytes")
						}
					}
				})
			}
		}
	}
}

func TestTLS12HandshakeRecordBoundaries(t *testing.T) {
	for _, size := range []int{1, 16382, 16383, 16384, 16385, 32766, 32767, 32768, 32769, 65535, 65536, 65537} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			payload := handshakeRecordPattern(size)
			original := bytes.Clone(payload)
			prefix := []byte("prefix")
			wire := AppendRecord(bytes.Clone(prefix), 22, payload)
			if !bytes.Equal(wire[:len(prefix)], prefix) || !bytes.Equal(payload, original) {
				t.Fatal("prefix or source content was modified")
			}
			wire = wire[len(prefix):]
			var got []byte
			records := 0
			for len(wire) > 0 {
				var content []byte
				content, wire = handshakeRecordNext(t, wire, 22, 16384)
				got = append(got, content...)
				records++
			}
			if !bytes.Equal(got, original) || records != (size+16383)/16384 {
				t.Fatalf("fragmented handshake lost content: input=%d output=%d records=%d", size, len(got), records)
			}
		})
	}
	payload := []byte("small handshake")
	want := append([]byte{22, 3, 3, 0, 15}, payload...)
	if got := AppendRecord(nil, 22, payload); !bytes.Equal(got, want) {
		t.Fatal("single plaintext handshake changed its wire bytes")
	}
	if got := AppendRecord(nil, 20, nil); !bytes.Equal(got, []byte{20, 3, 3, 0, 0}) {
		t.Fatal("empty record changed its wire bytes")
	}
}

func TestTLSLargeCertificateFlightVariants(t *testing.T) {
	fixture := handshakeRecordFixture(t, true, x509.ExtKeyUsageServerAuth)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, variant := range []string{"request_client_cert", "stapled"} {
			t.Run(tls.VersionName(version)+"/"+variant, func(t *testing.T) {
				var staple []byte
				if variant == "stapled" {
					padding := 16384 - 512
					for attempt := 0; attempt < 4; attempt++ {
						response := fixture.template(ocsp.Good, wallNow().Add(time.Hour))
						response.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Value: bytes.Repeat([]byte{5}, padding)}}
						staple = fixture.sign(t, response)
						if len(staple) > 16376 && len(staple) <= maxOCSPResponseLen {
							break
						}
						padding += 16380 - len(staple)
					}
					if len(staple) <= 16376 || len(staple) > maxOCSPResponseLen {
						t.Fatalf("OCSP fixture size %d must fit the existing response cap and exceed one record after handshake framing", len(staple))
					}
				}
				ts := handshakeRecordServer(t, fixture, func(cfg *Config) {
					if variant == "request_client_cert" {
						cfg.TLSClientAuth = RequestClientCert
					}
				}, staple)
				state := handshakeRecordGet(t, ts, handshakeRecordClient(fixture, version, "http/1.1"), fixture, "none")
				if staple != nil && !bytes.Equal(state.OCSPResponse, staple) {
					t.Fatal("large configured OCSP staple was truncated or changed")
				}
			})
		}
	}
}
