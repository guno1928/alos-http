package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

type exhaustionTransport struct{ frames [][]byte }

func (*exhaustionTransport) start(*backendConn) error        { return nil }
func (*exhaustionTransport) feed(*backendConn, []byte) error { return nil }
func (*exhaustionTransport) negotiatedALPN() string          { return "h2" }
func (transport *exhaustionTransport) wrapOut(_ *backendConn, data []byte) error {
	transport.frames = append(transport.frames, bytes.Clone(data))
	return nil
}
func exhaustionFixture() (*beLoop, *backendConn, *exhaustionTransport) {
	loop := &beLoop{cfg: &fpConfig{MaxHeaderBytes: 65536, MaxResponseBody: 1024}, h2conns: make(map[poolKey]*backendConn)}
	transport := &exhaustionTransport{}
	conn := &backendConn{fd: -1, be: loop, state: connReady, key: poolKey{h2: true, authority: "exhaustion.example.test:80"}, transport: transport}
	conn.h2init()
	loop.h2conns[conn.key] = conn
	loop.liveConns = 1
	return loop, conn, transport
}
func exhaustionExchange(key poolKey) *Exchange {
	return &Exchange{req: &fpRequest{Method: "POST", Path: "/identity", Authority: key.authority}, done: make(chan struct{}), key: key, deadline: turbo.UnixNano() + int64(time.Hour), port: 80}
}
func exhaustionReplacement(loop *beLoop, old *backendConn) *backendConn {
	replacement := &backendConn{fd: -1, be: loop, state: connHandshaking, key: old.key, transport: &exhaustionTransport{}}
	replacement.h2init()
	loop.h2conns[old.key] = replacement
	loop.liveConns++
	return replacement
}
func exhaustionWantDone(t *testing.T, ex *Exchange, expected error) {
	t.Helper()
	select {
	case <-ex.done:
	default:
		t.Fatal("exchange did not finish")
	}
	if !ex.finished || ex.err != expected {
		t.Fatalf("finished=%v error=%v want=%v", ex.finished, ex.err, expected)
	}
}
func TestFPH2ExhaustionFinalLegalIDAndPendingIdentity(t *testing.T) {
	loop, old, transport := exhaustionFixture()
	replacement := exhaustionReplacement(loop, old)
	old.h2.nextID = 0x7fffffff
	first := exhaustionExchange(old.key)
	first.req.Method = "GET"
	pending := exhaustionExchange(old.key)
	source := bytes.NewReader([]byte("body"))
	body := &upstreamBody{src: source, length: 4, want: make(chan struct{}, 1)}
	pending.body = body
	pending.retried = true
	deadline := pending.deadline
	old.h2.pending = []*Exchange{first, pending}
	loop.h2proto.flushPending(old)
	if old.h2.nextID != 0x80000001 || len(old.h2.streams) != 1 || old.h2.streams[0x7fffffff] == nil || first.bc != old || first.h2st.id != 0x7fffffff {
		t.Fatalf("last legal allocation next=%#x streams=%d", old.h2.nextID, len(old.h2.streams))
	}
	if len(transport.frames) != 1 || transport.frames[0][3] != h2FrameHeaders || binary.BigEndian.Uint32(transport.frames[0][5:9]) != 0x7fffffff {
		t.Fatalf("old frames=%x", transport.frames)
	}
	if len(old.h2.pending) != 0 || len(replacement.h2.pending) != 1 || replacement.h2.pending[0] != pending || pending.bc != nil || pending.h2st != nil || pending.body != body || pending.body.src != source || source.Len() != 4 || pending.body.sent != 0 || pending.body.requested || len(body.want) != 0 || pending.req.Method != "POST" || pending.deadline != deadline || !pending.retried || pending.replayable || pending.wroteRequest || pending.finished {
		t.Fatal("unsent POST/body ownership or flags changed")
	}
	loop.h2proto.flushPending(old)
	if len(transport.frames) != 1 || len(replacement.h2.pending) != 1 || loop.h2conns[old.key] != replacement {
		t.Fatal("repeated retirement changed handoff")
	}
}
func TestFPH2ExhaustionRetiresWithoutPendingOrConcurrency(t *testing.T) {
	for _, queued := range []bool{false, true} {
		t.Run(fmt.Sprint(queued), func(t *testing.T) {
			loop, old, _ := exhaustionFixture()
			old.h2.nextID = 0x80000001
			old.h2.maxConcurrent = 0
			active := exhaustionExchange(old.key)
			old.h2.streams[1] = &h2Stream{id: 1, ex: active}
			active.bc = old
			if queued {
				replacement := exhaustionReplacement(loop, old)
				ex := exhaustionExchange(old.key)
				old.h2.pending = []*Exchange{ex}
				loop.h2proto.flushPending(old)
				if len(replacement.h2.pending) != 1 || replacement.h2.pending[0] != ex {
					t.Fatal("concurrency zero stranded pending")
				}
			} else {
				loop.h2proto.flushPending(old)
				if loop.h2conns[old.key] == old {
					t.Fatal("exhausted connection remained selectable")
				}
			}
			if old.state != connReady || old.h2.streams[1].ex != active || active.finished {
				t.Fatal("retirement canceled active stream")
			}
		})
	}
}
func TestFPH2ExhaustionSkipsFinishedAndExpiresPending(t *testing.T) {
	loop, old, transport := exhaustionFixture()
	replacement := exhaustionReplacement(loop, old)
	old.h2.nextID = 0x80000001
	finished := exhaustionExchange(old.key)
	loop.finish(finished, errFPClientClosed)
	expired := exhaustionExchange(old.key)
	expired.deadline = turbo.UnixNano() - 1
	pending := exhaustionExchange(old.key)
	pending.retried = true
	old.h2.pending = []*Exchange{finished, expired, pending}
	loop.h2proto.flushPending(old)
	exhaustionWantDone(t, finished, errFPClientClosed)
	exhaustionWantDone(t, expired, errFPTimeout)
	if len(replacement.h2.pending) != 1 || replacement.h2.pending[0] != pending || len(old.h2.pending) != 0 || len(transport.frames) != 0 || pending.finished || !pending.retried || pending.req.Method != "POST" || old.state != connClosed || loop.liveConns != 1 {
		t.Fatal("pending handoff/cleanup failed")
	}
}
func TestFPH2ExhaustionActualAdmissionReleasesOldFirst(t *testing.T) {
	loop, old, _ := exhaustionFixture()
	old.h2.nextID = 0x80000001
	loop.liveConns = fpMaxBackendConns
	host := fmt.Sprintf("exhaustion-admission-%d.example.test", turbo.UnixNano())
	if !fpValidDNSName(host) {
		t.Fatal("fixture hostname invalid")
	}
	entry := &fpDNSEntry{expires: turbo.UnixNano() + int64(time.Hour)}
	fpDNSCache.StoreWithTTL(host, entry, time.Hour)
	t.Cleanup(func() { fpDNSCache.Delete(host) })
	if actual, ok := fpDNSCache.Load(host); !ok || actual != entry || actual.ip.IsValid() || actual.expires <= loop.nowNano() {
		t.Fatal("negative DNS fixture absent or expired")
	}
	old.key.authority = host + ":80"
	loop.h2conns = map[poolKey]*backendConn{old.key: old}
	ex := exhaustionExchange(old.key)
	if ex.ip.IsValid() || ex.deadline <= loop.nowNano() {
		t.Fatal("admission fixture can dial or expire")
	}
	old.h2.pending = []*Exchange{ex}
	loop.h2proto.flushPending(old)
	exhaustionWantDone(t, ex, errFPDNSFailed)
	if old.state != connClosed || loop.liveConns != fpMaxBackendConns-1 || len(loop.h2conns) != 0 || len(old.h2.pending) != 0 {
		t.Fatalf("old state=%d count=%d map=%d pending=%d", old.state, loop.liveConns, len(loop.h2conns), len(old.h2.pending))
	}
	loop.h2proto.flushPending(old)
	if loop.liveConns != fpMaxBackendConns-1 {
		t.Fatal("repeat cleanup decremented twice")
	}
}
func TestFPH2ExhaustionPreservesAdmissionCapWithActiveStream(t *testing.T) {
	loop, old, _ := exhaustionFixture()
	old.h2.nextID = 0x80000001
	loop.liveConns = fpMaxBackendConns
	active := exhaustionExchange(old.key)
	old.h2.streams[1] = &h2Stream{id: 1, ex: active}
	pending := exhaustionExchange(old.key)
	old.h2.pending = []*Exchange{pending}
	loop.h2proto.flushPending(old)
	exhaustionWantDone(t, pending, errFPTooManyConns)
	if active.finished || old.state != connReady || loop.liveConns != fpMaxBackendConns || len(old.h2.streams) != 1 {
		t.Fatal("cap enforcement canceled active work or bypassed limit")
	}
}
func TestFPH2ExhaustionEveryTerminalPathClosesOld(t *testing.T) {
	for _, terminal := range []string{"normal", "reset", "peer_reset", "timeout"} {
		for _, goAway := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_goaway_%t", terminal, goAway), func(t *testing.T) {
				loop, old, _ := exhaustionFixture()
				old.h2.nextID = 0x80000001
				ex := exhaustionExchange(old.key)
				ex.bc = old
				stream := &h2Stream{id: 1, ex: ex, status: 200}
				ex.h2st = stream
				old.h2.streams[1] = stream
				loop.h2proto.flushPending(old)
				if old.state != connReady || loop.h2conns[old.key] == old {
					t.Fatal("active retirement failed")
				}
				replacement := exhaustionReplacement(loop, old)
				old.h2.goAway = goAway
				var expected error
				switch terminal {
				case "normal":
					loop.h2proto.finishStream(old, stream)
				case "reset":
					expected = errFPBadResponse
					loop.h2proto.resetStream(old, stream, H2ErrCancel, expected)
				case "peer_reset":
					expected = errFPConnClosed
					loop.h2proto.closeStream(old, 1, expected)
				case "timeout":
					expected = errFPTimeout
					loop.sweepH2(old, ex.deadline+1)
				}
				exhaustionWantDone(t, ex, expected)
				if old.state != connClosed || loop.liveConns != 1 || loop.h2conns[old.key] != replacement || len(old.h2.streams) != 0 {
					t.Fatalf("drain state=%d count=%d streams=%d replacement=%v", old.state, loop.liveConns, len(old.h2.streams), loop.h2conns[old.key] == replacement)
				}
				loop.h2proto.closeStream(old, 1, errFPConnClosed)
				loop.sweepH2(old, ex.deadline+1)
				loop.h2proto.flushPending(old)
				if loop.liveConns != 1 || loop.h2conns[old.key] != replacement {
					t.Fatal("late cleanup damaged replacement/accounting")
				}
			})
		}
	}
}
func TestFPH2ExhaustionClosedFlushDoesNotOpen(t *testing.T) {
	loop, old, transport := exhaustionFixture()
	old.state = connClosed
	ex := exhaustionExchange(old.key)
	old.h2.pending = []*Exchange{ex}
	loop.h2proto.flushPending(old)
	if len(transport.frames) != 0 || ex.bc != nil || ex.h2st != nil || len(old.h2.streams) != 0 {
		t.Fatal("closed connection opened pending exchange")
	}
}

func TestFPH2ExhaustionUnexhaustedGoAwayUnchanged(t *testing.T) {
	loop, old, _ := exhaustionFixture()
	replacement := exhaustionReplacement(loop, old)
	old.h2.goAway = true
	loop.sweepH2(old, loop.nowNano())
	if old.state != connReady || loop.liveConns != 2 || loop.h2conns[old.key] != replacement {
		t.Fatal("unexhausted GOAWAY behavior changed")
	}
}
func TestFPH2ExhaustionPendingRemainsOwnedUntilTransfer(t *testing.T) {
	loop, old, _ := exhaustionFixture()
	replacement := exhaustionReplacement(loop, old)
	old.h2.nextID = 0x80000001
	ex := exhaustionExchange(old.key)
	old.h2.pending = []*Exchange{ex}
	loop.sweepH2(old, loop.nowNano())
	if old.state != connReady || ex.finished || len(old.h2.pending) != 1 {
		t.Fatal("cleanup discarded owned pending work")
	}
	loop.h2proto.flushPending(old)
	if old.state != connClosed || len(replacement.h2.pending) != 1 || replacement.h2.pending[0] != ex {
		t.Fatal("pending transfer failed")
	}
}
