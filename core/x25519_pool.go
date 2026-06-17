package core

import (
	"crypto/rand"
	"runtime"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

type x25519Keypair struct {
	priv [32]byte
	pub  [32]byte
}

func generateX25519Keypair() (x25519Keypair, error) {
	var kp x25519Keypair
	if _, err := rand.Read(kp.priv[:]); err != nil {
		return x25519Keypair{}, err
	}
	curve25519.ScalarBaseMult(&kp.pub, &kp.priv)
	return kp, nil
}

func deriveX25519SharedSecret(priv, peer *[32]byte) ([32]byte, bool) {
	var shared [32]byte
	secret, err := curve25519.X25519(priv[:], peer[:])
	if err != nil {
		return shared, false
	}
	copy(shared[:], secret)
	for i := range secret {
		secret[i] = 0
	}
	return shared, true
}

func (kp *x25519Keypair) zero() {
	for i := range kp.priv {
		kp.priv[i] = 0
		kp.pub[i] = 0
	}
}

type x25519KeyPool struct {
	ch        chan x25519Keypair
	stop      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

func newX25519KeyPool(size int) *x25519KeyPool {
	if size < 1 {
		size = 1
	}
	p := &x25519KeyPool{
		ch:   make(chan x25519Keypair, size),
		stop: make(chan struct{}),
	}
	for len(p.ch) < cap(p.ch) {
		kp, err := generateX25519Keypair()
		if err != nil {
			break
		}
		p.ch <- kp
	}
	workers := runtime.GOMAXPROCS(0) * 2
	if workers < 1 {
		workers = 1
	}
	if workers > 32 {
		workers = 32
	}
	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.fillLoop()
	}
	return p
}

func (p *x25519KeyPool) fillLoop() {
	defer p.wg.Done()
	for {
		kp, err := generateX25519Keypair()
		if err != nil {
			select {
			case <-p.stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		select {
		case p.ch <- kp:
		case <-p.stop:
			kp.zero()
			return
		}
	}
}

func (p *x25519KeyPool) Get() (x25519Keypair, error) {
	select {
	case kp, ok := <-p.ch:
		if ok {
			return kp, nil
		}
	default:
	}
	return generateX25519Keypair()
}

func (p *x25519KeyPool) Close() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() {
		close(p.stop)
		p.wg.Wait()
		close(p.ch)
		for kp := range p.ch {
			kp.zero()
		}
	})
}

func x25519KeyPoolSize(cfg Config) int {
	size := cfg.WorkerCount * 128
	if size < 4096 {
		size = cfg.Listeners * 512
	}
	if size < 4096 {
		size = runtime.GOMAXPROCS(0) * 256
	}
	if size < 4096 {
		size = 4096
	}
	if size > 32768 {
		size = 32768
	}
	return size
}
