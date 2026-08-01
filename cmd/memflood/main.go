package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "target host:port")
	useTLS := flag.Bool("tls", false, "use TLS with certificate verification disabled")
	conns := flag.Int("conns", 64, "number of simultaneous connections")
	declared := flag.Int64("content-length", 100<<20, "declared request body length")
	sendBytes := flag.Int64("send-bytes", 4<<20, "body bytes attempted per connection")
	hold := flag.Duration("hold", 8*time.Second, "time to keep incomplete uploads open")
	flag.Parse()

	if *conns < 1 || *conns > 10000 || *declared < 1 || *sendBytes < 0 || *sendBytes > *declared {
		panic("invalid bounded test parameters")
	}

	start := make(chan struct{})
	var opened, completed, rejected, written atomic.Int64
	var wg sync.WaitGroup
	payload := make([]byte, 32<<10)
	for i := 0; i < *conns; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			var conn net.Conn
			var err error
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			if *useTLS {
				conn, err = tls.DialWithDialer(dialer, "tcp", *addr, &tls.Config{InsecureSkipVerify: true})
			} else {
				conn, err = dialer.Dial("tcp", *addr)
			}
			if err != nil {
				rejected.Add(1)
				return
			}
			defer conn.Close()
			opened.Add(1)
			<-start
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			head := fmt.Sprintf("POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\nX-Forwarded-For: 198.18.%d.%d\r\nConnection: keep-alive\r\n\r\n", *declared, (id/250)%250, id%250+1)
			if _, err = io.WriteString(conn, head); err != nil {
				rejected.Add(1)
				return
			}
			left := *sendBytes
			for left > 0 {
				n := int64(len(payload))
				if left < n {
					n = left
				}
				wn, writeErr := conn.Write(payload[:n])
				written.Add(int64(wn))
				left -= int64(wn)
				if writeErr != nil || wn == 0 {
					rejected.Add(1)
					return
				}
			}
			completed.Add(1)
			time.Sleep(*hold)
		}(i)
	}
	for opened.Load()+rejected.Load() < int64(*conns) {
		time.Sleep(10 * time.Millisecond)
	}
	close(start)
	wg.Wait()
	fmt.Printf("opened=%d wrote=%dMiB full_writes=%d rejected_or_closed=%d\n",
		opened.Load(), written.Load()>>20, completed.Load(), rejected.Load())
}
