package core

import (
	"os"
	"strconv"
	"time"
)

func (s *Server) startRPSMonitor() {
	go func() {
		var lastReqs uint64

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				current := Stats.TotalReqs.Load()
				rps := current - lastReqs
				lastReqs = current

				var buf [128]byte
				b := buf[:0]
				b = append(b, "[RPS] "...)
				b = strconv.AppendUint(b, rps, 10)
				b = append(b, " req/s | conns="...)
				b = strconv.AppendInt(b, Stats.ActiveConns.Load(), 10)
				b = append(b, " | total="...)
				b = strconv.AppendUint(b, current, 10)
				b = append(b, '\n')
				os.Stdout.Write(b)

			case <-s.done:
				return
			}
		}
	}()
}
