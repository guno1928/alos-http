package core

import (
	"testing"
	"time"
)

const timeoutDetachHold = 150 * time.Millisecond

func TestTimeoutDetachedRequestDoesNotShareLazyCaches(t *testing.T) {
	release := make(chan struct{})
	observed := make(chan [2]string, 1)
	handler := Timeout(15 * time.Millisecond)(func(req *Request, resp *Response) {
		<-release
		observed <- [2]string{req.Cookie("session"), req.QueryParam("id")}
		resp.Status(200)
	})

	req := &Request{
		Method:  "GET",
		Path:    "/",
		Query:   "id=first",
		Headers: [][2]string{{"Cookie", "session=alpha"}},
		server:  New(Config{HTTPAddr: "-", LogRequests: false}),
	}
	req.ctx = nil
	if req.Cookie("session") != "alpha" || req.QueryParam("id") != "first" {
		t.Fatal("setup: caches not populated")
	}
	resp := &Response{}
	handler(req, resp)
	if resp.StatusCode != 504 {
		t.Fatalf("status = %d, want 504", resp.StatusCode)
	}

	req.Reset()
	req.Query = "id=second"
	req.Headers = [][2]string{{"Cookie", "session=beta"}}
	_ = req.Cookie("session")
	_ = req.QueryParam("id")

	close(release)
	select {
	case got := <-observed:
		if got[0] != "alpha" || got[1] != "first" {
			t.Fatalf("detached handler observed cookie=%q id=%q after the pooled request was reused for another request; want alpha/first", got[0], got[1])
		}
	case <-time.After(timeoutDetachHold + 2*time.Second):
		t.Fatal("detached handler never finished")
	}
}
