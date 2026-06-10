package core

import "testing"

// Regression: a lookup path that shares a prefix with registered static routes
// under a wildcard parent (e.g. /dashboard/shop vs /dashboard/shop-editor) must
// fall back to the parent's catch-all with the CORRECT remaining suffix, not the
// whole path and not a 404.
func TestCatchAllBacktrackPrefixCollision(t *testing.T) {
	build := func(built bool) *Router {
		r := NewRouter()
		var got string
		reg := func(p string) { r.GET(p, func(req *Request, resp *Response) {}) }
		reg("/dashboard/shop-products")
		reg("/dashboard/shop-editor")
		reg("/dashboard/shop-analytics")
		reg("/dashboard/shop-admins")
		reg("/dashboard/shop-permissions")
		reg("/dashboard/supervisor")
		reg("/dashboard/admincaptcha")
		reg("/shop/:affiliate")
		r.GET("/*page", func(req *Request, resp *Response) {})
		reg("/dashboard")
		r.GET("/dashboard/*page", func(req *Request, resp *Response) { got = "dash" })
		_ = got
		if built {
			r.Build()
		}
		return r
	}

	cases := []struct {
		path string
		want string // expected page param
	}{
		{"/dashboard/shop", "shop"},
		{"/dashboard/settings", "settings"},
		{"/dashboard/wallet", "wallet"},
		{"/dashboard/apis", "apis"},
		{"/dashboard/shop-editor", ""}, // static route, no page param
	}

	for _, built := range []bool{false, true} {
		r := build(built)
		for _, c := range cases {
			req := &Request{}
			h := r.Lookup("GET", c.path, req)
			if h == nil {
				t.Errorf("built=%v %s -> NIL (404)", built, c.path)
				continue
			}
			if got := req.ParamValue("page"); got != c.want {
				t.Errorf("built=%v %s -> page=%q want %q", built, c.path, got, c.want)
			}
		}
	}
}
