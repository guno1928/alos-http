package routing_test

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/guno1928/alos-http/core"
)

func invoke(t *testing.T, router *core.Router, method, path string) (*core.Request, *core.Response) {
	t.Helper()
	req := &core.Request{Method: method, Path: path}
	resp := &core.Response{}
	resp.Reset()
	router.Lookup(method, path, req)(req, resp)
	return req, resp
}

func TestStaticRouteMatrix(t *testing.T) {
	router := core.NewRouter()
	for i := 0; i < 128; i++ {
		i := i
		path := fmt.Sprintf("/static/%03d", i)
		router.GET(path, func(_ *core.Request, resp *core.Response) {
			resp.Status(200).String(strconv.Itoa(i))
		})
	}
	router.Build()
	for i := 0; i < 128; i++ {
		i := i
		t.Run(fmt.Sprintf("route_%03d", i), func(t *testing.T) {
			_, resp := invoke(t, router, "GET", fmt.Sprintf("/static/%03d", i))
			if resp.StatusCode != 200 || string(resp.GetBody()) != strconv.Itoa(i) {
				t.Fatalf("status=%d body=%q", resp.StatusCode, resp.GetBody())
			}
		})
	}
}

func TestParameterRouteMatrix(t *testing.T) {
	router := core.NewRouter()
	router.GET("/users/:id/orders/:order", func(req *core.Request, resp *core.Response) {
		resp.String(req.ParamValue("id") + ":" + req.ParamValue("order"))
	})
	router.Build()
	for i := 0; i < 64; i++ {
		i := i
		t.Run(fmt.Sprintf("params_%02d", i), func(t *testing.T) {
			path := fmt.Sprintf("/users/u%d/orders/o%d", i, 63-i)
			req, resp := invoke(t, router, "GET", path)
			want := fmt.Sprintf("u%d:o%d", i, 63-i)
			if string(resp.GetBody()) != want || req.ParamCount != 2 {
				t.Fatalf("body=%q params=%d", resp.GetBody(), req.ParamCount)
			}
		})
	}
}

func TestCatchAllRouteMatrix(t *testing.T) {
	router := core.NewRouter()
	router.GET("/assets/*path", func(req *core.Request, resp *core.Response) {
		resp.String(req.ParamValue("path"))
	})
	router.Build()
	for depth := 1; depth <= 32; depth++ {
		depth := depth
		t.Run(fmt.Sprintf("depth_%02d", depth), func(t *testing.T) {
			path := ""
			for i := 0; i < depth; i++ {
				path += "/x" + strconv.Itoa(i)
			}
			_, resp := invoke(t, router, "GET", "/assets"+path)
			if string(resp.GetBody()) != path[1:] {
				t.Fatalf("body=%q want=%q", resp.GetBody(), path[1:])
			}
		})
	}
}

func TestMethodRouteMatrix(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	for pathIndex := 0; pathIndex < 8; pathIndex++ {
		pathIndex := pathIndex
		router := core.NewRouter()
		path := fmt.Sprintf("/method/%d", pathIndex)
		for _, method := range methods {
			method := method
			router.Handle(method, path, func(_ *core.Request, resp *core.Response) {
				resp.String(method)
			})
		}
		router.Build()
		for _, method := range methods {
			method := method
			t.Run(fmt.Sprintf("path_%d_%s", pathIndex, method), func(t *testing.T) {
				_, resp := invoke(t, router, method, path)
				if string(resp.GetBody()) != method {
					t.Fatalf("body=%q", resp.GetBody())
				}
			})
		}
	}
}

func TestNotFoundAndMethodNotAllowedMatrix(t *testing.T) {
	router := core.NewRouter()
	router.GET("/known", func(_ *core.Request, resp *core.Response) { resp.String("known") })
	router.NotFound(func(_ *core.Request, resp *core.Response) { resp.Status(404).String("missing") })
	router.MethodNotAllowed(func(_ *core.Request, resp *core.Response) { resp.Status(405).String("method") })
	router.Build()
	for i := 0; i < 16; i++ {
		i := i
		t.Run(fmt.Sprintf("missing_%02d", i), func(t *testing.T) {
			_, resp := invoke(t, router, "GET", fmt.Sprintf("/missing/%d", i))
			if resp.StatusCode != 404 || string(resp.GetBody()) != "missing" {
				t.Fatalf("status=%d body=%q", resp.StatusCode, resp.GetBody())
			}
		})
		t.Run(fmt.Sprintf("method_%02d", i), func(t *testing.T) {
			_, resp := invoke(t, router, "POST", "/known")
			if resp.StatusCode != 405 || string(resp.GetBody()) != "method" {
				t.Fatalf("status=%d body=%q", resp.StatusCode, resp.GetBody())
			}
		})
	}
}

func TestGroupAndMiddlewareMatrix(t *testing.T) {
	for i := 0; i < 32; i++ {
		i := i
		t.Run(fmt.Sprintf("group_%02d", i), func(t *testing.T) {
			router := core.NewRouter()
			middleware := func(next core.HandlerFunc) core.HandlerFunc {
				return func(req *core.Request, resp *core.Response) {
					resp.SetHeader("X-Before", strconv.Itoa(i))
					next(req, resp)
					resp.SetHeader("X-After", strconv.Itoa(i+1))
				}
			}
			group := router.Group(fmt.Sprintf("/api/%d", i), middleware)
			group.GET("/item/:id", func(req *core.Request, resp *core.Response) {
				resp.String(req.ParamValue("id"))
			})
			router.Build()
			_, resp := invoke(t, router, "GET", fmt.Sprintf("/api/%d/item/value", i))
			if string(resp.GetBody()) != "value" || len(resp.Headers) != 2 {
				t.Fatalf("body=%q headers=%v", resp.GetBody(), resp.Headers)
			}
		})
	}
}
