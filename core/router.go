package core

import (
	"math/bits"
	"sort"
	"strings"
	"sync"
	"unsafe"
)

// HandlerFunc is the signature for request handlers. Every route handler and
// middleware terminal receives a Request (the incoming HTTP request) and a
// Response (the outgoing reply builder). Write the response by calling methods
// on resp such as resp.Status(200).String("ok").
//
//	srv.Router.GET("/hello", func(req *core.Request, resp *core.Response) {
//	    resp.Status(200).String("hello world")
//	})
type HandlerFunc func(req *Request, resp *Response)

// MiddlewareFunc wraps a HandlerFunc to add behavior before or after the
// downstream handler runs. Return a new HandlerFunc that calls next when
// the request should continue down the chain.
//
//	func MyMiddleware() core.MiddlewareFunc {
//	    return func(next core.HandlerFunc) core.HandlerFunc {
//	        return func(req *core.Request, resp *core.Response) {
//	            log.Println("before")
//	            next(req, resp)
//	            log.Println("after")
//	        }
//	    }
//	}
type MiddlewareFunc func(HandlerFunc) HandlerFunc

type node struct {
	path              string
	children          []*node
	indices           []byte
	handler           HandlerFunc
	wrappedHandler    HandlerFunc
	paramChild        *node
	catchAll          *node
	inheritedCatchAll *node
	paramName         string
	catchName         string
	middleware        []MiddlewareFunc
}

const (
	methodGET     = 0
	methodPOST    = 1
	methodPUT     = 2
	methodDELETE  = 3
	methodPATCH   = 4
	methodHEAD    = 5
	methodOPTIONS = 6
	methodCONNECT = 7
	methodTRACE   = 8
	methodCount   = 9
)

var methodLookup [256][256]int8

func init() {
	methods := [methodCount][2]byte{
		{'G', 'E'},
		{'P', 'O'},
		{'P', 'U'},
		{'D', 'E'},
		{'P', 'A'},
		{'H', 'E'},
		{'O', 'P'},
		{'C', 'O'},
		{'T', 'R'},
	}
	for i, m := range methods {
		methodLookup[m[0]][m[1]] = int8(i + 1)
	}
}

func methodIndex(method string) int {
	if len(method) < 3 {
		return -1
	}
	switch {
	case method[0] == 'G' && method[1] == 'E':
		return methodGET
	case method[0] == 'P' && method[1] == 'O':
		return methodPOST
	case method[0] == 'P' && method[1] == 'U':
		return methodPUT
	case method[0] == 'D' && method[1] == 'E':
		return methodDELETE
	case method[0] == 'P' && method[1] == 'A':
		return methodPATCH
	case method[0] == 'H' && method[1] == 'E':
		return methodHEAD
	case method[0] == 'O' && method[1] == 'P':
		return methodOPTIONS
	case method[0] == 'C' && method[1] == 'O':
		return methodCONNECT
	case method[0] == 'T' && method[1] == 'R':
		return methodTRACE
	}
	return -1
}

type staticEntry struct {
	path    string
	hash    uint32
	handler HandlerFunc
}

type Router struct {
	trees                   [methodCount]*node
	staticHashes            [methodCount][]uint32
	staticPaths             [methodCount][]string
	staticHandlers          [methodCount][]HandlerFunc
	staticMask              [methodCount]uint32
	validFirst              [4]uint64
	notFound                HandlerFunc
	methodNotAllowed        HandlerFunc
	globalMiddleware        []MiddlewareFunc
	wrappedNotFound         HandlerFunc
	wrappedMethodNotAllowed HandlerFunc
	built                   bool
	buildOnce               sync.Once
	server                  *Server
}

// NewRouter creates a new Router with default 404 and 405 handlers. Register
// routes with the HTTP method helpers (GET, POST, PUT, DELETE, etc.) then call
// Build before passing the router to the server.
//
//	r := core.NewRouter()
//	r.GET("/", indexHandler)
//	r.Build()
func NewRouter() *Router {
	r := &Router{
		notFound: func(req *Request, resp *Response) {
			resp.Status(404).String("Not Found")
		},
		methodNotAllowed: func(req *Request, resp *Response) {
			resp.Status(405).String("Method Not Allowed")
		},
	}
	return r
}

// Use registers one or more global middleware functions that run on every request
// in the order they are added.
//
//	r.Use(core.Logger, core.Recovery)
//	r.Use(core.CORS(core.NewCORSEngine(core.CORSConfig{
//	    AllowOrigins: []string{"*"},
//	})))
func (r *Router) Use(middleware ...MiddlewareFunc) {
	r.globalMiddleware = append(r.globalMiddleware, middleware...)
}

// Handle registers a handler for the given HTTP method and path pattern. Path
// patterns can include named parameters (:param) and catch-all segments (*name).
//
//	r.Handle("GET", "/users/:id", getUser)
//	r.Handle("GET", "/files/*filepath", serveFiles)
func (r *Router) Handle(method, path string, handler HandlerFunc) *Route {
	idx := methodIndex(method)
	if idx < 0 {
		return &Route{}
	}
	if r.trees[idx] == nil {
		r.trees[idx] = &node{}
	}
	n := r.addRoute(r.trees[idx], path, handler)
	return &Route{node: n, router: r, method: method, path: path}
}

// GET registers a handler for GET requests at the given path.
func (r *Router) GET(path string, handler HandlerFunc) *Route { return r.Handle("GET", path, handler) }

// POST registers a handler for POST requests at the given path.
func (r *Router) POST(path string, handler HandlerFunc) *Route {
	return r.Handle("POST", path, handler)
}

// PUT registers a handler for PUT requests at the given path.
func (r *Router) PUT(path string, handler HandlerFunc) *Route { return r.Handle("PUT", path, handler) }

// DELETE registers a handler for DELETE requests at the given path.
func (r *Router) DELETE(path string, handler HandlerFunc) *Route {
	return r.Handle("DELETE", path, handler)
}

// PATCH registers a handler for PATCH requests at the given path.
func (r *Router) PATCH(path string, handler HandlerFunc) *Route {
	return r.Handle("PATCH", path, handler)
}

// HEAD registers a handler for HEAD requests at the given path.
func (r *Router) HEAD(path string, handler HandlerFunc) *Route {
	return r.Handle("HEAD", path, handler)
}

// OPTIONS registers a handler for OPTIONS requests at the given path.
func (r *Router) OPTIONS(path string, handler HandlerFunc) *Route {
	return r.Handle("OPTIONS", path, handler)
}

var allMethods = [...]string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"}

// ANY registers a handler that matches all HTTP methods (GET, POST, PUT, DELETE,
// PATCH, HEAD, OPTIONS, CONNECT, TRACE) at the given path.
//
//	r.ANY("/health", func(req *core.Request, resp *core.Response) {
//	    resp.Status(200).String("ok")
//	})
func (r *Router) ANY(path string, handler HandlerFunc) {
	for _, m := range allMethods {
		r.Handle(m, path, handler)
	}
}

// NotFound sets a custom handler that runs when no route matches the request path.
//
//	r.NotFound(func(req *core.Request, resp *core.Response) {
//	    resp.Status(404).JSON([]byte(`{"error":"not found"}`))
//	})
func (r *Router) NotFound(handler HandlerFunc) {
	r.notFound = handler
}

// MethodNotAllowed sets a custom handler that runs when a route exists but not
// for the requested HTTP method.
func (r *Router) MethodNotAllowed(handler HandlerFunc) {
	r.methodNotAllowed = handler
}

func (r *Router) addRoute(root *node, path string, handler HandlerFunc) *node {
	current := root
	remaining := path

	for len(remaining) > 0 {
		if remaining[0] == ':' {
			paramEnd := 1
			for paramEnd < len(remaining) && remaining[paramEnd] != '/' {
				paramEnd++
			}
			paramName := remaining[1:paramEnd]

			if current.paramChild == nil {
				current.paramChild = &node{paramName: paramName}
			}
			current = current.paramChild
			current.paramName = paramName
			remaining = remaining[paramEnd:]
			continue
		}

		if remaining[0] == '*' {
			catchName := remaining[1:]
			current.catchAll = &node{catchName: catchName, handler: handler}
			return current.catchAll
		}

		found := false
		for i, idx := range current.indices {
			if idx == remaining[0] {
				child := current.children[i]
				commonLen := longestCommonPrefix(child.path, remaining)

				if commonLen < len(child.path) {
					splitChild := &node{
						path:       child.path[commonLen:],
						children:   child.children,
						indices:    child.indices,
						handler:    child.handler,
						paramChild: child.paramChild,
						catchAll:   child.catchAll,
						paramName:  child.paramName,
						catchName:  child.catchName,
						middleware: child.middleware,
					}

					child.path = child.path[:commonLen]
					child.children = []*node{splitChild}
					child.indices = []byte{splitChild.path[0]}
					child.handler = nil
					child.paramChild = nil
					child.catchAll = nil
					child.paramName = ""
					child.catchName = ""
					child.middleware = nil
				}

				remaining = remaining[commonLen:]
				current = child
				found = true
				break
			}
		}

		if !found {
			staticEnd := len(remaining)
			for j := 0; j < len(remaining); j++ {
				if remaining[j] == ':' || remaining[j] == '*' {
					staticEnd = j
					break
				}
			}
			segment := remaining[:staticEnd]
			newNode := &node{path: segment}
			current.children = append(current.children, newNode)
			current.indices = append(current.indices, segment[0])
			remaining = remaining[staticEnd:]
			current = newNode
			if len(remaining) == 0 {
				current.handler = handler
				return current
			}
			continue
		}
	}

	current.handler = handler
	return current
}

func longestCommonPrefix(a, b string) int {
	max := len(a)
	if len(b) < max {
		max = len(b)
	}
	i := 0
	for ; i+7 < max; i += 8 {
		aw := *(*uint64)(unsafe.Pointer(unsafe.StringData(a[i:])))
		bw := *(*uint64)(unsafe.Pointer(unsafe.StringData(b[i:])))
		if aw != bw {
			diff := aw ^ bw
			return i + bits.TrailingZeros64(diff)/8
		}
	}
	for i < max && a[i] == b[i] {
		i++
	}
	return i
}

func pathQuickHash(s string) uint32 {
	l := uint32(len(s))
	if l < 2 {
		return l*0x9E3779B9 | 0x80000000
	}
	h := l
	h = (h ^ uint32(s[1])) * 0x9E3779B9
	h = (h ^ uint32(s[l-1])) * 0x9E3779B9
	if l > 3 {
		h = (h ^ uint32(s[l>>1])) * 0x9E3779B9
	}
	return h | 0x80000000
}

// Build pre-compiles the routing table by wrapping all handlers with global
// middleware and building index lookup tables. Call this once after all routes
// and middleware are registered, before the server starts handling requests.
//
//	r.GET("/", indexHandler)
//	r.Use(core.Logger)
//	r.Build()
func (r *Router) Build() {
	r.buildOnce.Do(r.build)
}

func (r *Router) build() {
	r.wrappedNotFound = r.applyMiddleware(r.notFound)
	r.wrappedMethodNotAllowed = r.applyMiddleware(r.methodNotAllowed)
	for mi, root := range r.trees {
		if root != nil {
			r.buildNode(root, nil)
			if root.path == "" && len(root.children) == 1 &&
				root.wrappedHandler == nil && root.paramChild == nil && root.catchAll == nil {
				r.trees[mi] = root.children[0]
				root = r.trees[mi]
			}
			var statics []staticEntry
			collectStaticRoutes(root, "", &statics)
			if len(statics) > 0 {
				sz := 16
				for sz < len(statics)*2 {
					sz <<= 1
				}
				hashes := make([]uint32, sz)
				paths := make([]string, sz)
				handlers := make([]HandlerFunc, sz)
				mask := uint32(sz - 1)
				for _, se := range statics {
					idx := se.hash & mask
					for hashes[idx] != 0 {
						idx = (idx + 1) & mask
					}
					hashes[idx] = se.hash
					paths[idx] = se.path
					handlers[idx] = se.handler
				}
				r.staticHashes[mi] = hashes
				r.staticPaths[mi] = paths
				r.staticHandlers[mi] = handlers
				r.staticMask[mi] = mask
			}
		}
	}
	for _, root := range r.trees {
		if root != nil {
			for _, b := range root.indices {
				r.validFirst[b/64] |= 1 << (b % 64)
			}
			if root.paramChild != nil || root.catchAll != nil {
				r.validFirst = [4]uint64{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
				break
			}
		}
	}
	r.built = true
}

func collectStaticRoutes(n *node, prefix string, out *[]staticEntry) {
	fullPath := prefix + n.path
	if n.wrappedHandler != nil {
		*out = append(*out, staticEntry{
			path:    fullPath,
			hash:    pathQuickHash(fullPath),
			handler: n.wrappedHandler,
		})
	}
	for _, child := range n.children {
		collectStaticRoutes(child, fullPath, out)
	}
}

func (r *Router) buildNode(n *node, inheritedCatchAll *node) {
	if n.handler != nil {
		n.wrappedHandler = r.applyMiddleware(n.handler)
	}
	if inheritedCatchAll != nil {
		n.inheritedCatchAll = inheritedCatchAll
	}
	if n.catchAll != nil {
		inheritedCatchAll = n.catchAll
	}
	for _, child := range n.children {
		r.buildNode(child, inheritedCatchAll)
	}
	if n.paramChild != nil {
		r.buildNode(n.paramChild, inheritedCatchAll)
	}
	if n.catchAll != nil {
		r.buildNode(n.catchAll, inheritedCatchAll)
	}
}

// Lookup finds the handler for the given method and path, populating any path
// parameters on the Request. Returns the not-found or method-not-allowed handler
// when no exact match exists. This is called internally by the server for each
// incoming request.
func (r *Router) Lookup(method, path string, req *Request) HandlerFunc {
	idx := methodIndex(method)
	if idx < 0 {
		if r.built {
			return r.wrappedNotFound
		}
		return r.notFound
	}

	if r.built {
		return r.lookupBuilt(idx, path, req)
	}

	root := r.trees[idx]
	if root == nil {
		return r.applyMiddleware(r.notFound)
	}
	handler := r.findInTree(root, path, req)
	if handler != nil {
		return r.applyMiddleware(handler)
	}
	return r.applyMiddleware(r.notFound)
}

func (r *Router) lookupBuilt(idx int, path string, req *Request) HandlerFunc {
	root := r.trees[idx]
	if root == nil {
		for i := range r.trees {
			if i != idx && r.trees[i] != nil {
				if findBuilt(r.trees[i], path, req) != nil {
					req.ParamCount = 0
					return r.wrappedMethodNotAllowed
				}
			}
		}
		return r.wrappedNotFound
	}

	if hashes := r.staticHashes[idx]; hashes != nil {
		mask := r.staticMask[idx]
		h := pathQuickHash(path)
		i := h & mask
		for {
			if hashes[i] == 0 {
				break
			}
			if hashes[i] == h && r.staticPaths[idx][i] == path {
				return r.staticHandlers[idx][i]
			}
			i = (i + 1) & mask
		}
	}

	if handler := findBuilt(root, path, req); handler != nil {
		return handler
	}

	if root.catchAll != nil {
		req.ParamCount = 0
		if len(req.Params) > 0 {
			p := &req.Params[0]
			p.Key = root.catchAll.catchName
			if len(path) > 1 {
				p.Value = path[1:]
			} else {
				p.Value = ""
			}
			req.ParamCount = 1
		}
		return root.catchAll.wrappedHandler
	}

	if len(path) > 1 {
		b := path[1]
		if r.validFirst[b/64]&(1<<(b%64)) == 0 {
			return r.wrappedNotFound
		}
	}

	for i := range r.trees {
		if i != idx && r.trees[i] != nil {
			if findBuilt(r.trees[i], path, req) != nil {
				req.ParamCount = 0
				return r.wrappedMethodNotAllowed
			}
		}
	}
	return r.wrappedNotFound
}

func findBuilt(current *node, path string, req *Request) HandlerFunc {
	remaining := path
	req.ParamCount = 0

	if rp := len(current.path); rp > 0 {
		if len(remaining) < rp || remaining[:rp] != current.path {
			return nil
		}
		remaining = remaining[rp:]
	}

	var pendingCatch *node
	var pendingRemaining string
	var pendingParamCount int

	for {
		if len(remaining) == 0 {
			return current.wrappedHandler
		}

		if current.catchAll != nil {
			pendingCatch = current.catchAll
			pendingRemaining = remaining
			pendingParamCount = req.ParamCount
		}

		c := remaining[0]
		matched := false
		nIndices := len(current.indices)
		switch {
		case nIndices == 1:
			if current.indices[0] == c {
				child := current.children[0]
				plen := len(child.path)
				if plen == 1 {
					remaining = remaining[1:]
					current = child
					matched = true
				} else if len(remaining) >= plen && remaining[:plen] == child.path {
					remaining = remaining[plen:]
					current = child
					matched = true
				}
			}
		case nIndices == 2:
			if current.indices[0] == c {
				child := current.children[0]
				plen := len(child.path)
				if plen == 1 {
					remaining = remaining[1:]
					current = child
					matched = true
				} else if len(remaining) >= plen && remaining[:plen] == child.path {
					remaining = remaining[plen:]
					current = child
					matched = true
				}
			} else if current.indices[1] == c {
				child := current.children[1]
				plen := len(child.path)
				if plen == 1 {
					remaining = remaining[1:]
					current = child
					matched = true
				} else if len(remaining) >= plen && remaining[:plen] == child.path {
					remaining = remaining[plen:]
					current = child
					matched = true
				}
			}
		default:
			for i, b := range current.indices {
				if b == c {
					child := current.children[i]
					plen := len(child.path)
					if plen == 1 {
						remaining = remaining[1:]
						current = child
						matched = true
					} else if len(remaining) >= plen && remaining[:plen] == child.path {
						remaining = remaining[plen:]
						current = child
						matched = true
					}
					break
				}
			}
		}
		if matched {
			continue
		}

		if current.paramChild != nil {
			paramEnd := 0
			for paramEnd < len(remaining) && remaining[paramEnd] != '/' {
				paramEnd++
			}
			if req.ParamCount < len(req.Params) {
				p := &req.Params[req.ParamCount]
				p.Key = current.paramChild.paramName
				p.Value = remaining[:paramEnd]
				req.ParamCount++
			}
			remaining = remaining[paramEnd:]
			current = current.paramChild
			continue
		}

		if current.catchAll != nil {
			if req.ParamCount < len(req.Params) {
				p := &req.Params[req.ParamCount]
				p.Key = current.catchAll.catchName
				p.Value = remaining
				req.ParamCount++
			}
			return current.catchAll.wrappedHandler
		}

		if pendingCatch != nil {
			req.ParamCount = pendingParamCount
			if req.ParamCount < len(req.Params) {
				p := &req.Params[req.ParamCount]
				p.Key = pendingCatch.catchName
				p.Value = pendingRemaining
				req.ParamCount++
			}
			return pendingCatch.wrappedHandler
		}

		return nil
	}
}

func (r *Router) findInTree(root *node, path string, req *Request) HandlerFunc {
	current := root
	remaining := path
	req.ParamCount = 0

	var pendingCatch *node
	var pendingRemaining string
	var pendingParamCount int

	for {
		if len(remaining) == 0 {
			if current.handler != nil {
				return current.handler
			}
			return nil
		}

		if current.catchAll != nil {
			pendingCatch = current.catchAll
			pendingRemaining = remaining
			pendingParamCount = req.ParamCount
		}

		c := remaining[0]
		matched := false
		nIndices := len(current.indices)
		switch {
		case nIndices == 1:
			if current.indices[0] == c {
				child := current.children[0]
				if len(remaining) >= len(child.path) && remaining[:len(child.path)] == child.path {
					remaining = remaining[len(child.path):]
					current = child
					matched = true
				}
			}
		case nIndices == 2:
			if current.indices[0] == c {
				child := current.children[0]
				if len(remaining) >= len(child.path) && remaining[:len(child.path)] == child.path {
					remaining = remaining[len(child.path):]
					current = child
					matched = true
				}
			} else if current.indices[1] == c {
				child := current.children[1]
				if len(remaining) >= len(child.path) && remaining[:len(child.path)] == child.path {
					remaining = remaining[len(child.path):]
					current = child
					matched = true
				}
			}
		default:
			for i, b := range current.indices {
				if b == c {
					child := current.children[i]
					if len(remaining) >= len(child.path) && remaining[:len(child.path)] == child.path {
						remaining = remaining[len(child.path):]
						current = child
						matched = true
					}
					break
				}
			}
		}
		if matched {
			continue
		}

		if current.paramChild != nil {
			paramEnd := 0
			for paramEnd < len(remaining) && remaining[paramEnd] != '/' {
				paramEnd++
			}
			if req.ParamCount < len(req.Params) {
				req.Params[req.ParamCount] = Param{
					Key:   current.paramChild.paramName,
					Value: remaining[:paramEnd],
				}
				req.ParamCount++
			}
			remaining = remaining[paramEnd:]
			current = current.paramChild
			continue
		}

		if current.catchAll != nil {
			if req.ParamCount < len(req.Params) {
				req.Params[req.ParamCount] = Param{
					Key:   current.catchAll.catchName,
					Value: remaining,
				}
				req.ParamCount++
			}
			return current.catchAll.handler
		}

		if pendingCatch != nil {
			req.ParamCount = pendingParamCount
			if req.ParamCount < len(req.Params) {
				req.Params[req.ParamCount] = Param{
					Key:   pendingCatch.catchName,
					Value: pendingRemaining,
				}
				req.ParamCount++
			}
			return pendingCatch.handler
		}

		return nil
	}
}

func (r *Router) applyMiddleware(handler HandlerFunc) HandlerFunc {
	h := handler
	for i := len(r.globalMiddleware) - 1; i >= 0; i-- {
		h = r.globalMiddleware[i](h)
	}
	return h
}

// RouteGroup is a collection of routes that share a common path prefix and
// middleware stack. Create one with Router.Group.
//
//	api := r.Group("/api/v1", authMiddleware)
//	api.GET("/users", listUsers)
//	api.POST("/users", createUser)
//
//	admin := api.Group("/admin", adminOnly)
//	admin.DELETE("/users/:id", deleteUser)
type RouteGroup struct {
	prefix     string
	router     *Router
	middleware []MiddlewareFunc
}

// Group creates a new RouteGroup with the given path prefix and optional middleware.
// All routes registered on the group inherit the prefix and middleware chain.
//
//	api := r.Group("/api/v1")
//	api.Use(rateLimiter)
//	api.GET("/items", listItems)
func (r *Router) Group(prefix string, middleware ...MiddlewareFunc) *RouteGroup {
	return &RouteGroup{
		prefix:     prefix,
		router:     r,
		middleware: middleware,
	}
}

// Use adds middleware to the group. These run after any middleware passed to Group
// and before the route handler.
func (g *RouteGroup) Use(middleware ...MiddlewareFunc) {
	g.middleware = append(g.middleware, middleware...)
}

func (g *RouteGroup) handle(method, path string, handler HandlerFunc) *Route {
	h := handler
	for i := len(g.middleware) - 1; i >= 0; i-- {
		h = g.middleware[i](h)
	}
	return g.router.Handle(method, g.prefix+path, h)
}

// GET registers a GET handler on the group at prefix+path.
func (g *RouteGroup) GET(path string, handler HandlerFunc) *Route {
	return g.handle("GET", path, handler)
}

// POST registers a POST handler on the group at prefix+path.
func (g *RouteGroup) POST(path string, handler HandlerFunc) *Route {
	return g.handle("POST", path, handler)
}

// PUT registers a PUT handler on the group at prefix+path.
func (g *RouteGroup) PUT(path string, handler HandlerFunc) *Route {
	return g.handle("PUT", path, handler)
}

// DELETE registers a DELETE handler on the group at prefix+path.
func (g *RouteGroup) DELETE(path string, handler HandlerFunc) *Route {
	return g.handle("DELETE", path, handler)
}

// PATCH registers a PATCH handler on the group at prefix+path.
func (g *RouteGroup) PATCH(path string, handler HandlerFunc) *Route {
	return g.handle("PATCH", path, handler)
}

// HEAD registers a HEAD handler on the group at prefix+path.
func (g *RouteGroup) HEAD(path string, handler HandlerFunc) *Route {
	return g.handle("HEAD", path, handler)
}

// OPTIONS registers an OPTIONS handler on the group.
func (g *RouteGroup) OPTIONS(path string, handler HandlerFunc) { g.handle("OPTIONS", path, handler) }

// ANY registers a handler for all HTTP methods on the group.
func (g *RouteGroup) ANY(path string, handler HandlerFunc) {
	for _, m := range allMethods {
		g.handle(m, path, handler)
	}
}

// Group creates a nested sub-group inheriting the parent's prefix and middleware.
//
//	v1 := r.Group("/v1")
//	admin := v1.Group("/admin", adminAuth)
//	admin.GET("/stats", statsHandler)  // matches /v1/admin/stats
func (g *RouteGroup) Group(prefix string, middleware ...MiddlewareFunc) *RouteGroup {
	combined := make([]MiddlewareFunc, 0, len(g.middleware)+len(middleware))
	combined = append(combined, g.middleware...)
	combined = append(combined, middleware...)
	return &RouteGroup{
		prefix:     g.prefix + prefix,
		router:     g.router,
		middleware: combined,
	}
}

// Chain wraps a handler with the given middleware, applying them in order so
// the first middleware in the list is the outermost wrapper.
//
//	protected := core.Chain(myHandler, authMiddleware, logMiddleware)
//	r.GET("/secret", protected)
func Chain(handler HandlerFunc, middleware ...MiddlewareFunc) HandlerFunc {
	h := handler
	for i := len(middleware) - 1; i >= 0; i-- {
		h = middleware[i](h)
	}
	return h
}

// RouteInfo describes a single registered route returned by Routes.
//
// Method is the HTTP method (e.g. "GET").
// Path is the full registered path pattern (e.g. "/users/:id").
type RouteInfo struct {
	Method string
	Path   string
}

// Routes returns all registered routes across every method, sorted by method
// then path. Useful for debugging and introspection.
func (r *Router) Routes() []RouteInfo {
	var routes []RouteInfo
	for i, root := range r.trees {
		if root == nil {
			continue
		}
		collectRoutes(root, "", allMethods[i], &routes)
	}
	sort.Slice(routes, func(a, b int) bool {
		if routes[a].Method != routes[b].Method {
			return routes[a].Method < routes[b].Method
		}
		return routes[a].Path < routes[b].Path
	})
	return routes
}

func collectRoutes(n *node, prefix, method string, out *[]RouteInfo) {
	fullPath := prefix + n.path
	if n.handler != nil || n.wrappedHandler != nil {
		*out = append(*out, RouteInfo{Method: method, Path: fullPath})
	}
	for _, child := range n.children {
		collectRoutes(child, fullPath, method, out)
	}
	if n.paramChild != nil {
		collectRoutes(n.paramChild, fullPath+":"+n.paramChild.paramName, method, out)
	}
	if n.catchAll != nil {
		catchPath := fullPath + "*" + n.catchAll.catchName
		*out = append(*out, RouteInfo{Method: method, Path: catchPath})
	}
}

// Routes returns all registered routes whose path starts with the group prefix.
func (g *RouteGroup) Routes() []RouteInfo {
	all := g.router.Routes()
	var filtered []RouteInfo
	for _, ri := range all {
		if strings.HasPrefix(ri.Path, g.prefix) {
			filtered = append(filtered, ri)
		}
	}
	return filtered
}

// Match reports whether a route exists for the given method and path without
// executing the handler. Useful for testing route registration.
//
//	if r.Match("GET", "/api/users") {
//	    fmt.Println("route exists")
//	}
func (r *Router) Match(method, path string) bool {
	idx := methodIndex(method)
	if idx < 0 {
		return false
	}
	if r.built {
		root := r.trees[idx]
		if root == nil {
			return false
		}
		var dummy Request
		return findBuilt(root, path, &dummy) != nil
	}
	root := r.trees[idx]
	if root == nil {
		return false
	}
	var dummy Request
	return r.findInTree(root, path, &dummy) != nil
}
