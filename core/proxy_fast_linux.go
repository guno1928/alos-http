//go:build linux

package core

// StartFastProxy builds host-routed backend groups from domains and starts
// the epoll-based fast reverse proxy listening on listenAddr with the given
// number of event loops. A DomainConfig whose Domain is "" or "*" becomes
// the fallback route used when no host matches; every other domain routes by
// exact host match. StartFastProxy returns once the proxy is listening; it
// does not block.
//
// Example: err := StartFastProxy(":8080", domains, 4)
func StartFastProxy(listenAddr string, domains []DomainConfig, loops int) error {
	var routes []FastRoute
	var fallback []FastBackend
	for _, d := range domains {
		var bes []FastBackend
		for _, bc := range d.Backends {
			b := bc
			normalizeBackendAddr(&b)
			bes = append(bes, FastBackend{
				Addr:       b.Addr,
				TLS:        b.TLS,
				SkipVerify: b.TLSSkipVerify,
				Weight:     b.Weight,
			})
		}
		if d.Domain == "" || d.Domain == "*" {
			fallback = bes
		} else {
			routes = append(routes, FastRoute{Host: d.Domain, Backends: bes, LB: d.LoadBalancer})
		}
	}
	_, err := ListenAndFastProxy(listenAddr, routes, fallback, loops)
	return err
}
