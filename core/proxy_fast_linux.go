//go:build linux

package core

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
