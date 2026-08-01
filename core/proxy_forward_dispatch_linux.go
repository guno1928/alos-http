//go:build linux

package core

func (pe *ProxyEngine) forwardRequest(req *Request, resp *Response, b *backend, cfg *DomainConfig) error {
	if isWebSocket(req) {
		return pe.forwardWebSocket(req, resp, b, cfg)
	}
	return pe.forwardRequestFP(req, resp, b, cfg)
}
