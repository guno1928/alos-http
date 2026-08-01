//go:build !linux

package core

func (pe *ProxyEngine) forwardRequest(req *Request, resp *Response, b *backend, cfg *DomainConfig) error {
	return pe.forwardRequestStdnet(req, resp, b, cfg)
}
