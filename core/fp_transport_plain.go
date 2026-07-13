//go:build linux

package core

type plainTransport struct {
	h2 bool
}

func (t *plainTransport) start(c *backendConn) error {
	c.loop.onTransportReady(c)
	return nil
}

func (t *plainTransport) feed(c *backendConn, raw []byte) error {
	return c.proto.onData(c, raw)
}

func (t *plainTransport) wrapOut(c *backendConn, plain []byte) error {
	c.wbuf.write(plain)
	return nil
}

func (t *plainTransport) negotiatedALPN() string {
	if t.h2 {
		return "h2"
	}
	return "http/1.1"
}
