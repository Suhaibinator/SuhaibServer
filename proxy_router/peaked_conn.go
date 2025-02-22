package proxy_router

import "net"

type PeekedConn struct {
	net.Conn

	// The sniffed bytes that we already read
	peeked []byte

	// How far we've consumed from peeked
	offset int
}

// NewPeekedConn wraps the original connection with the peeked data at the front.
func NewPeekedConn(conn net.Conn, peeked []byte) *PeekedConn {
	return &PeekedConn{
		Conn:   conn,
		peeked: peeked,
		offset: 0,
	}
}

// Read first serves data from the peeked buffer, then from the underlying conn.
func (pc *PeekedConn) Read(b []byte) (n int, err error) {
	// If we still have unconsumed peeked data, serve that first.
	if pc.offset < len(pc.peeked) {
		n = copy(b, pc.peeked[pc.offset:])
		pc.offset += n
		return n, nil
	}
	// Otherwise read from the underlying connection
	return pc.Conn.Read(b)
}
