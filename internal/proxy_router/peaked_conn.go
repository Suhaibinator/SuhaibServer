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

// Read first consumes peeked data, then continues reading from the underlying conn
func (pc *PeekedConn) Read(b []byte) (int, error) {
	totalRead := 0

	// 1. Serve unconsumed peeked data if any
	if pc.offset < len(pc.peeked) {
		n := copy(b, pc.peeked[pc.offset:])
		pc.offset += n
		totalRead += n
		// If we filled the entire buffer from peeked data, return now
		if n == len(b) {
			return totalRead, nil
		}
	}

	// 2. If there's still capacity in b, read from underlying connection
	rn, err := pc.Conn.Read(b[totalRead:])
	totalRead += rn
	return totalRead, err
}
