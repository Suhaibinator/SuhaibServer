package proxy_router

import (
	"bytes"
	"io"
	"net"
)

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

// multiReaderConn wraps a net.Conn so that its Read() method
// first returns data from an in-memory buffer (the "peeked" bytes)
// and then transparently continues reading from the original conn.
type multiReaderConn struct {
	net.Conn // embed so we inherit all net.Conn methods
	reader   io.Reader
}

func (m *multiReaderConn) Read(b []byte) (int, error) {
	return m.reader.Read(b)
}

// NewMultiReaderConn creates a net.Conn whose Read() method will
// first return peekedData, then read from originalConn.
func NewMultiReaderConn(originalConn net.Conn, peekedData []byte) net.Conn {
	return &multiReaderConn{
		Conn:   originalConn,
		reader: io.MultiReader(bytes.NewReader(peekedData), originalConn),
	}
}
