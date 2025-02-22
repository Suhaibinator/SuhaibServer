package proxy_router

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A simple mockedConn2 that implements net.Conn by wrapping a *bytes.Buffer.
type mockedConn2 struct {
	*bytes.Buffer
}

func (m *mockedConn2) Close() error                       { return nil }
func (m *mockedConn2) LocalAddr() net.Addr                { return nil }
func (m *mockedConn2) RemoteAddr() net.Addr               { return nil }
func (m *mockedConn2) SetDeadline(t time.Time) error      { return nil }
func (m *mockedConn2) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockedConn2) SetWriteDeadline(t time.Time) error { return nil }

func TestPeekedConn(t *testing.T) {

	t.Run("no peeked data, reads from underlying conn", func(t *testing.T) {
		underlying := &mockedConn2{bytes.NewBufferString("underlying")}
		pc := NewPeekedConn(underlying, nil)

		buf := make([]byte, 20)
		n, err := pc.Read(buf)
		require.NoError(t, err)
		require.Equal(t, "underlying", string(buf[:n]))
	})

	t.Run("partial read of peeked data", func(t *testing.T) {
		underlying := &mockedConn2{bytes.NewBufferString("underlying")}
		peeked := []byte("peeked data")
		pc := NewPeekedConn(underlying, peeked)

		// Request fewer bytes than are in 'peeked'.
		buf := make([]byte, 6)
		n, err := pc.Read(buf)
		require.NoError(t, err)
		require.Equal(t, "peeked", string(buf[:n]))

		// Next read pulls the remainder of peeked data.
		buf2 := make([]byte, 10)
		n2, err := pc.Read(buf2)
		require.NoError(t, err)
		// We only had " data" left in the peeked buffer
		require.Equal(t, " data", string(buf2[:n2]))
	})

	t.Run("read more than peeked, then read underlying", func(t *testing.T) {
		underlying := &mockedConn2{bytes.NewBufferString("under")}
		peeked := []byte("peek")
		pc := NewPeekedConn(underlying, peeked)

		// Buffer larger than total peeked data, so it should read from peeked
		// first, then continue reading from underlying.
		buf := make([]byte, 10)
		n, err := pc.Read(buf)
		require.NoError(t, err)
		// "peek" + "under" = "peekunder"
		require.Equal(t, "peekunder", string(buf[:n]))
	})

	t.Run("multiple reads eventually consume all peeked data", func(t *testing.T) {
		underlying := &mockedConn2{bytes.NewBufferString("conn data")}
		peeked := []byte("abc")
		pc := NewPeekedConn(underlying, peeked)

		// 1st read: 2 bytes from "abc" => "ab"
		buf1 := make([]byte, 2)
		n1, err := pc.Read(buf1)
		require.NoError(t, err)
		require.Equal(t, "ab", string(buf1[:n1]))

		// 2nd read: 1 byte left from "abc" => "c"
		buf2 := make([]byte, 5)
		n2, err := pc.Read(buf2)
		require.NoError(t, err)
		require.Equal(t, "c", string(buf2[:n2]))

		// 3rd read: from underlying => "conn data"
		buf3 := make([]byte, 20)
		n3, err := pc.Read(buf3)
		require.NoError(t, err)
		require.Equal(t, "conn data", string(buf3[:n3]))
	})

	t.Run("empty reads do not skip peeked data", func(t *testing.T) {
		underlying := &mockedConn2{bytes.NewBufferString("after peeked")}
		peeked := []byte("initial data")
		pc := NewPeekedConn(underlying, peeked)

		// Simulate a read of 0 bytes (sometimes used by libraries for checks).
		buf0 := make([]byte, 0)
		n0, err := pc.Read(buf0)
		require.NoError(t, err)
		require.Equal(t, 0, n0)

		// Next read should still return the peeked data first.
		buf := make([]byte, 50)
		n, err := pc.Read(buf)
		require.NoError(t, err)
		// Expect "initial dataafter peeked"
		require.Equal(t, "initial dataafter peeked", string(buf[:n]))
	})
}
