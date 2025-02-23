package proxy_router

import (
	"bytes"
	"io"
	"net"
	"sync"
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
		require.Equal(t, "peek", string(buf[:n]))
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
		require.Equal(t, "initial data", string(buf[:n]))
	})
}

// TestMultiReaderConn_PartialReads checks reading in small chunks.
func TestMultiReaderConn_PartialReads(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	peekedData := []byte("ABC")
	mc := NewMultiReaderConn(clientConn, peekedData)

	// Server writes something after a brief delay
	go func() {
		time.Sleep(10 * time.Millisecond)
		_, _ = serverConn.Write([]byte("DEF")) // total "ABCDEF" expected
		_ = serverConn.Close()
	}()

	readBuf := make([]byte, 2)

	// 1) First partial read -> "AB" from the peekedData
	n, err := mc.Read(readBuf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := string(readBuf[:n]); got != "AB" {
		t.Errorf("partial read mismatch; want 'AB', got %q", got)
	}

	// 2) Next partial read -> "C" from the peekedData
	n, err = mc.Read(readBuf)
	if err != nil && err != io.EOF {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := string(readBuf[:n]); got != "C" {
		t.Errorf("partial read mismatch; want 'C', got %q", got)
	}

	// 3) Next partial reads -> from the server: "DE" and then "F"
	n, err = mc.Read(readBuf)
	if err != nil && err != io.EOF {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := string(readBuf[:n]); got != "DE" {
		t.Errorf("partial read mismatch; want 'DE', got %q", got)
	}

	n, err = mc.Read(readBuf)
	if err != nil && err != io.EOF {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := string(readBuf[:n]); got != "F" {
		t.Errorf("partial read mismatch; want 'F', got %q", got)
	}

	// 4) Should now be EOF
	n, err = mc.Read(readBuf)
	if err != io.EOF && err != nil {
		t.Errorf("expected EOF, got %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes at EOF, got %d", n)
	}
}

// TestMultiReaderConn_EmptyPeeked ensures behavior is normal if peekedData is empty.
func TestMultiReaderConn_EmptyPeeked(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	// Wrap with empty peek data
	mc := NewMultiReaderConn(clientConn, nil)

	// Write something from server side
	go func() {
		_, _ = serverConn.Write([]byte("HELLO"))
		_ = serverConn.Close()
	}()

	// Expect immediate read from the underlying conn (because no peek).
	buf := make([]byte, 10)
	n, err := mc.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("unexpected read error: %v", err)
	}
	if got := string(buf[:n]); got != "HELLO" {
		t.Errorf("expected to read 'HELLO', got %q", got)
	}

	// Next read should get EOF.
	n2, err2 := mc.Read(buf)
	if err2 != io.EOF && err2 != nil {
		t.Errorf("expected EOF, got %v", err2)
	}
	if n2 != 0 {
		t.Errorf("expected 0 bytes at EOF, got %d", n2)
	}
}

// TestMultiReaderConn_DelegatedMethods verifies that methods other than Read()
// (e.g. Write, Close, LocalAddr, RemoteAddr) are delegated to the underlying conn.
func TestMultiReaderConn_DelegatedMethods(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	// We'll wrap clientConn. Use some trivial peeked data for completeness.
	mc := NewMultiReaderConn(clientConn, []byte("PEEK"))

	// Check LocalAddr / RemoteAddr delegation
	if mc.LocalAddr() != clientConn.LocalAddr() {
		t.Errorf("LocalAddr() not delegated properly; got %v, want %v",
			mc.LocalAddr(), clientConn.LocalAddr())
	}
	if mc.RemoteAddr() != clientConn.RemoteAddr() {
		t.Errorf("RemoteAddr() not delegated properly; got %v, want %v",
			mc.RemoteAddr(), clientConn.RemoteAddr())
	}

	// Check Write delegation:
	// We'll write from mc to serverConn, read from serverConn side to confirm.
	wantData := []byte("TEST_WRITE")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, len(wantData))
		n, err := serverConn.Read(buf)
		if err != nil {
			t.Errorf("serverConn.Read error: %v", err)
			return
		}
		if string(buf[:n]) != string(wantData) {
			t.Errorf("serverConn got %q, want %q", buf[:n], wantData)
		}
	}()

	n, err := mc.Write(wantData)
	if err != nil {
		t.Fatalf("unexpected error on Write: %v", err)
	}
	if n != len(wantData) {
		t.Fatalf("short write: wrote %d, expected %d", n, len(wantData))
	}
	wg.Wait()

	// Check SetDeadline (and others like SetReadDeadline, SetWriteDeadline)
	// Just ensure they don't panic and are delegated. We won't do full functional tests here.
	err = mc.SetDeadline(time.Now().Add(time.Second))
	if err != nil {
		t.Errorf("SetDeadline returned error: %v", err)
	}

	// Finally, check Close delegation
	err = mc.Close()
	if err != nil {
		t.Errorf("unexpected error on mc.Close(): %v", err)
	}
	// Now the underlying connection should also be closed; a further write should fail
	_, err = clientConn.Write([]byte("SHOULD_FAIL"))
	if err == nil {
		t.Error("expected write to closed connection to fail, got nil error")
	}
}

// TestMultiReaderConn_ReadAll uses io.ReadAll to confirm the entire
// "peeked" plus underlying data is returned in one shot.
func TestMultiReaderConn_ReadAll(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	peeked := []byte("FIRST_PART_")
	mc := NewMultiReaderConn(clientConn, peeked)

	// Write from the server side, then close.
	go func() {
		data := []byte("SECOND_PART")
		_, _ = serverConn.Write(data)
		_ = serverConn.Close()
	}()

	allData, err := io.ReadAll(mc)
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	want := "FIRST_PART_SECOND_PART"
	if string(allData) != want {
		t.Errorf("ReadAll mismatch: got %q, want %q", string(allData), want)
	}
}

func TestMultiReader_SingleCallWithBuffers(t *testing.T) {
	peeked := bytes.NewReader([]byte("12345"))
	rest := bytes.NewReader([]byte("67890"))
	combined := io.MultiReader(peeked, rest)

	// We'll read until we exhaust both parts:
	var all []byte
	buf := make([]byte, 10)
	for {
		n, err := combined.Read(buf)
		if n > 0 {
			all = append(all, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
	}
	got := string(all)
	want := "1234567890"
	if got != want {
		t.Errorf("Read mismatch: got %q, want %q", got, want)
	}
}

// TestMultiReaderConn_MultipleWritesFromServer verifies that multiple writes
// from the server side still appear as a continuous stream to the client.
func TestMultiReaderConn_MultipleWritesFromServer(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	peeked := []byte("HELLO_")
	mc := NewMultiReaderConn(clientConn, peeked)

	go func() {
		// Server writes in multiple steps.
		serverConn.Write([]byte("PART_1_"))
		time.Sleep(10 * time.Millisecond)
		serverConn.Write([]byte("PART_2_"))
		time.Sleep(10 * time.Millisecond)
		serverConn.Write([]byte("PART_3"))
		serverConn.Close()
	}()

	// Instead of a single Read, read until EOF:
	var allData []byte
	buf := make([]byte, 32)
	for {
		n, err := mc.Read(buf)
		if n > 0 {
			allData = append(allData, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	got := string(allData)
	want := "HELLO_PART_1_PART_2_PART_3"
	if got != want {
		t.Errorf("multiple writes mismatch:\n got  %q\n want %q", got, want)
	}
}

// TestMultiReaderConn_EarlyServerClose verifies behavior when the server
// closes the connection without sending all expected data. We should read
// whatever was sent and then get EOF.
func TestMultiReaderConn_EarlyServerClose(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	peeked := []byte("PEEKED_DATA_")
	mc := NewMultiReaderConn(clientConn, peeked)

	go func() {
		// Write only partial data, then close unexpectedly
		serverConn.Write([]byte("ONLY_HALF"))
		serverConn.Close()
	}()

	var allData []byte
	buf := make([]byte, 32)
	for {
		n, err := mc.Read(buf)
		if n > 0 {
			allData = append(allData, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected read error: %v", err)
		}
	}

	got := string(allData)
	want := "PEEKED_DATA_ONLY_HALF"
	if got != want {
		t.Errorf("early close mismatch:\n got  %q\n want %q", got, want)
	}
}
