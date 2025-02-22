package proxy_router

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// mockConn is a simple in-memory net.Conn implementation for testing.
type mockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
}

func newMockConn(data []byte) *mockConn {
	return &mockConn{
		readBuf:  bytes.NewBuffer(data),
		writeBuf: bytes.NewBuffer(nil),
		closed:   false,
	}
}

func (m *mockConn) Read(b []byte) (int, error) {
	if m.closed {
		return 0, io.EOF
	}
	return m.readBuf.Read(b)
}

func (m *mockConn) Write(b []byte) (int, error) {
	if m.closed {
		return 0, io.EOF
	}
	return m.writeBuf.Write(b)
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr           { return nil }
func (m *mockConn) RemoteAddr() net.Addr          { return nil }
func (m *mockConn) SetDeadline(t time.Time) error { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error {
	// In a real test, you could simulate timeouts.
	return nil
}
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// buildTLSRecord is a helper to build a single TLS record with the provided
// recordType, version, and payload.
func buildTLSRecord(recordType byte, major, minor byte, payload []byte) []byte {
	recordLen := len(payload)
	header := []byte{
		recordType,
		major,
		minor,
		byte(recordLen >> 8),
		byte(recordLen & 0xff),
	}
	return append(header, payload...)
}

// buildClientHelloPayload constructs a minimal ClientHello handshake message
// with optional SNI. This includes the 4-byte handshake header (type + length).
func buildClientHelloPayload(serverName string) []byte {
	// We'll build the actual ClientHello bytes (excluding the handshake header).
	// Fields:
	// - client_version(2) + random(32)
	// - session_id_length(1) + session_id
	// - cipher_suites_length(2) + cipher_suites
	// - compression_methods_length(1) + compression_methods
	// - extensions_length(2) + extensions (if any)

	// For SNI extension, we build a single extension of type 0, containing
	// a single hostname entry.

	var hello cryptobyte.Builder

	// client_version(2) + random(32)
	hello.AddUint16(0x0303)          // example TLS 1.2 version in the ClientHello
	hello.AddBytes(make([]byte, 32)) // random

	// session_id
	hello.AddUint8(0) // length=0

	// cipher_suites
	hello.AddUint16(2)      // length = 2
	hello.AddUint16(0x1301) // example TLS_AES_128_GCM_SHA256

	// compression_methods
	hello.AddUint8(1) // length=1
	hello.AddUint8(0) // "null" compression

	// Build extensions
	var exts cryptobyte.Builder
	if serverName != "" {
		// SNI extension type = 0
		var sniExt cryptobyte.Builder
		sniExt.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			// server_name_list
			// single entry: name_type (0), length-prefixed hostname
			b.AddUint8(0) // name_type = host_name
			b.AddUint16LengthPrefixed(func(b2 *cryptobyte.Builder) {
				b2.AddBytes([]byte(serverName))
			})
		})

		// Wrap the extension with type=0
		exts.AddUint16(0) // extension type = SNI
		exts.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(sniExt.BytesOrPanic())
		})
	}

	// Add more dummy extensions if needed, or skip if no SNI
	hello.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(exts.BytesOrPanic())
	})

	clientHelloData := hello.BytesOrPanic()

	// Now prepend the 4-byte handshake header:
	// - 1 byte: Handshake Type (1 = ClientHello)
	// - 3 bytes: Handshake Length
	totalLen := len(clientHelloData)
	handshakeHeader := []byte{
		0x01,
		byte(totalLen >> 16),
		byte(totalLen >> 8),
		byte(totalLen & 0xff),
	}

	return append(handshakeHeader, clientHelloData...)
}

// TestSniSniffer_SniffSNI tests the main entrypoint.
func TestSniSniffer_SniffSNI(t *testing.T) {
	tests := []struct {
		name         string
		sniffer      SniSniffer
		inputRecords [][]byte
		wantSNI      string
		wantErr      bool
		errContains  string
	}{
		{
			name: "Valid single record with SNI",
			sniffer: SniSniffer{
				MaxReadSize: 65536,
				Timeout:     0,
			},
			inputRecords: [][]byte{
				buildTLSRecord(
					0x16,       // Handshake
					0x03, 0x04, // TLS 1.3 record version
					buildClientHelloPayload("example.com"),
				),
			},
			wantSNI: "example.com",
			wantErr: false,
		},
		{
			name: "Valid single record with no SNI",
			sniffer: SniSniffer{
				MaxReadSize: 65536,
				Timeout:     0,
			},
			inputRecords: [][]byte{
				buildTLSRecord(
					0x16,
					0x03, 0x04,
					buildClientHelloPayload(""), // no SNI
				),
			},
			wantSNI: "",
			wantErr: false,
		},
		{
			name: "Invalid TLS version",
			sniffer: SniSniffer{
				MaxReadSize: 65536,
				Timeout:     0,
			},
			inputRecords: [][]byte{
				buildTLSRecord(
					0x16,
					0x03, 0x03, // TLS 1.2 -> we explicitly disallow in code
					buildClientHelloPayload("test.com"),
				),
			},
			wantSNI:     "",
			wantErr:     true,
			errContains: "unsupported TLS version 3.3",
		},
		{
			name: "Record length = 0",
			sniffer: SniSniffer{
				MaxReadSize: 65536,
				Timeout:     0,
			},
			// Build a header with length=0
			inputRecords: [][]byte{
				{0x16, 0x03, 0x04, 0x00, 0x00},
			},
			wantErr:     true,
			errContains: "TLS record length is 0",
		},
		{
			name: "Not a handshake record",
			sniffer: SniSniffer{
				MaxReadSize: 65536,
				Timeout:     0,
			},
			inputRecords: [][]byte{
				buildTLSRecord(
					0x15, // Something else (alert?)
					0x03, 0x04,
					[]byte{0x01, 0x02, 0x03}, // minimal data
				),
			},
			wantErr:     true,
			errContains: "expected handshake record",
		},
		{
			name: "Not a ClientHello (handshake type != 0x01)",
			sniffer: SniSniffer{
				MaxReadSize: 65536,
				Timeout:     0,
			},
			inputRecords: [][]byte{
				buildTLSRecord(
					0x16,
					0x03, 0x04,
					// handshake type 0x02 = ServerHello, for example
					append([]byte{0x02, 0x00, 0x00, 0x05}, make([]byte, 5)...),
				),
			},
			wantErr:     true,
			errContains: "not a ClientHello",
		},
		{
			name: "Multiple records needed for ClientHello",
			sniffer: SniSniffer{
				MaxReadSize: 65536,
				Timeout:     0,
			},
			// We'll split the ClientHello across two records
			// 1) Record #1: partial handshake data
			// 2) Record #2: the rest
			inputRecords: [][]byte{
				buildTLSRecord(
					0x16, 0x03, 0x04,
					// Let's cut the ClientHello in half
					buildClientHelloPayload("multi-record")[:10],
				),
				buildTLSRecord(
					0x16, 0x03, 0x04,
					buildClientHelloPayload("multi-record")[10:],
				),
			},
			wantSNI: "multi-record",
			wantErr: false,
		},
		{
			name: "Exceed MaxReadSize",
			sniffer: SniSniffer{
				MaxReadSize: 20, // small max read
				Timeout:     0,
			},
			inputRecords: [][]byte{
				buildTLSRecord(
					0x16, 0x03, 0x04,
					buildClientHelloPayload("toolong"),
				),
			},
			wantErr:     true,
			errContains: "too much data without completing ClientHello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Combine all inputRecords into one byte slice
			var combined []byte
			for _, rec := range tt.inputRecords {
				combined = append(combined, rec...)
			}

			mc := newMockConn(combined)
			sni, allData, err := tt.sniffer.SniffSNI(mc)
			if (err != nil) != tt.wantErr {
				t.Errorf("SniffSNI() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.errContains != "" && err != nil {
				if !bytes.Contains([]byte(err.Error()), []byte(tt.errContains)) {
					t.Errorf("Error %v does not contain %q", err, tt.errContains)
				}
			}
			if sni != tt.wantSNI {
				t.Errorf("SniffSNI() got SNI = %q, want %q", sni, tt.wantSNI)
			}
			if len(allData) == 0 && !tt.wantErr {
				t.Error("SniffSNI() returned 0 allData on success")
			}
		})
	}
}

// TestParseSNI tests the internal parseSNI function directly.
func TestParseSNI(t *testing.T) {
	tests := []struct {
		name       string
		handshake  []byte
		wantSNI    string
		wantErr    bool
		errContain string
	}{
		{
			name:      "Valid ClientHello with SNI",
			handshake: buildClientHelloPayload("example.com"),
			wantSNI:   "example.com",
			wantErr:   false,
		},
		{
			name:      "Valid ClientHello, no SNI extension",
			handshake: buildClientHelloPayload(""), // no SNI
			wantSNI:   "",
			wantErr:   false,
		},
		{
			name:       "Not a ClientHello (type=2)",
			handshake:  append([]byte{0x02, 0x00, 0x00, 0x05}, make([]byte, 5)...),
			wantErr:    true,
			errContain: "not a ClientHello",
		},
		{
			name:       "Handshake too short",
			handshake:  []byte{0x01, 0x00, 0x00}, // only 3 bytes
			wantErr:    true,
			errContain: "handshake too short",
		},
		{
			name:       "Incomplete ClientHello data",
			handshake:  []byte{0x01, 0x00, 0x00, 0x10}, // claims length=16 but doesn't provide enough
			wantErr:    true,
			errContain: "incomplete ClientHello data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sni, err := parseSNI(tt.handshake)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSNI() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.errContain != "" && err != nil {
				if !bytes.Contains([]byte(err.Error()), []byte(tt.errContain)) {
					t.Errorf("Error %v does not contain %q", err, tt.errContain)
				}
			}
			if sni != tt.wantSNI {
				t.Errorf("parseSNI() got = %q, want %q", sni, tt.wantSNI)
			}
		})
	}
}

// TestParseSNIExtension tests the internal parseSNIExtension function directly.
func TestParseSNIExtension(t *testing.T) {
	tests := []struct {
		name         string
		extDataBuild func() []byte
		wantSNI      string
		wantErr      bool
		errContains  string
	}{
		{
			name: "Single host_name, valid",
			extDataBuild: func() []byte {
				// We want to build the extension data such that:
				//   server_name_list_length (2 bytes)
				//     -> name_type(1 byte) = 0
				//     -> name_length(2 bytes)
				//     -> host_name([]byte)
				var b cryptobyte.Builder
				b.AddUint16LengthPrefixed(func(b2 *cryptobyte.Builder) {
					// one entry
					b2.AddUint8(0) // name_type = 0
					b2.AddUint16LengthPrefixed(func(b3 *cryptobyte.Builder) {
						b3.AddBytes([]byte("example.com"))
					})
				})
				return b.BytesOrPanic()
			},
			wantSNI: "example.com",
			wantErr: false,
		},
		{
			name: "Empty server_name_list",
			extDataBuild: func() []byte {
				var b cryptobyte.Builder
				b.AddUint16(0) // length=0, no names
				return b.BytesOrPanic()
			},
			wantSNI: "",
			wantErr: false,
		},
		{
			name: "Malformed extension data (cannot read server_name_list length)",
			extDataBuild: func() []byte {
				return []byte{} // completely empty
			},
			wantErr:     true,
			errContains: "could not read server_name_list length",
		},
		{
			name: "name_type missing",
			extDataBuild: func() []byte {
				var b cryptobyte.Builder
				// Claim a length but don't provide any data
				b.AddUint16(5) // says 5 bytes follow, but we won't provide them
				return b.BytesOrPanic()
			},
			wantErr:     true,
			errContains: "could not read name_type",
		},
		{
			name: "name_length missing",
			extDataBuild: func() []byte {
				var b cryptobyte.Builder
				b.AddUint16LengthPrefixed(func(b2 *cryptobyte.Builder) {
					b2.AddUint8(0) // name_type
					// Omit the length and actual name data
				})
				return b.BytesOrPanic()
			},
			wantErr:     true,
			errContains: "could not read host_name length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extData := cryptobyte.String(tt.extDataBuild())
			sni, err := parseSNIExtension(extData)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSNIExtension() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.errContains != "" && err != nil {
				if !bytes.Contains([]byte(err.Error()), []byte(tt.errContains)) {
					t.Errorf("Error %v does not contain %q", err, tt.errContains)
				}
			}
			if sni != tt.wantSNI {
				t.Errorf("parseSNIExtension() got = %q, want %q", sni, tt.wantSNI)
			}
		})
	}
}

// -- OPTIONAL EXAMPLE --
// Demonstration of testing the Timeout feature (may be tricky or brittle):
// This test forces a small read, then tries to read again, simulating a stall.
// You might skip or adapt this test as needed.
/*
func TestSniSniffer_Timeout(t *testing.T) {
	sniffer := SniSniffer{
		MaxReadSize: 65536,
		Timeout:     10 * time.Millisecond, // short timeout
	}
	// We'll create a mockConn that returns partial data and then blocks.
	partialRecord := buildTLSRecord(0x16, 0x03, 0x04, []byte{0x01, 0x00, 0x00, 0x05}) // incomplete data
	mc := newMockConn(partialRecord)

	start := time.Now()
	_, _, err := sniffer.SniffSNI(mc)
	elapsed := time.Since(start)

	if err == nil {
		t.Errorf("expected timeout error, got nil")
	}
	if elapsed < sniffer.Timeout {
		t.Errorf("expected to wait at least %v, only waited %v", sniffer.Timeout, elapsed)
	}
}
*/
