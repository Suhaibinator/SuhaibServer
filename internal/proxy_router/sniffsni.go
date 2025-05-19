package proxy_router

import (
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

type SniSniffer struct {
	MaxReadSize int           // e.g., 65536
	Timeout     time.Duration // e.g., 5 * time.Second
}

// sniffSNI will read one or more TLS records from conn until
// it obtains a complete ClientHello handshake message. It returns:
//
//   - sni: the ServerName from the ClientHello (empty if none)
//   - allData: all bytes read from the connection (record headers + payload)
//   - error if something goes wrong
func (s *SniSniffer) SniffSNI(conn net.Conn) (sni string, allData []byte, err error) {
	// We accumulate handshake bytes here.
	var handshakeBuf []byte

	// We'll track how many bytes we need for the ClientHello message
	// (1 byte for handshake type + 3 bytes for handshake length + the message itself)
	clientHelloNeeded := -1

	for {
		// ---------------------------------------------------------------------
		// 1) Read the 5-byte TLS record header
		// ---------------------------------------------------------------------
		if s.Timeout > 0 {
			// Set a read deadline so we don't block forever
			_ = conn.SetReadDeadline(time.Now().Add(s.Timeout))
		}

		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return "", allData, fmt.Errorf("failed reading record header: %v", err)
		}
		allData = append(allData, header...)

		recordType := header[0] // 0x16 == Handshake
		// versionMajor := header[1] // e.g. 0x03
		// versionMinor := header[2] // e.g. 0x03 (TLS 1.2), 0x04 (TLS 1.3)

		recordLen := int(header[3])<<8 | int(header[4])

		if recordLen == 0 {
			return "", allData, fmt.Errorf("TLS record length is 0")
		}

		// Optional check: block very old TLS versions (just an example)
		// if versionMajor == 0x01 && versionMinor < 0x03 {
		//     return "", allData, fmt.Errorf("TLS version too old, min is TLS 1.3")
		// }

		// ---------------------------------------------------------------------
		// 2) Read the record payload
		// ---------------------------------------------------------------------
		if s.Timeout > 0 {
			// Reset the read deadline for the payload read
			_ = conn.SetReadDeadline(time.Now().Add(s.Timeout))
		}

		if len(allData)+recordLen > s.MaxReadSize {
			return "", allData, fmt.Errorf("too much data without completing ClientHello, possible attack")
		}

		payload := make([]byte, recordLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return "", allData, fmt.Errorf("failed reading record payload: %v", err)
		}
		allData = append(allData, payload...)

		if len(allData) > s.MaxReadSize {
			return "", allData, fmt.Errorf("too much data without completing ClientHello, possible attack")
		}

		// ---------------------------------------------------------------------
		// 3) We only care about Handshake records for the ClientHello
		// ---------------------------------------------------------------------
		if recordType != 0x16 {
			return "", allData, fmt.Errorf("expected handshake record (type=0x16), got 0x%02x", recordType)
		}

		// Accumulate handshake bytes
		handshakeBuf = append(handshakeBuf, payload...)

		// ---------------------------------------------------------------------
		// 4) Check if we can determine the total ClientHello length
		// ---------------------------------------------------------------------
		// If we haven't yet figured out how big the ClientHello is, try to parse
		// the first 4 bytes of handshakeBuf:
		if clientHelloNeeded < 0 && len(handshakeBuf) >= 4 {
			// The first byte must be handshake type = 0x01 (ClientHello)
			if handshakeBuf[0] != 0x01 {
				return "", allData, fmt.Errorf("not a ClientHello (handshake type=%d)", handshakeBuf[0])
			}
			// Next 3 bytes are the handshake message length
			msgLen := int(handshakeBuf[1])<<16 |
				int(handshakeBuf[2])<<8 |
				int(handshakeBuf[3])
			clientHelloNeeded = 4 + msgLen
		}

		// ---------------------------------------------------------------------
		// 5) If we have enough data for the entire ClientHello, parse the SNI
		// ---------------------------------------------------------------------
		if clientHelloNeeded > 0 && len(handshakeBuf) >= clientHelloNeeded {
			clientHello := handshakeBuf[:clientHelloNeeded]

			sni, err := parseSNI(clientHello)
			if err != nil {
				return "", allData, fmt.Errorf("failed to parse SNI from ClientHello: %v", err)
			}

			// Done: return the SNI plus all data we read.
			return sni, allData, nil
		}

		// If we still don’t have enough data for the ClientHello, loop again to read another record.
		// For safety, also check an upper bound on how large allData can get (which we did earlier).
	}
}

// parseSNI attempts to parse the SNI from the *handshake portion*
// of the record data (the ClientHello message).
func parseSNI(handshake []byte) (string, error) {
	// handshake[0] is handshake type (must be 0x01 for ClientHello)
	// handshake[1..3] is length of the ClientHello message
	if len(handshake) < 4 {
		return "", fmt.Errorf("handshake too short to contain ClientHello header")
	}
	if handshake[0] != 0x01 {
		return "", fmt.Errorf("not a ClientHello (type=%d)", handshake[0])
	}

	// Next 3 bytes for totalLen
	totalLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+totalLen {
		return "", fmt.Errorf("incomplete ClientHello data (need %d, have %d)",
			4+totalLen, len(handshake))
	}

	// The actual ClientHello struct
	clientHelloData := handshake[4 : 4+totalLen]
	s := cryptobyte.String(clientHelloData)

	// Minimal parse. We skip a bunch of fields until we reach the extensions.
	// -------------------------------------
	// uint16 client_version
	// opaque random[32]
	if !s.Skip(2 + 32) {
		return "", fmt.Errorf("unable to skip client_version + random")
	}

	// session_id (length-prefixed by 1 byte)
	var sessionIDLen uint8
	if !s.ReadUint8(&sessionIDLen) {
		return "", fmt.Errorf("unable to read session_id length")
	}
	if !s.Skip(int(sessionIDLen)) {
		return "", fmt.Errorf("truncated session_id")
	}

	// cipher_suites (length-prefixed by 2 bytes)
	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return "", fmt.Errorf("unable to read cipher_suites length")
	}
	// No extra skip needed here!

	// compression_methods (length-prefixed by 1 byte)
	var compressionLen uint8
	if !s.ReadUint8(&compressionLen) {
		return "", fmt.Errorf("unable to read compression_methods length")
	}
	if !s.Skip(int(compressionLen)) {
		return "", fmt.Errorf("truncated compression_methods")
	}

	// extensions (length-prefixed by 2 bytes)
	var exts cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&exts) {
		// No extensions at all => no SNI
		return "", nil
	}

	// Now parse each extension
	var serverName string
	for len(exts) > 0 {
		var extType uint16
		var extData cryptobyte.String
		if !exts.ReadUint16(&extType) ||
			!exts.ReadUint16LengthPrefixed(&extData) {
			return "", fmt.Errorf("unable to read extension header")
		}

		// SNI extension = 0
		if extType == 0 {
			name, err := parseSNIExtension(extData)
			if err != nil {
				return "", fmt.Errorf("failed to parse SNI extension: %w", err)
			}
			serverName = name
			break // typically only one SNI extension
		}
	}

	return serverName, nil
}

// parseSNIExtension parses just the SNI extension data.
func parseSNIExtension(ext cryptobyte.String) (string, error) {
	// The extension data starts with a 2-byte length for the server_name_list
	var serverNameList cryptobyte.String
	if !ext.ReadUint16LengthPrefixed(&serverNameList) {
		return "", fmt.Errorf("could not read server_name_list length")
	}

	var hostname string
	for len(serverNameList) > 0 {
		var nameType uint8
		var nameData cryptobyte.String
		// Each entry:
		//   uint8 name_type
		//   uint16 name_length
		if !serverNameList.ReadUint8(&nameType) {
			return "", fmt.Errorf("could not read name_type")
		}
		if !serverNameList.ReadUint16LengthPrefixed(&nameData) {
			return "", fmt.Errorf("could not read host_name length")
		}

		if nameType == 0 {
			// SNI host_name
			hostname = string(nameData)
			// Typically only one SNI name
			break
		}
	}

	return hostname, nil
}
