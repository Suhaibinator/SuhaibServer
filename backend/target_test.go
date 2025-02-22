package backend

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Suhaibinator/SuhaibServer/config"
)

// TestNewBackend covers creation of a Backend using NewBackend.
// We demonstrate tests for both the "terminateTLS" == false case,
// and the "terminateTLS" == true case.
func TestNewBackend(t *testing.T) {
	_, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("terminateTLS=false", func(t *testing.T) {
		// Build a BackendConfig that does NOT terminate TLS
		bcfg := config.BackendConfig{
			HostName:     "dummy",
			TerminateTLS: false,
			MTLSEnabled:  false,
			// No cert/key needed when TLS termination is false
			TLSCertFile:  "",
			TLSKeyFile:   "",
			RootCAFile:   "",
			OriginServer: "127.0.0.1",
			OriginPort:   "8080",
		}

		b, err := NewBackendFromConfig(bcfg)
		if err != nil {
			t.Fatalf("unexpected error creating backend: %v", err)
		}
		if b == nil {
			t.Fatal("expected non-nil backend")
		}
		if b.TerminateTLS {
			t.Error("expected TerminateTLS to be false")
		}
		if b.InboundTLSConfig != nil {
			t.Error("expected InboundTLSConfig to be nil for non-TLS backend")
		}
		if b.ReverseProxy == nil {
			t.Error("expected ReverseProxy to be non-nil")
		}
	})

	t.Run("terminateTLS=true with invalid cert/key", func(t *testing.T) {
		// Build a BackendConfig that DOES terminate TLS but points to non-existent cert/key
		bcfg := config.BackendConfig{
			HostName:     "dummyTLS",
			TerminateTLS: true,
			MTLSEnabled:  false,
			TLSCertFile:  "non_existent_cert.pem",
			TLSKeyFile:   "non_existent_key.pem",
			RootCAFile:   "",
			OriginServer: "127.0.0.1",
			OriginPort:   "8080",
		}

		_, err := NewBackendFromConfig(bcfg)
		if err == nil {
			t.Fatal("expected error due to invalid cert/key file paths, got nil")
		}
	})
}

// TestTunnelTCP verifies that data is tunneled correctly over a raw TCP connection.
func TestTunnelTCP(t *testing.T) {
	_, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// This is your "client" connection:
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Start a real TCP listener to represent the backend.
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on backend: %v", err)
	}
	defer backendLn.Close()

	// Handle one incoming connection in the backend by simply echoing data
	go func() {
		backendConn, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer backendConn.Close()
		// In a real scenario, you'd read/write to backendConn
		// For testing, maybe just echo the data
		_, _ = io.Copy(backendConn, backendConn)
	}()

	// Launch tunnelTCP in a goroutine, using the real backend address
	go func() {
		_ = tunnelTCP(serverConn, backendLn.Addr().String())
	}()

	// Now test that data from clientConn goes through the tunnel -> backend -> back
	testMsg := []byte("hello tunnel")
	_, err = clientConn.Write(testMsg)
	if err != nil {
		t.Fatalf("failed to write to clientConn: %v", err)
	}

	// In this simple echo example, read it back on clientConn
	buf := make([]byte, len(testMsg))
	_, err = io.ReadFull(clientConn, buf)
	if err != nil {
		t.Fatalf("failed to read echoed data: %v", err)
	}
	if string(buf) != string(testMsg) {
		t.Errorf("expected %q, got %q", string(testMsg), string(buf))
	}
}

// TestSingleConnListener ensures singleConnListener only returns one connection and then errors.
func TestSingleConnListener(t *testing.T) {
	_, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	ln := &singleConnListener{
		conn: serverConn,
		done: make(chan struct{}),
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("unexpected error on first Accept: %v", err)
			return
		}
		if conn == nil {
			t.Error("expected non-nil connection on first Accept")
			return
		}
		// Second Accept should fail
		conn2, err2 := ln.Accept()
		if err2 == nil {
			t.Error("expected error on second Accept, got nil")
		}
		if conn2 != nil {
			t.Error("expected nil conn on second Accept")
		}
	}()

	wg.Wait()

	if ln.Addr() != serverConn.LocalAddr() {
		t.Errorf("listener Addr() mismatch; got %v, want %v", ln.Addr(), serverConn.LocalAddr())
	}

	// Close the listener
	err := ln.Close()
	if err != nil {
		t.Errorf("listener Close error: %v", err)
	}
}

// TestBuildInboundTLSConfig demonstrates a basic check of buildInboundTLSConfig.
// It expects valid cert/key files. For demonstration, we generate them on-the-fly
// in code, but you could load them from testdata if you prefer.
func TestBuildInboundTLSConfig(t *testing.T) {
	_, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Generate a temporary self-signed cert/key
	certPem, keyPem, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate self-signed cert: %v", err)
	}

	// Write them to temp files so the function can read them
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	err = os.WriteFile(certFile, certPem, 0600)
	if err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	err = os.WriteFile(keyFile, keyPem, 0600)
	if err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Create a Backend with the cert/key, no RootCA
	b := &Backend{
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		RootCAFile:  "",
	}

	// Here we explicitly pass 'false' to indicate mTLS is disabled.
	cfg, err := b.buildInboundTLSConfig(false)
	if err != nil {
		t.Fatalf("buildInboundTLSConfig(false) error: %v", err)
	}

	// We should have exactly one certificate loaded.
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected exactly 1 certificate, got %d", len(cfg.Certificates))
	}

	// Because we passed false, we expect no client cert enforcement.
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("expected NoClientCert, got %v", cfg.ClientAuth)
	}
}

// TestBuildReverseProxy does a simple check that a ReverseProxy is created
// with the correct origin host/port.
func TestBuildReverseProxy(t *testing.T) {
	_, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	b := &Backend{
		OriginServer: "example.com",
		OriginPort:   "1234",
	}
	rp, err := b.buildReverseProxy()
	if err != nil {
		t.Fatalf("BuildReverseProxy error: %v", err)
	}
	// The Director should rewrite requests to "http://example.com:1234"
	req, _ := http.NewRequest("GET", "http://originalhost/", nil)
	rp.Director(req)
	if req.URL.Scheme != "http" {
		t.Errorf("expected scheme=http, got %s", req.URL.Scheme)
	}
	if req.URL.Host != "example.com:1234" {
		t.Errorf("expected host=example.com:1234, got %s", req.URL.Host)
	}
}

// Below is a very simple test for the Handle method in pass-through mode.
// For TLS-termination tests, you'd need to set up a real or fake TLS dial
// to fully exercise the http.Server / TLS handshake logic. That becomes
// more of an integration test than a pure unit test.
func TestBackendHandle_PassThrough(t *testing.T) {
	_, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create a backend that does NOT terminate TLS
	b := &Backend{
		TerminateTLS: false,
		OriginServer: "127.0.0.1",
		OriginPort:   "9090", // We'll run a tiny server on 9090
	}

	// Start a TCP server that echoes data
	l, err := net.Listen("tcp", "127.0.0.1:9090")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	go func() {
		conn, err2 := l.Accept()
		if err2 != nil {
			return
		}
		defer conn.Close()
		// echo server
		io.Copy(conn, conn)
	}()

	// net.Pipe to simulate client -> b.Handle -> server
	clientConn, serverSide := net.Pipe()
	defer clientConn.Close()
	defer serverSide.Close()

	// We'll run b.Handle in a goroutine
	go func() {
		_ = b.Handle(serverSide, "some-sni")
	}()

	// Write data from client side
	testMsg := []byte("hello pass-through")
	if _, err := clientConn.Write(testMsg); err != nil {
		t.Fatalf("client write error: %v", err)
	}

	// We'll read from the client side as well to see if the echo came back
	echoBuf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(clientConn, echoBuf); err != nil {
		t.Fatalf("client read error: %v", err)
	}
	if string(echoBuf) != string(testMsg) {
		t.Errorf("expected echo %q, got %q", string(testMsg), string(echoBuf))
	}
}

// generateSelfSignedCert creates an ephemeral RSA key pair and self-signed certificate.
// It returns the certificate and private key in PEM-encoded form.
func generateSelfSignedCert() (certPem, keyPem []byte, err error) {
	// 1) Generate a new RSA private key. For testing, 2048 bits is sufficient.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("rsa.GenerateKey: %w", err)
	}

	// 2) Create a certificate template.
	//    - If you're testing a "real" TLS server, you might want the Subject Alt Names, etc.
	//    - This example just uses a single CommonName and short validity period.
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<48))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(time.Hour),

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		// This is a self-signed cert, so the issuer is the same as the subject.
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	// 3) Self-sign the certificate (template -> DER bytes).
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template, // since self-signed, parent = template
		&privKey.PublicKey,
		privKey,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("x509.CreateCertificate: %w", err)
	}

	// 4) PEM-encode the certificate.
	certBuf := &bytes.Buffer{}
	if err := pem.Encode(certBuf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}); err != nil {
		return nil, nil, fmt.Errorf("pem.Encode certificate: %w", err)
	}

	// 5) Convert the private key to PKCS#8 DER and PEM-encode it.
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("x509.MarshalPKCS8PrivateKey: %w", err)
	}
	keyBuf := &bytes.Buffer{}
	if err := pem.Encode(keyBuf, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}); err != nil {
		return nil, nil, fmt.Errorf("pem.Encode private key: %w", err)
	}

	return certBuf.Bytes(), keyBuf.Bytes(), nil
}
