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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Suhaibinator/SuhaibServer/internal/config"
	"github.com/Suhaibinator/SuhaibServer/sdk/hooks"
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
			Hostname:     "dummy",
			TerminateTLS: false,
			MTLSEnabled:  false,
			// No cert/key needed when TLS termination is false
			TLSCertFile:  "",
			TLSKeyFile:   "",
			RootCAFile:   "",
			OriginServer: "127.0.0.1",
			OriginPort:   "8080",
		}

		b, err := NewBackendFromConfig(bcfg, config.BackendHookPlan{})
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
			Hostname:     "dummyTLS",
			TerminateTLS: true,
			MTLSEnabled:  false,
			TLSCertFile:  "non_existent_cert.pem",
			TLSKeyFile:   "non_existent_key.pem",
			RootCAFile:   "",
			OriginServer: "127.0.0.1",
			OriginPort:   "8080",
		}

		_, err := NewBackendFromConfig(bcfg, config.BackendHookPlan{})
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

	t.Run("http scheme", func(t *testing.T) {
		b := &Backend{
			OriginScheme: "http",
			OriginServer: "example.com",
			OriginPort:   "1234",
		}
		rp, err := b.buildReverseProxy()
		if err != nil {
			t.Fatalf("BuildReverseProxy error: %v", err)
		}

		req, _ := http.NewRequest("GET", "http://originalhost/", nil)
		rp.Director(req)
		if req.URL.Scheme != "http" {
			t.Errorf("expected scheme=http, got %s", req.URL.Scheme)
		}
		if req.URL.Host != "example.com:1234" {
			t.Errorf("expected host=example.com:1234, got %s", req.URL.Host)
		}
	})

	t.Run("https scheme", func(t *testing.T) {
		b := &Backend{
			OriginScheme: "https",
			OriginServer: "secure.example.com",
			OriginPort:   "8443",
		}
		rp, err := b.buildReverseProxy()
		if err != nil {
			t.Fatalf("BuildReverseProxy error: %v", err)
		}

		req, _ := http.NewRequest("GET", "http://originalhost/", nil)
		rp.Director(req)
		if req.URL.Scheme != "https" {
			t.Errorf("expected scheme=https, got %s", req.URL.Scheme)
		}
		if req.URL.Host != "secure.example.com:8443" {
			t.Errorf("expected host=secure.example.com:8443, got %s", req.URL.Host)
		}
	})
}

// TestSingleConnListener checks that the listener returns exactly one connection
// on the first Accept call. For subsequent Accept calls, it should block until
// the connection (or the listener) is closed, then return net.ErrClosed.
func TestSingleConnListener(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create a pair of in-memory connection endpoints.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	// Wrap serverConn in our singleConnListener.
	ln := newSingleConnListener(serverConn)

	// 1) First Accept() should succeed and return the connection.
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("unexpected error on first Accept: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil connection on first Accept")
	}

	// 2) Subsequent Accept() calls should block until the connection is closed.
	// We'll test that it indeed blocks, then unblocks with net.ErrClosed.
	errCh := make(chan error, 1)
	go func() {
		// This call should block until the connection or listener is closed.
		c, e := ln.Accept()
		if c != nil {
			_ = c.Close() // be a good citizen and close if we got a conn (unlikely in this path)
		}
		errCh <- e
	}()

	// Check that it's still blocked after a small sleep, i.e. we haven't
	// received from errCh yet.
	select {
	case e := <-errCh:
		t.Fatalf("second Accept() returned prematurely with error: %v", e)
	case <-time.After(100 * time.Millisecond):
		// Good: accept is still blocking as expected.
	}

	// 3) Now close the first Accept()ed connection. This should unblock the second Accept()
	// and cause it to return net.ErrClosed.
	_ = conn.Close()

	// Wait for the second Accept() to unblock.
	var acceptErr error
	select {
	case <-ctx.Done():
		t.Fatal("test timed out waiting for second Accept() to unblock")
	case acceptErr = <-errCh:
		// proceed
	}

	if !errors.Is(acceptErr, net.ErrClosed) {
		t.Fatalf("expected second Accept() error to be net.ErrClosed, got: %v", acceptErr)
	}

	// 4) Check listener address is still reported correctly.
	wantAddr := serverConn.LocalAddr()
	gotAddr := ln.Addr()
	if gotAddr != wantAddr {
		t.Errorf("listener Addr() mismatch: got %v, want %v", gotAddr, wantAddr)
	}

	// 5) Close the listener; further Accept calls should also return net.ErrClosed.
	if err := ln.Close(); err != nil {
		t.Errorf("listener Close() error: %v", err)
	}

	// Optional: Verify that another Accept() after Close() returns net.ErrClosed immediately.
	_, errAfterClose := ln.Accept()
	if !errors.Is(errAfterClose, net.ErrClosed) {
		t.Fatalf("expected Accept() after listener Close() to return net.ErrClosed; got %v", errAfterClose)
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
		OriginScheme: "http",
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

// ========================================================================
// HOOK EXECUTION TESTS
// ========================================================================

// TestRunRequestHooks_Success verifies that request hooks are executed in order.
func TestRunRequestHooks_Success(t *testing.T) {
	ctx := context.Background()
	var called []string

	plan := config.BackendHookPlan{
		Request: []hooks.ResolvedHook{
			{
				Registration: hooks.Registration{
					Name:    "hook1",
					Kind:    hooks.OnRequestReceived,
					Handler: hooks.RequestHook(func(_ context.Context, _ hooks.RequestCtx) error { called = append(called, "hook1"); return nil }),
				},
				Matcher: hooks.Matcher{},
			},
			{
				Registration: hooks.Registration{
					Name:    "hook2",
					Kind:    hooks.OnRequestReceived,
					Handler: hooks.RequestHook(func(_ context.Context, _ hooks.RequestCtx) error { called = append(called, "hook2"); return nil }),
				},
				Matcher: hooks.Matcher{},
			},
		},
	}

	b := &Backend{hookPlan: plan}
	reqCtx := hooks.RequestCtx{Host: "example.com", Path: "/test"}

	err := b.runRequestHooks(ctx, reqCtx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(called) != 2 {
		t.Fatalf("expected 2 hooks called, got %d", len(called))
	}
	if called[0] != "hook1" || called[1] != "hook2" {
		t.Errorf("expected hooks called in order [hook1, hook2], got %v", called)
	}
}

// TestRunRequestHooks_MatcherFiltering verifies that hooks are skipped when matcher doesn't match.
func TestRunRequestHooks_MatcherFiltering(t *testing.T) {
	ctx := context.Background()
	var called []string

	plan := config.BackendHookPlan{
		Request: []hooks.ResolvedHook{
			{
				Registration: hooks.Registration{
					Name:    "matchingHook",
					Kind:    hooks.OnRequestReceived,
					Handler: hooks.RequestHook(func(_ context.Context, _ hooks.RequestCtx) error { called = append(called, "matchingHook"); return nil }),
				},
				Matcher: hooks.Matcher{Host: "example.com"},
			},
			{
				Registration: hooks.Registration{
					Name:    "nonMatchingHook",
					Kind:    hooks.OnRequestReceived,
					Handler: hooks.RequestHook(func(_ context.Context, _ hooks.RequestCtx) error { called = append(called, "nonMatchingHook"); return nil }),
				},
				Matcher: hooks.Matcher{Host: "other.com"},
			},
		},
	}

	b := &Backend{hookPlan: plan}
	reqCtx := hooks.RequestCtx{Host: "example.com", Path: "/test"}

	err := b.runRequestHooks(ctx, reqCtx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(called) != 1 {
		t.Fatalf("expected 1 hook called, got %d", len(called))
	}
	if called[0] != "matchingHook" {
		t.Errorf("expected matchingHook to be called, got %v", called)
	}
}

// TestRunRequestHooks_Error verifies that hook errors are propagated.
func TestRunRequestHooks_Error(t *testing.T) {
	ctx := context.Background()
	expectedErr := errors.New("hook failed")

	plan := config.BackendHookPlan{
		Request: []hooks.ResolvedHook{
			{
				Registration: hooks.Registration{
					Name:    "failingHook",
					Kind:    hooks.OnRequestReceived,
					Handler: hooks.RequestHook(func(_ context.Context, _ hooks.RequestCtx) error { return expectedErr }),
				},
				Matcher: hooks.Matcher{},
			},
		},
	}

	b := &Backend{hookPlan: plan}
	reqCtx := hooks.RequestCtx{Host: "example.com", Path: "/test"}

	err := b.runRequestHooks(ctx, reqCtx)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failingHook") {
		t.Errorf("expected error to contain hook name, got %v", err)
	}
}

// TestRunCompletionHooks_Success verifies that completion hooks are executed.
func TestRunCompletionHooks_Success(t *testing.T) {
	ctx := context.Background()
	var called []string

	plan := config.BackendHookPlan{
		Completion: []hooks.ResolvedHook{
			{
				Registration: hooks.Registration{
					Name:    "completionHook1",
					Kind:    hooks.OnRequestCompleted,
					Handler: hooks.CompletionHook(func(_ context.Context, _ hooks.ResponseCtx) error { called = append(called, "completionHook1"); return nil }),
				},
				Matcher: hooks.Matcher{},
			},
			{
				Registration: hooks.Registration{
					Name:    "completionHook2",
					Kind:    hooks.OnRequestCompleted,
					Handler: hooks.CompletionHook(func(_ context.Context, _ hooks.ResponseCtx) error { called = append(called, "completionHook2"); return nil }),
				},
				Matcher: hooks.Matcher{},
			},
		},
	}

	b := &Backend{hookPlan: plan}
	respCtx := hooks.ResponseCtx{
		ReqCtx: hooks.RequestCtx{Host: "example.com", Path: "/test"},
		Status: 200,
	}

	b.runCompletionHooks(ctx, respCtx)
	if len(called) != 2 {
		t.Fatalf("expected 2 hooks called, got %d", len(called))
	}
	if called[0] != "completionHook1" || called[1] != "completionHook2" {
		t.Errorf("expected hooks called in order [completionHook1, completionHook2], got %v", called)
	}
}

// TestRunCompletionHooks_MatcherFiltering verifies completion hooks respect matchers.
func TestRunCompletionHooks_MatcherFiltering(t *testing.T) {
	ctx := context.Background()
	var called []string

	plan := config.BackendHookPlan{
		Completion: []hooks.ResolvedHook{
			{
				Registration: hooks.Registration{
					Name:    "matchingHook",
					Kind:    hooks.OnRequestCompleted,
					Handler: hooks.CompletionHook(func(_ context.Context, _ hooks.ResponseCtx) error { called = append(called, "matchingHook"); return nil }),
				},
				Matcher: hooks.Matcher{PathPrefix: "/api"},
			},
			{
				Registration: hooks.Registration{
					Name:    "nonMatchingHook",
					Kind:    hooks.OnRequestCompleted,
					Handler: hooks.CompletionHook(func(_ context.Context, _ hooks.ResponseCtx) error { called = append(called, "nonMatchingHook"); return nil }),
				},
				Matcher: hooks.Matcher{PathPrefix: "/admin"},
			},
		},
	}

	b := &Backend{hookPlan: plan}
	respCtx := hooks.ResponseCtx{
		ReqCtx: hooks.RequestCtx{Host: "example.com", Path: "/api/users"},
		Status: 200,
	}

	b.runCompletionHooks(ctx, respCtx)
	if len(called) != 1 {
		t.Fatalf("expected 1 hook called, got %d", len(called))
	}
	if called[0] != "matchingHook" {
		t.Errorf("expected matchingHook to be called, got %v", called)
	}
}

// TestExecuteHook_Timeout verifies that hook timeout is respected.
func TestExecuteHook_Timeout(t *testing.T) {
	ctx := context.Background()

	rh := hooks.ResolvedHook{
		Registration: hooks.Registration{
			Name: "slowHook",
			Kind: hooks.OnRequestReceived,
			Handler: hooks.RequestHook(func(ctx context.Context, _ hooks.RequestCtx) error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(5 * time.Second):
					return nil
				}
			}),
		},
		Matcher: hooks.Matcher{},
		Timeout: 50 * time.Millisecond,
	}

	b := &Backend{}
	reqCtx := hooks.RequestCtx{Host: "example.com", Path: "/test"}

	start := time.Now()
	err := b.executeHook(ctx, rh, reqCtx, hooks.ResponseCtx{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected timeout error message, got %v", err)
	}
	if elapsed > 1*time.Second {
		t.Errorf("expected hook to timeout quickly, took %v", elapsed)
	}
}

// TestExecuteHook_PanicRecovery verifies that panics in hooks are recovered.
func TestExecuteHook_PanicRecovery(t *testing.T) {
	ctx := context.Background()

	rh := hooks.ResolvedHook{
		Registration: hooks.Registration{
			Name: "panicHook",
			Kind: hooks.OnRequestReceived,
			Handler: hooks.RequestHook(func(_ context.Context, _ hooks.RequestCtx) error {
				panic("intentional panic for testing")
			}),
		},
		Matcher: hooks.Matcher{},
	}

	b := &Backend{}
	reqCtx := hooks.RequestCtx{Host: "example.com", Path: "/test"}

	err := b.executeHook(ctx, rh, reqCtx, hooks.ResponseCtx{})
	if err == nil {
		t.Fatal("expected error from panic recovery, got nil")
	}
	if !strings.Contains(err.Error(), "panicked") {
		t.Errorf("expected panic error message, got %v", err)
	}
	if !strings.Contains(err.Error(), "panicHook") {
		t.Errorf("expected error to contain hook name, got %v", err)
	}
}

// TestExecuteHook_UnknownKind verifies error for unknown hook kind.
func TestExecuteHook_UnknownKind(t *testing.T) {
	ctx := context.Background()

	rh := hooks.ResolvedHook{
		Registration: hooks.Registration{
			Name:    "unknownKindHook",
			Kind:    hooks.Kind("unknown_kind"),
			Handler: nil,
		},
		Matcher: hooks.Matcher{},
	}

	b := &Backend{}
	reqCtx := hooks.RequestCtx{Host: "example.com", Path: "/test"}

	err := b.executeHook(ctx, rh, reqCtx, hooks.ResponseCtx{})
	if err == nil {
		t.Fatal("expected error for unknown hook kind, got nil")
	}
	if !strings.Contains(err.Error(), "unknown hook kind") {
		t.Errorf("expected unknown hook kind error, got %v", err)
	}
}

// TestExecuteHook_CompletionHook verifies completion hook execution.
func TestExecuteHook_CompletionHook(t *testing.T) {
	ctx := context.Background()
	var capturedStatus int

	rh := hooks.ResolvedHook{
		Registration: hooks.Registration{
			Name: "completionHook",
			Kind: hooks.OnRequestCompleted,
			Handler: hooks.CompletionHook(func(_ context.Context, rc hooks.ResponseCtx) error {
				capturedStatus = rc.Status
				return nil
			}),
		},
		Matcher: hooks.Matcher{},
	}

	b := &Backend{}
	reqCtx := hooks.RequestCtx{Host: "example.com", Path: "/test"}
	respCtx := hooks.ResponseCtx{ReqCtx: reqCtx, Status: 201}

	err := b.executeHook(ctx, rh, reqCtx, respCtx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if capturedStatus != 201 {
		t.Errorf("expected status 201, got %d", capturedStatus)
	}
}

// TestExecuteHook_NoTimeout verifies hooks work without timeout.
func TestExecuteHook_NoTimeout(t *testing.T) {
	ctx := context.Background()
	called := false

	rh := hooks.ResolvedHook{
		Registration: hooks.Registration{
			Name: "noTimeoutHook",
			Kind: hooks.OnRequestReceived,
			Handler: hooks.RequestHook(func(_ context.Context, _ hooks.RequestCtx) error {
				called = true
				return nil
			}),
		},
		Matcher: hooks.Matcher{},
		Timeout: 0, // No timeout
	}

	b := &Backend{}
	reqCtx := hooks.RequestCtx{Host: "example.com", Path: "/test"}

	err := b.executeHook(ctx, rh, reqCtx, hooks.ResponseCtx{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !called {
		t.Error("expected hook to be called")
	}
}

// TestRunCompletionHooks_ErrorLogged verifies that completion hook errors are handled gracefully.
func TestRunCompletionHooks_ErrorLogged(t *testing.T) {
	ctx := context.Background()
	var calledAfterError bool

	plan := config.BackendHookPlan{
		Completion: []hooks.ResolvedHook{
			{
				Registration: hooks.Registration{
					Name:    "failingHook",
					Kind:    hooks.OnRequestCompleted,
					Handler: hooks.CompletionHook(func(_ context.Context, _ hooks.ResponseCtx) error { return errors.New("hook error") }),
				},
				Matcher: hooks.Matcher{},
			},
			{
				Registration: hooks.Registration{
					Name:    "afterErrorHook",
					Kind:    hooks.OnRequestCompleted,
					Handler: hooks.CompletionHook(func(_ context.Context, _ hooks.ResponseCtx) error { calledAfterError = true; return nil }),
				},
				Matcher: hooks.Matcher{},
			},
		},
	}

	b := &Backend{hookPlan: plan}
	respCtx := hooks.ResponseCtx{
		ReqCtx: hooks.RequestCtx{Host: "example.com", Path: "/test"},
		Status: 200,
	}

	// Completion hooks should continue even if one fails
	b.runCompletionHooks(ctx, respCtx)
	if !calledAfterError {
		t.Error("expected hook after error to be called")
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
