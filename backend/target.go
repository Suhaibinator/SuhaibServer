package backend

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/Suhaibinator/SuhaibServer/config"
	"golang.org/x/net/http2"
)

// Backend describes how to handle a particular SNI domain.
type Backend struct {
	// If true, terminate TLS locally. If false, pass through raw TCP.
	TerminateTLS bool

	// UseMTLS is called (per request) to decide if the client MUST present a certificate.
	UseMTLS func(incomingURL *url.URL) bool

	// The certificate/key to present if terminating TLS:
	TLSCertFile string
	TLSKeyFile  string

	// RootCAFile is the CA used to verify client certs if mTLS is enabled.
	// If empty, we won't forcibly verify client certs at handshake time
	// (we do a partial check in the HTTP handler).
	RootCAFile string

	// The origin server and port for reverse-proxy.
	OriginServer string
	OriginPort   string

	// Pre-built objects for efficiency:
	InboundTLSConfig *tls.Config
	ReverseProxy     *httputil.ReverseProxy
}

// NewBackendFromConfig constructs a Backend based on a single
// config.BackendConfig and pre-builds any needed TLS configs
// and reverse-proxy objects.
func NewBackendFromConfig(bcfg config.BackendConfig) (*Backend, error) {
	// If no mTLS, define a no-op function.
	var useMTLS func(*url.URL) bool
	if !bcfg.MTLSEnabled || bcfg.MTLSEnforce == nil {
		useMTLS = func(u *url.URL) bool { return false }
	} else {
		// Convert paths and queries to sets for faster membership checks.
		pathSet := sliceToSet(bcfg.MTLSEnforce.Paths)
		querySet := sliceToSet(bcfg.MTLSEnforce.Queries)

		useMTLS = func(u *url.URL) bool {
			// Check path prefixes:
			for prefix := range pathSet {
				if strings.HasPrefix(u.Path, prefix) {
					return true
				}
			}

			// Check query params via set membership:
			q := u.Query()
			for param := range querySet {
				if q.Has(param) {
					return true
				}
			}
			return false
		}
	}

	// Create the Backend with fundamental fields.
	b := &Backend{
		TerminateTLS: bcfg.TerminateTLS,
		UseMTLS:      useMTLS,

		TLSCertFile:  bcfg.TLSCertFile,
		TLSKeyFile:   bcfg.TLSKeyFile,
		RootCAFile:   bcfg.RootCAFile,
		OriginServer: bcfg.OriginServer,
		OriginPort:   bcfg.OriginPort,
	}

	// 3) If we plan to terminate TLS, build the inbound TLS config (which enforces client cert validation if MTLSEnabled).
	if b.TerminateTLS {
		tlsCfg, err := b.buildInboundTLSConfig(bcfg.MTLSEnabled)
		if err != nil {
			return nil, fmt.Errorf("buildInboundTLSConfig error: %w", err)
		}
		b.InboundTLSConfig = tlsCfg
	}

	// Build the reverse proxy (if you plan to do HTTP forwarding).
	rp, err := b.buildReverseProxy()
	if err != nil {
		return nil, fmt.Errorf("buildReverseProxy error: %w", err)
	}
	b.ReverseProxy = rp

	return b, nil
}

// sliceToSet is a helper converting a string slice to a set.
func sliceToSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, v := range items {
		set[v] = struct{}{}
	}
	return set
}

// Handle processes an incoming connection using this backend’s config.
//
// If TerminateTLS==true, we locally terminate TLS and reverse-proxy HTTP.
// If TerminateTLS==false, we do a raw TCP tunnel to the origin server/port.
func (b *Backend) Handle(conn net.Conn, sni string) error {
	if b.TerminateTLS {
		// Terminate TLS locally, then proxy via HTTP to the origin
		return b.terminateTLSAndProxyHTTP(conn)
	} else {
		// Pass-through / tunnel raw TCP
		dest := net.JoinHostPort(b.OriginServer, b.OriginPort)
		return tunnelTCP(conn, dest)
	}
}

// ----------------------------------------------------------------------------
// TUNNEL MODE (no TLS termination)
// ----------------------------------------------------------------------------
func tunnelTCP(client net.Conn, backendAddr string) error {
	defer client.Close()
	server, err := net.Dial("tcp", backendAddr)
	if err != nil {
		return err
	}
	defer server.Close()

	// copy in both directions
	go func() { _, _ = io.Copy(server, client) }()
	_, _ = io.Copy(client, server)
	return nil
}

// ----------------------------------------------------------------------------
// TLS-TERMINATION MODE
// ----------------------------------------------------------------------------

// terminateTLSAndProxyHTTP:
//  1. Wrap conn in tls.Server(...) with the pre-built inbound TLS config.
//  2. Optionally request/enforce client cert (for mTLS) - partial or at handshake
//  3. Use an http.Server to handle requests (single-conn) and reverse-proxy to the origin.
func (b *Backend) terminateTLSAndProxyHTTP(conn net.Conn) error {
	if b.InboundTLSConfig == nil {
		return fmt.Errorf("inboundTLSConfig is nil; cannot terminate TLS")
	}

	tlsConn := tls.Server(conn, b.InboundTLSConfig)

	// We'll serve exactly one connection with an http.Server
	oneShotLn := &singleConnListener{
		conn: tlsConn,
		done: make(chan struct{}),
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1) If we need mTLS for this path/query, check if a cert was presented
			// (At this point, any *invalid* cert would have failed the TLS handshake.)
			if b.UseMTLS != nil && b.UseMTLS(r.URL) {
				if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
					http.Error(w, "client certificate required", http.StatusUnauthorized)
					return
				}
				// If the certificate was provided but invalid, the handshake
				// wouldn't have succeeded. So at this point, we know it's valid.
			}

			// 2) Possibly pass the real client IP to the origin
			remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
			r.Header.Set("X-Original-Remote-IP", remoteIP)

			// 3) Let the pre-built ReverseProxy handle it
			b.ReverseProxy.ServeHTTP(w, r)
		}),
	}

	// If you want HTTP/2 inbound, set up the h2 server:
	h2s := &http2.Server{}
	server.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
		"h2": func(s *http.Server, tc *tls.Conn, h http.Handler) {
			h2s.ServeConn(tc, &http2.ServeConnOpts{
				Handler: s.Handler,
			})
		},
	}

	// Serve on this single connection
	err := server.Serve(oneShotLn)
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http server error: %w", err)
	}
	return nil
}

// buildInboundTLSConfig loads cert/key and optionally RootCA for verifying client certs.
func (b *Backend) buildInboundTLSConfig(mtlsEnabled bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(b.TLSCertFile, b.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// If you're using HTTP/2, the Go standard library might auto-enable it
		// if the TLS config is compatible. You can further configure if needed.
	}

	// If mTLS is enabled and we have a RootCAFile, load it and configure ClientAuth.
	if mtlsEnabled && b.RootCAFile != "" {
		pool, err := loadCertPool(b.RootCAFile)
		if err != nil {
			return nil, fmt.Errorf("could not load root CA file: %w", err)
		}

		// "VerifyClientCertIfGiven" means:
		// - If a client cert is presented, we validate it.
		// - If none is presented, the handshake still succeeds
		//   (making partial mTLS possible).
		//   If you want to *always* require a cert, use tls.RequireAndVerifyClientCert instead.
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	}

	return tlsCfg, nil
}

// buildReverseProxy constructs an httputil.ReverseProxy for the origin server.
func (b *Backend) buildReverseProxy() (*httputil.ReverseProxy, error) {
	rawURL := fmt.Sprintf("http://%s:%s", b.OriginServer, b.OriginPort)
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse origin URL %q: %w", rawURL, err)
	}
	return httputil.NewSingleHostReverseProxy(parsed), nil
}

// Helper to load a CA cert file into an *x509.CertPool.
func loadCertPool(caFile string) (*x509.CertPool, error) {
	caBytes, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("failed to append certs from %s", caFile)
	}
	return pool, nil
}

// singleConnListener is a net.Listener that returns exactly one connection.
// This is a trick to let http.Server.Serve() handle a single net.Conn.
type singleConnListener struct {
	conn net.Conn
	mu   sync.Mutex
	done chan struct{}
	used bool
}

func (s *singleConnListener) Accept() (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used {
		return nil, fmt.Errorf("no more connections")
	}
	s.used = true
	return s.conn, nil
}

func (s *singleConnListener) Close() error {
	close(s.done)
	if s.conn != nil {
		s.conn.Close()
	}
	return nil
}

func (s *singleConnListener) Addr() net.Addr {
	return s.conn.LocalAddr()
}
