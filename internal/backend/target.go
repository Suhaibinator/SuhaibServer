package backend

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/Suhaibinator/SuhaibServer/internal/config"
	"golang.org/x/net/http2"
)

type Backend struct {
	TerminateTLS bool
	UseMTLS      func(*url.URL) bool

	TLSCertFile string
	TLSKeyFile  string
	RootCAFile  string

	OriginServer string
	OriginPort   string

	InboundTLSConfig *tls.Config
	ReverseProxy     *httputil.ReverseProxy
}

func NewBackendFromConfig(bcfg config.BackendConfig) (*Backend, error) {
	log.Printf("[DEBUG] Entering NewBackendFromConfig(bcfg=%+v)", bcfg)

	// Build the UseMTLS function according to MTLSEnabled and MTLSPolicy.
	log.Printf("[DEBUG] Calling buildMTLSLogic...")
	useMTLS := buildMTLSLogic(bcfg)

	// Create the base Backend struct.
	b := &Backend{
		TerminateTLS: bcfg.TerminateTLS,
		UseMTLS:      useMTLS,
		TLSCertFile:  bcfg.TLSCertFile,
		TLSKeyFile:   bcfg.TLSKeyFile,
		RootCAFile:   bcfg.RootCAFile,
		OriginServer: bcfg.OriginServer,
		OriginPort:   bcfg.OriginPort,
	}

	log.Printf("[DEBUG] Created Backend struct: TerminateTLS=%v, TLSCertFile=%q, TLSKeyFile=%q, RootCAFile=%q, OriginServer=%q, OriginPort=%q",
		b.TerminateTLS, b.TLSCertFile, b.TLSKeyFile, b.RootCAFile, b.OriginServer, b.OriginPort)

	// If we’re terminating TLS, build the inbound TLS config.
	if b.TerminateTLS {
		log.Printf("[DEBUG] TerminateTLS is true; building inbound TLS config (mTLS enabled=%v)...", bcfg.MTLSEnabled)
		tlsCfg, err := b.buildInboundTLSConfig(bcfg.MTLSEnabled)
		if err != nil {
			log.Printf("[ERROR] buildInboundTLSConfig failed: %v", err)
			return nil, fmt.Errorf("buildInboundTLSConfig error: %w", err)
		}
		b.InboundTLSConfig = tlsCfg
		log.Printf("[DEBUG] Inbound TLS config successfully built.")
	} else {
		log.Printf("[DEBUG] TerminateTLS is false; no TLS config will be built.")
	}

	// Build the reverse proxy to the origin server.
	log.Printf("[DEBUG] Building reverse proxy to origin %s:%s...", b.OriginServer, b.OriginPort)
	rp, err := b.buildReverseProxy()
	if err != nil {
		log.Printf("[ERROR] buildReverseProxy failed: %v", err)
		return nil, fmt.Errorf("buildReverseProxy error: %w", err)
	}
	b.ReverseProxy = rp
	log.Printf("[DEBUG] Reverse proxy successfully built.")

	log.Printf("[DEBUG] Exiting NewBackendFromConfig, returning Backend: %+v", b)
	return b, nil
}

// buildMTLSLogic returns a function that decides whether a given path/query requires mTLS.
// This encapsulates the “default plus exceptions” logic.
func buildMTLSLogic(bcfg config.BackendConfig) func(u *url.URL) bool {
	log.Printf("[DEBUG] Entering buildMTLSLogic(bcfg=%+v)", bcfg)

	// If mTLS isn’t enabled globally, always return false.
	if !bcfg.MTLSEnabled {
		log.Printf("[DEBUG] mTLS not enabled globally, returning function that always returns false.")
		return func(u *url.URL) bool {
			log.Printf("[TRACE] buildMTLSLogic: returning false for URL=%v", u)
			return false
		}
	}

	// If we *are* enabled but have no policy, decide how you want to handle it:
	if bcfg.MTLSPolicy == nil {
		log.Printf("[DEBUG] mTLS is enabled but policy is nil; returning function that always returns true.")
		return func(u *url.URL) bool {
			log.Printf("[TRACE] buildMTLSLogic: returning true for URL=%v", u)
			return true
		}
	}

	// Extract the default and the exceptions from MTLSPolicy.
	defaultMTLS := bcfg.MTLSPolicy.Default
	pathSet := sliceToSet(bcfg.MTLSPolicy.Paths)
	querySet := sliceToSet(bcfg.MTLSPolicy.Queries)

	log.Printf("[DEBUG] mTLS enabled with policy; default=%v, pathSet=%v, querySet=%v",
		defaultMTLS, pathSet, querySet)

	return func(u *url.URL) bool {
		log.Printf("[TRACE] Checking mTLS requirement for URL: %v", u)

		matchesException := false

		// Check path prefixes first
		for prefix := range pathSet {
			if strings.HasPrefix(u.Path, prefix) {
				log.Printf("[TRACE] URL path %q has prefix %q => exception match", u.Path, prefix)
				matchesException = true
				break
			}
		}
		// If no path matched, check the query params
		if !matchesException {
			q := u.Query()
			for param := range querySet {
				if q.Has(param) {
					log.Printf("[TRACE] URL query %v has param %q => exception match", q, param)
					matchesException = true
					break
				}
			}
		}

		result := defaultMTLS
		if matchesException {
			result = !defaultMTLS
		}

		log.Printf("[TRACE] buildMTLSLogic: URL=%v => requireMTLS=%v (defaultMTLS=%v, matchesException=%v)",
			u, result, defaultMTLS, matchesException)

		return result
	}
}

func sliceToSet(items []string) map[string]struct{} {
	log.Printf("[DEBUG] Entering sliceToSet(items=%v)", items)
	set := make(map[string]struct{}, len(items))
	for _, v := range items {
		set[v] = struct{}{}
	}
	log.Printf("[DEBUG] Exiting sliceToSet, returning set: %v", set)
	return set
}

// Handle processes an incoming connection using this backend’s config.
//
// If TerminateTLS==true, we locally terminate TLS and reverse-proxy HTTP.
// If TerminateTLS==false, we do a raw TCP tunnel to the origin server/port.
func (b *Backend) Handle(conn net.Conn, sni string) error {
	log.Printf("[DEBUG] Entering (*Backend).Handle(conn=%v, sni=%q). TerminateTLS=%v", conn.RemoteAddr(), sni, b.TerminateTLS)

	if b.TerminateTLS {
		log.Printf("[DEBUG] TerminateTLS is true; will terminate TLS locally and proxy via HTTP.")
		err := b.terminateTLSAndProxyHTTP(conn)
		log.Printf("[DEBUG] Exiting (*Backend).Handle with error: %v", err)
		return err
	} else {
		log.Printf("[DEBUG] TerminateTLS is false; tunnel TCP directly to origin.")
		dest := net.JoinHostPort(b.OriginServer, b.OriginPort)
		err := tunnelTCP(conn, dest)
		log.Printf("[DEBUG] Exiting (*Backend).Handle with error: %v", err)
		return err
	}
}

// ----------------------------------------------------------------------------
// TUNNEL MODE (no TLS termination)
// ----------------------------------------------------------------------------
func tunnelTCP(client net.Conn, backendAddr string) error {
	log.Printf("[DEBUG] Entering tunnelTCP(client=%v, backendAddr=%q)", client.RemoteAddr(), backendAddr)
	defer func() {
		log.Printf("[DEBUG] Closing client connection from %v in tunnelTCP", client.RemoteAddr())
		client.Close()
	}()
	server, err := net.Dial("tcp", backendAddr)
	if err != nil {
		log.Printf("[ERROR] tunnelTCP: failed to dial backend at %q: %v", backendAddr, err)
		return err
	}
	defer func() {
		log.Printf("[DEBUG] Closing server connection to %v in tunnelTCP", server.RemoteAddr())
		server.Close()
	}()

	log.Printf("[DEBUG] tunnelTCP: copying data between client and server.")
	go func() {
		_, copyErr := io.Copy(server, client)
		if copyErr != nil {
			log.Printf("[ERROR] tunnelTCP: error copying from client to server: %v", copyErr)
		}
	}()
	_, copyErr := io.Copy(client, server)
	if copyErr != nil {
		log.Printf("[ERROR] tunnelTCP: error copying from server to client: %v", copyErr)
	}

	log.Printf("[DEBUG] Exiting tunnelTCP")
	return nil
}

// ----------------------------------------------------------------------------
// TLS-TERMINATION MODE
// ----------------------------------------------------------------------------

// terminateTLSAndProxyHTTP terminates TLS and uses a standard HTTP server to handle
// multiple requests (HTTP/1.1 keep-alive or HTTP/2) over the same single connection.
func (b *Backend) terminateTLSAndProxyHTTP(conn net.Conn) error {
	log.Printf("[DEBUG] Entering terminateTLSAndProxyHTTP(conn=%v)", conn.RemoteAddr())

	if b.InboundTLSConfig == nil {
		return fmt.Errorf("inboundTLSConfig is nil; cannot terminate TLS")
	}

	// Wrap the raw conn in a TLS server
	tlsConn := tls.Server(conn, b.InboundTLSConfig)

	// Perform the TLS handshake now (so if there's an error, we see it early)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[ERROR] TLS handshake failed from %v: %v", conn.RemoteAddr(), err)
		tlsConn.Close()
		return err
	}

	// We’ll serve exactly this one TLS connection with an http.Server
	oneShotLn := newSingleConnListener(tlsConn)

	// Build an http.Server
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If mTLS required for this URL, check client certificate
			if b.UseMTLS != nil && b.UseMTLS(r.URL) {
				if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
					log.Printf("[WARN] No client cert provided; returning 401.")
					http.Error(w, "client certificate required", http.StatusUnauthorized)
					return
				}
			}
			// Pass real client IP to origin
			remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
			r.Header.Set("X-Original-Remote-IP", remoteIP)

			// Let ReverseProxy handle the request
			b.ReverseProxy.ServeHTTP(w, r)
		}),
	}

	// If you want to support HTTP/2, set up the h2 server:
	h2s := &http2.Server{}
	server.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
		"h2": func(s *http.Server, tc *tls.Conn, h http.Handler) {
			h2s.ServeConn(tc, &http2.ServeConnOpts{Handler: s.Handler})
		},
	}

	// Serve will not exit until we return from Accept() with a permanent error or
	// the connection is closed by the client or forcibly by us.
	err := server.Serve(oneShotLn)
	if err != nil && err != http.ErrServerClosed {
		log.Printf("[ERROR] http server error: %v", err)
		return fmt.Errorf("http server error: %w", err)
	}

	log.Printf("[DEBUG] Exiting terminateTLSAndProxyHTTP (conn=%v) with no fatal error", conn.RemoteAddr())
	return nil
}

// buildInboundTLSConfig loads cert/key and optionally RootCA for verifying client certs.
func (b *Backend) buildInboundTLSConfig(mtlsEnabled bool) (*tls.Config, error) {
	log.Printf("[DEBUG] Entering (*Backend).buildInboundTLSConfig(mtlsEnabled=%v). Files: cert=%q, key=%q, rootCA=%q",
		mtlsEnabled, b.TLSCertFile, b.TLSKeyFile, b.RootCAFile)

	cert, err := tls.LoadX509KeyPair(b.TLSCertFile, b.TLSKeyFile)
	if err != nil {
		log.Printf("[ERROR] failed to load key pair (cert=%q, key=%q): %v", b.TLSCertFile, b.TLSKeyFile, err)
		return nil, fmt.Errorf("failed to load key pair: %w", err)
	}
	log.Printf("[DEBUG] Loaded X509 key pair successfully.")

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	log.Printf("[DEBUG] Created base tls.Config with loaded certificate.")

	// If mTLS is enabled and we have a RootCAFile, load it and configure ClientAuth.
	if mtlsEnabled && b.RootCAFile != "" {
		log.Printf("[DEBUG] mTLS enabled and RootCAFile provided; loading CA from %q", b.RootCAFile)
		pool, err := loadCertPool(b.RootCAFile)
		if err != nil {
			log.Printf("[ERROR] Could not load root CA file %q: %v", b.RootCAFile, err)
			return nil, fmt.Errorf("could not load root CA file: %w", err)
		}

		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		log.Printf("[DEBUG] Set tlsCfg.ClientCAs and tlsCfg.ClientAuth=VerifyClientCertIfGiven for partial mTLS.")
	} else {
		log.Printf("[DEBUG] mTLS disabled or no RootCAFile specified; not setting ClientCAs.")
	}

	log.Printf("[DEBUG] Exiting (*Backend).buildInboundTLSConfig with success.")
	return tlsCfg, nil
}

// buildReverseProxy constructs an httputil.ReverseProxy for the origin server.
func (b *Backend) buildReverseProxy() (*httputil.ReverseProxy, error) {
	log.Printf("[DEBUG] Entering (*Backend).buildReverseProxy(). OriginServer=%q, OriginPort=%q", b.OriginServer, b.OriginPort)

	rawURL := fmt.Sprintf("http://%s:%s", b.OriginServer, b.OriginPort)
	log.Printf("[DEBUG] Constructed raw origin URL=%q", rawURL)

	parsed, err := url.Parse(rawURL)
	if err != nil {
		log.Printf("[ERROR] Failed to parse origin URL %q: %v", rawURL, err)
		return nil, fmt.Errorf("failed to parse origin URL %q: %w", rawURL, err)
	}

	log.Printf("[DEBUG] Creating httputil.NewSingleHostReverseProxy for parsed URL=%q", parsed.String())
	proxy := httputil.NewSingleHostReverseProxy(parsed)
	log.Printf("[DEBUG] Exiting (*Backend).buildReverseProxy with success.")
	return proxy, nil
}

// Helper to load a CA cert file into an *x509.CertPool.
func loadCertPool(caFile string) (*x509.CertPool, error) {
	log.Printf("[DEBUG] Entering loadCertPool(caFile=%q)", caFile)

	caBytes, err := os.ReadFile(caFile)
	if err != nil {
		log.Printf("[ERROR] Could not read CA file %q: %v", caFile, err)
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		err := fmt.Errorf("failed to append certs from %s", caFile)
		log.Printf("[ERROR] %v", err)
		return nil, err
	}

	log.Printf("[DEBUG] Exiting loadCertPool with success (CA file=%q).", caFile)
	return pool, nil
}

// ----------------------------------------------------------------------------
// SINGLE-CONN LISTENER (FIXED)
// ----------------------------------------------------------------------------

// singleConnListener is a net.Listener that returns exactly one net.Conn (the TLS-wrapped
// conn), but does NOT immediately error out on subsequent Accept() calls. Instead, it
// blocks until the connection is closed, so that http.Server does not fail prematurely.
type singleConnListener struct {
	conn net.Conn

	mu     sync.Mutex
	used   bool
	closed bool

	// doneChan is closed once we close the underlying connection,
	// which unblocks any subsequent Accept().
	doneChan chan struct{}
}

// newSingleConnListener creates a singleConnListener for one net.Conn.
func newSingleConnListener(c net.Conn) *singleConnListener {
	return &singleConnListener{
		conn:     c,
		doneChan: make(chan struct{}),
	}
}

func (s *singleConnListener) Accept() (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, net.ErrClosed
	}
	if !s.used {
		// First Accept call returns the net.Conn
		s.used = true
		return s.conn, nil
	}

	// Any subsequent Accept call blocks until conn is closed, then returns net.ErrClosed
	s.mu.Unlock()
	<-s.doneChan
	s.mu.Lock()
	return nil, net.ErrClosed
}

func (s *singleConnListener) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.conn != nil {
		s.conn.Close()
	}
	close(s.doneChan)
	return nil
}

func (s *singleConnListener) Addr() net.Addr {
	return s.conn.LocalAddr()
}
