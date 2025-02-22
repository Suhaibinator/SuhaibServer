package backend

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"

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

// NewBackend constructs a Backend and pre-builds any needed
// TLS configs and reverse-proxy objects so it doesn't have
// to do so on every incoming connection.
func NewBackend(
	terminateTLS bool,
	useMTLS func(*url.URL) bool,
	certFile, keyFile, rootCAFile string,
	originServer, originPort string,
) (*Backend, error) {

	b := &Backend{
		TerminateTLS: terminateTLS,
		UseMTLS:      useMTLS,
		TLSCertFile:  certFile,
		TLSKeyFile:   keyFile,
		RootCAFile:   rootCAFile,
		OriginServer: originServer,
		OriginPort:   originPort,
	}

	// 1) If we plan to terminate TLS, build the inbound TLS config now.
	if b.TerminateTLS {
		tlsCfg, err := b.buildInboundTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("buildInboundTLSConfig error: %w", err)
		}
		b.InboundTLSConfig = tlsCfg
	}

	// 2) Build the reverse proxy (if you plan to do HTTP forwarding).
	rp, err := b.buildReverseProxy()
	if err != nil {
		return nil, fmt.Errorf("buildReverseProxy error: %w", err)
	}
	b.ReverseProxy = rp

	return b, nil
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

	// Our custom http.Server which will forward requests to b.ReverseProxy
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1) If we need mTLS, check if we got a client cert
			if b.UseMTLS != nil && b.UseMTLS(r.URL) {
				if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
					http.Error(w, "client certificate required", http.StatusUnauthorized)
					return
				}
				// If using tls.RequireAndVerifyClientCert at handshake time,
				// it would have failed earlier if the cert was invalid.
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

// buildInboundTLSConfig sets up inbound TLS for the server side,
// optionally requesting client certs if b.RootCAFile is set.
func (b *Backend) buildInboundTLSConfig() (*tls.Config, error) {
	crt, err := tls.LoadX509KeyPair(b.TLSCertFile, b.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("LoadX509KeyPair error: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{crt},
		ClientAuth:   tls.NoClientCert, // might override below
	}

	if b.RootCAFile != "" {
		caBytes, err := os.ReadFile(b.RootCAFile)
		if err != nil {
			return nil, fmt.Errorf("read rootCA file error: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("failed to parse rootCA PEM")
		}
		// We'll do a "request" client cert mode so clients can connect even if they don't present a cert,
		// but in the HTTP handler we can reject them if we want. If you prefer fail at handshake, do:
		//   tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		tlsCfg.ClientAuth = tls.RequestClientCert
		tlsCfg.ClientCAs = caPool
	}

	return tlsCfg, nil
}

// buildReverseProxy creates a ReverseProxy for requests to b.OriginServer:b.OriginPort
func (b *Backend) buildReverseProxy() (*httputil.ReverseProxy, error) {
	targetURL := &url.URL{
		Scheme: "http", // or "https" if your origin is HTTPS
		Host:   net.JoinHostPort(b.OriginServer, b.OriginPort),
	}
	rp := httputil.NewSingleHostReverseProxy(targetURL)

	// Optionally customize the Transport if you want to do special TLS checks on the origin
	rp.Transport = &http.Transport{
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
		DisableKeepAlives:   false,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		// TLSClientConfig: &tls.Config{ ... } if you want custom CA to verify origin
	}

	// You can customize the Director if needed
	rp.Director = func(req *http.Request) {
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		// If you want to preserve the client's original Host header, you might do:
		// req.Host = req.Header.Get("X-Forwarded-Host") // or something custom
	}
	return rp, nil
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
