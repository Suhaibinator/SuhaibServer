package backend

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Suhaibinator/SuhaibServer/internal/config"
	"github.com/Suhaibinator/SuhaibServer/sdk/hooks"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
)

type Backend struct {
	TerminateTLS bool
	UseMTLS      func(*url.URL) bool

	TLSCertFile string
	TLSKeyFile  string
	RootCAFile  string

	// Scheme to use when connecting to the origin (http or https).
	OriginScheme string

	OriginServer string
	OriginPort   string

	InboundTLSConfig *tls.Config
	ReverseProxy     *httputil.ReverseProxy

	hookPlan config.BackendHookPlan
}

func NewBackendFromConfig(bcfg config.BackendConfig, plan config.BackendHookPlan) (*Backend, error) {
	zap.L().Debug("Entering NewBackendFromConfig", zap.Any("backendConfig", bcfg))

	// Build the UseMTLS function according to MTLSEnabled and MTLSPolicy.
	zap.L().Debug("Calling buildMTLSLogic...")
	useMTLS := buildMTLSLogic(bcfg)

	// Create the base Backend struct.
	scheme := bcfg.OriginScheme
	if scheme == "" {
		scheme = "http"
	}
	b := &Backend{
		TerminateTLS: bcfg.TerminateTLS,
		UseMTLS:      useMTLS,
		TLSCertFile:  bcfg.TLSCertFile,
		TLSKeyFile:   bcfg.TLSKeyFile,
		RootCAFile:   bcfg.RootCAFile,
		OriginScheme: scheme,
		OriginServer: bcfg.OriginServer,
		OriginPort:   bcfg.OriginPort,
		hookPlan:     plan,
	}

	zap.L().Debug("Created Backend struct",
		zap.Bool("TerminateTLS", b.TerminateTLS),
		zap.String("TLSCertFile", b.TLSCertFile),
		zap.String("TLSKeyFile", b.TLSKeyFile),
		zap.String("RootCAFile", b.RootCAFile),
		zap.String("OriginScheme", b.OriginScheme),
		zap.String("OriginServer", b.OriginServer),
		zap.String("OriginPort", b.OriginPort),
	)

	// If we’re terminating TLS, build the inbound TLS config.
	if b.TerminateTLS {
		zap.L().Debug("TerminateTLS is true; building inbound TLS config",
			zap.Bool("mTLS", bcfg.MTLSEnabled),
		)
		tlsCfg, err := b.buildInboundTLSConfig(bcfg.MTLSEnabled)
		if err != nil {
			zap.L().Error("buildInboundTLSConfig failed", zap.Error(err))
			return nil, fmt.Errorf("buildInboundTLSConfig error: %w", err)
		}
		b.InboundTLSConfig = tlsCfg
		zap.L().Debug("Inbound TLS config successfully built.")
	} else {
		zap.L().Debug("TerminateTLS is false; no TLS config will be built.")
	}

	// Build the reverse proxy to the origin server.
	zap.L().Debug("Building reverse proxy to origin",
		zap.String("OriginScheme", b.OriginScheme),
		zap.String("OriginServer", b.OriginServer),
		zap.String("OriginPort", b.OriginPort),
	)
	rp, err := b.buildReverseProxy()
	if err != nil {
		zap.L().Error("buildReverseProxy failed", zap.Error(err))
		return nil, fmt.Errorf("buildReverseProxy error: %w", err)
	}
	b.ReverseProxy = rp
	zap.L().Debug("Reverse proxy successfully built.")

	zap.L().Debug("Exiting NewBackendFromConfig, returning Backend", zap.Any("backend", b))
	return b, nil
}

// buildMTLSLogic returns a function that decides whether a given path/query requires mTLS.
// This encapsulates the "default plus exceptions" logic.
func buildMTLSLogic(bcfg config.BackendConfig) func(u *url.URL) bool {
	zap.L().Debug("Entering buildMTLSLogic", zap.Any("backendConfig", bcfg))

	// If mTLS isn’t enabled globally, always return false.
	if !bcfg.MTLSEnabled {
		zap.L().Debug("mTLS not enabled globally; returning false always.")
		return func(u *url.URL) bool {
			zap.L().Debug("mTLSLogic => false", zap.String("url", u.String()))
			return false
		}
	}

	// If we *are* enabled but have no policy, always return true.
	if bcfg.MTLSPolicy == nil {
		zap.L().Debug("mTLS is enabled but policy is nil; returning true always.")
		return func(u *url.URL) bool {
			zap.L().Debug("mTLSLogic => true", zap.String("url", u.String()))
			return true
		}
	}

	// Extract the default and the exceptions from MTLSPolicy.
	defaultMTLS := bcfg.MTLSPolicy.Default
	pathSet := sliceToSet(bcfg.MTLSPolicy.Paths)
	querySet := sliceToSet(bcfg.MTLSPolicy.Queries)

	zap.L().Debug("mTLS enabled with policy",
		zap.Bool("defaultMTLS", defaultMTLS),
		zap.Any("pathSet", pathSet),
		zap.Any("querySet", querySet),
	)

	return func(u *url.URL) bool {
		zap.L().Debug("Checking mTLS requirement for URL", zap.String("url", u.String()))

		matchesException := false

		// Check path prefixes
		for prefix := range pathSet {
			if strings.HasPrefix(u.Path, prefix) {
				zap.L().Debug("URL path has prefix => exception match",
					zap.String("path", u.Path),
					zap.String("prefix", prefix),
				)
				matchesException = true
				break
			}
		}

		// If no path matched, check query params
		if !matchesException {
			q := u.Query()
			for param := range querySet {
				if q.Has(param) {
					zap.L().Debug("URL query has param => exception match",
						zap.Any("query", q),
						zap.String("param", param),
					)
					matchesException = true
					break
				}
			}
		}

		result := defaultMTLS
		if matchesException {
			result = !defaultMTLS
		}

		zap.L().Debug("mTLS decision",
			zap.String("url", u.String()),
			zap.Bool("requireMTLS", result),
			zap.Bool("defaultMTLS", defaultMTLS),
			zap.Bool("matchesException", matchesException),
		)

		return result
	}
}

func sliceToSet(items []string) map[string]struct{} {
	zap.L().Debug("Entering sliceToSet", zap.Strings("items", items))
	set := make(map[string]struct{}, len(items))
	for _, v := range items {
		set[v] = struct{}{}
	}
	zap.L().Debug("Exiting sliceToSet", zap.Any("set", set))
	return set
}

// Handle processes an incoming connection using this backend’s config.
// If TerminateTLS==true, we locally terminate TLS and reverse-proxy HTTP.
// If TerminateTLS==false, we do a raw TCP tunnel to the origin server/port.
func (b *Backend) Handle(conn net.Conn, sni string) error {
	zap.L().Debug("Entering Backend.Handle",
		zap.String("remoteAddr", conn.RemoteAddr().String()),
		zap.String("sni", sni),
		zap.Bool("terminateTLS", b.TerminateTLS),
	)

	if b.TerminateTLS {
		zap.L().Debug("TerminateTLS => will terminate TLS locally and proxy via HTTP")
		err := b.terminateTLSAndProxyHTTP(conn)
		zap.L().Debug("Exiting Backend.Handle", zap.Error(err))
		return err
	} else {
		zap.L().Debug("TerminateTLS=false => tunnel raw TCP directly to origin")
		dest := net.JoinHostPort(b.OriginServer, b.OriginPort)
		err := tunnelTCP(conn, dest)
		zap.L().Debug("Exiting Backend.Handle", zap.Error(err))
		return err
	}
}

// ----------------------------------------------------------------------------
// TUNNEL MODE (no TLS termination)
// ----------------------------------------------------------------------------

func tunnelTCP(client net.Conn, backendAddr string) error {
	zap.L().Debug("Entering tunnelTCP",
		zap.String("clientAddr", client.RemoteAddr().String()),
		zap.String("backendAddr", backendAddr),
	)
	defer func() {
		zap.L().Debug("Closing client connection in tunnelTCP", zap.String("clientAddr", client.RemoteAddr().String()))
		client.Close()
	}()

	server, err := net.Dial("tcp", backendAddr)
	if err != nil {
		zap.L().Error("tunnelTCP: failed to dial backend", zap.String("backendAddr", backendAddr), zap.Error(err))
		return err
	}
	defer func() {
		zap.L().Debug("Closing server connection in tunnelTCP", zap.String("serverAddr", server.RemoteAddr().String()))
		server.Close()
	}()

	zap.L().Debug("tunnelTCP: copying data between client and server.")
	go func() {
		if _, copyErr := io.Copy(server, client); copyErr != nil {
			zap.L().Error("tunnelTCP: error copying from client to server", zap.Error(copyErr))
		}
	}()
	if _, copyErr := io.Copy(client, server); copyErr != nil {
		zap.L().Error("tunnelTCP: error copying from server to client", zap.Error(copyErr))
	}

	zap.L().Debug("Exiting tunnelTCP")
	return nil
}

// ----------------------------------------------------------------------------
// TLS-TERMINATION MODE
// ----------------------------------------------------------------------------

// terminateTLSAndProxyHTTP terminates TLS and uses a standard HTTP server to handle
// multiple requests (HTTP/1.1 keep-alive or HTTP/2) over the same single connection.
func (b *Backend) terminateTLSAndProxyHTTP(conn net.Conn) error {
	zap.L().Debug("Entering terminateTLSAndProxyHTTP",
		zap.String("remoteAddr", conn.RemoteAddr().String()),
	)

	if b.InboundTLSConfig == nil {
		return fmt.Errorf("inboundTLSConfig is nil; cannot terminate TLS")
	}

	// Wrap the raw conn in a TLS server
	tlsConn := tls.Server(conn, b.InboundTLSConfig)

	// Perform the TLS handshake now (so if there's an error, we see it early)
	if err := tlsConn.Handshake(); err != nil {
		zap.L().Error("TLS handshake failed",
			zap.String("remoteAddr", conn.RemoteAddr().String()),
			zap.Error(err),
		)
		tlsConn.Close()
		return err
	}

	// We’ll serve exactly this one TLS connection with an http.Server
	oneShotLn := newSingleConnListener(tlsConn)

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			zap.L().Debug("mTLS check details",
				zap.Bool("hasMTLSFunc", b.UseMTLS != nil),
				zap.String("url", r.URL.String()),
			)

			if b.UseMTLS != nil {
				requiresMTLS := b.UseMTLS(r.URL)
				zap.L().Debug("mTLS requirement check",
					zap.Bool("requiresMTLS", requiresMTLS),
					zap.Bool("hasTLSInfo", r.TLS != nil),
					zap.Int("numPeerCerts", func() int {
						if r.TLS != nil {
							return len(r.TLS.PeerCertificates)
						}
						return 0
					}()),
				)

				if requiresMTLS {

					if len(tlsConn.ConnectionState().PeerCertificates) == 0 {
						zap.L().Warn("No client cert provided; returning 401",
							zap.String("remoteAddr", r.RemoteAddr),
							zap.String("url", r.URL.String()),
						)
						http.Error(w, "client certificate required", http.StatusUnauthorized)
						return
					}
				}
			}

			remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
			reqCtx := b.buildRequestContext(r, remoteIP, tlsConn.ConnectionState().PeerCertificates)

			ctx := context.WithValue(r.Context(), hookContextKey{}, hookContext{
				reqCtx: reqCtx,
				start:  time.Now(),
			})
			r = r.WithContext(ctx)

			if err := b.runRequestHooks(r.Context(), reqCtx); err != nil {
				zap.L().Warn("request hook blocked request", zap.Error(err))
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}

			r.Header.Set("X-Original-Remote-IP", remoteIP)
			r.Header.Set("X-Forwarded-Proto", "https")

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

	// Serve will not exit until we return from Accept() with a permanent error
	// or the connection is closed by the client or forcibly by us.
	err := server.Serve(oneShotLn)
	if err != nil && err != http.ErrServerClosed {
		zap.L().Error("http server error", zap.Error(err))
		return fmt.Errorf("http server error: %w", err)
	}

	zap.L().Debug("Exiting terminateTLSAndProxyHTTP with no fatal error",
		zap.String("remoteAddr", conn.RemoteAddr().String()),
	)
	return nil
}

// buildInboundTLSConfig loads cert/key and optionally RootCA for verifying client certs.
func (b *Backend) buildInboundTLSConfig(mtlsEnabled bool) (*tls.Config, error) {
	zap.L().Debug("Entering buildInboundTLSConfig",
		zap.Bool("mtlsEnabled", mtlsEnabled),
		zap.String("certFile", b.TLSCertFile),
		zap.String("keyFile", b.TLSKeyFile),
		zap.String("rootCA", b.RootCAFile),
	)

	cert, err := tls.LoadX509KeyPair(b.TLSCertFile, b.TLSKeyFile)
	if err != nil {
		zap.L().Error("Failed to load key pair",
			zap.String("certFile", b.TLSCertFile),
			zap.String("keyFile", b.TLSKeyFile),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to load key pair: %w", err)
	}
	zap.L().Debug("Loaded X509 key pair successfully.")

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	zap.L().Debug("Created base tls.Config with loaded certificate.")

	// If mTLS is enabled and we have a RootCAFile, load it and configure ClientAuth.
	if mtlsEnabled && b.RootCAFile != "" {
		zap.L().Debug("mTLS enabled and RootCAFile provided, loading CA",
			zap.String("rootCAFile", b.RootCAFile),
		)
		pool, err := loadCertPool(b.RootCAFile)
		if err != nil {
			zap.L().Error("Could not load root CA file",
				zap.String("rootCAFile", b.RootCAFile),
				zap.Error(err),
			)
			return nil, fmt.Errorf("could not load root CA file: %w", err)
		}

		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		zap.L().Debug("Set tlsCfg.ClientCAs and tlsCfg.ClientAuth=VerifyClientCertIfGiven for partial mTLS.")
	} else {
		zap.L().Debug("mTLS disabled or no RootCAFile specified; not setting ClientCAs.")
	}

	zap.L().Debug("Exiting buildInboundTLSConfig with success.")
	return tlsCfg, nil
}

// buildReverseProxy constructs an httputil.ReverseProxy for the origin server.
func (b *Backend) buildReverseProxy() (*httputil.ReverseProxy, error) {
	zap.L().Debug("Entering buildReverseProxy",
		zap.String("OriginScheme", b.OriginScheme),
		zap.String("OriginServer", b.OriginServer),
		zap.String("OriginPort", b.OriginPort),
	)

	rawURL := fmt.Sprintf("%s://%s:%s", b.OriginScheme, b.OriginServer, b.OriginPort)
	zap.L().Debug("Constructed raw origin URL", zap.String("rawURL", rawURL))

	parsed, err := url.Parse(rawURL)
	if err != nil {
		zap.L().Error("Failed to parse origin URL",
			zap.String("rawURL", rawURL),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to parse origin URL %q: %w", rawURL, err)
	}

	zap.L().Debug("Creating httputil.NewSingleHostReverseProxy", zap.String("parsedURL", parsed.String()))
	proxy := httputil.NewSingleHostReverseProxy(parsed)
	proxy.ModifyResponse = b.handleProxyResponse
	proxy.ErrorHandler = b.handleProxyError
	zap.L().Debug("Exiting buildReverseProxy with success.")
	return proxy, nil
}

type hookContextKey struct{}

type hookContext struct {
	reqCtx hooks.RequestCtx
	start  time.Time
}

func (b *Backend) buildRequestContext(r *http.Request, remoteIP string, peerCerts []*x509.Certificate) hooks.RequestCtx {
	var clientCert *hooks.ClientCert
	if len(peerCerts) > 0 {
		fp := sha256.Sum256(peerCerts[0].Raw)
		clientCert = &hooks.ClientCert{
			Leaf:        peerCerts[0],
			Chain:       peerCerts,
			Fingerprint: hex.EncodeToString(fp[:]),
		}
	}

	traceID := r.Header.Get("X-Request-Id")
	if traceID == "" {
		traceID = fmt.Sprintf("%d", time.Now().UnixNano())
	}

	return hooks.RequestCtx{
		Req:        r,
		Host:       r.Host,
		Path:       r.URL.Path,
		TraceID:    traceID,
		ClientIP:   remoteIP,
		Meta:       map[string]string{},
		ClientCert: clientCert,
	}
}

func (b *Backend) runRequestHooks(ctx context.Context, reqCtx hooks.RequestCtx) error {
	for _, rh := range b.hookPlan.Request {
		if !rh.Matcher.Matches(reqCtx) {
			continue
		}
		if err := b.executeHook(ctx, rh, reqCtx, hooks.ResponseCtx{}); err != nil {
			return err
		}
	}
	return nil
}

func (b *Backend) runCompletionHooks(ctx context.Context, respCtx hooks.ResponseCtx) {
	for _, rh := range b.hookPlan.Completion {
		if !rh.Matcher.Matches(respCtx.ReqCtx) {
			continue
		}
		if err := b.executeHook(ctx, rh, respCtx.ReqCtx, respCtx); err != nil {
			zap.L().Warn("completion hook failed", zap.String("hook", rh.Registration.Name), zap.Error(err))
		}
	}
}

func (b *Backend) executeHook(ctx context.Context, rh hooks.ResolvedHook, reqCtx hooks.RequestCtx, respCtx hooks.ResponseCtx) (err error) {
	hookCtx := ctx
	cancel := func() {}
	if rh.Timeout > 0 {
		hookCtx, cancel = context.WithTimeout(ctx, rh.Timeout)
	}
	defer cancel()

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("hook %s panicked: %v", rh.Registration.Name, r)
		}
	}()

	switch rh.Registration.Kind {
	case hooks.OnRequestReceived:
		err = rh.Registration.Handler.(hooks.RequestHook)(hookCtx, reqCtx)
	case hooks.OnRequestCompleted:
		err = rh.Registration.Handler.(hooks.CompletionHook)(hookCtx, respCtx)
	default:
		err = fmt.Errorf("unknown hook kind %s", rh.Registration.Kind)
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("hook %s timed out", rh.Registration.Name)
	}
	if err != nil {
		return fmt.Errorf("hook %s: %w", rh.Registration.Name, err)
	}
	return nil
}

func (b *Backend) handleProxyResponse(resp *http.Response) error {
	hc, ok := resp.Request.Context().Value(hookContextKey{}).(hookContext)
	if !ok {
		return nil
	}
	respCtx := hooks.ResponseCtx{
		ReqCtx:  hc.reqCtx,
		Status:  resp.StatusCode,
		Headers: resp.Header.Clone(),
		Latency: time.Since(hc.start),
	}
	b.runCompletionHooks(resp.Request.Context(), respCtx)
	return nil
}

func (b *Backend) handleProxyError(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusBadGateway)
	hc, ok := r.Context().Value(hookContextKey{}).(hookContext)
	if !ok {
		return
	}
	respCtx := hooks.ResponseCtx{
		ReqCtx:  hc.reqCtx,
		Status:  http.StatusBadGateway,
		Err:     err,
		Latency: time.Since(hc.start),
	}
	b.runCompletionHooks(r.Context(), respCtx)
}

// Helper to load a CA cert file into an *x509.CertPool.
func loadCertPool(caFile string) (*x509.CertPool, error) {
	zap.L().Debug("Entering loadCertPool", zap.String("caFile", caFile))

	caBytes, err := os.ReadFile(caFile)
	if err != nil {
		zap.L().Error("Could not read CA file",
			zap.String("caFile", caFile),
			zap.Error(err),
		)
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		e := fmt.Errorf("failed to append certs from %s", caFile)
		zap.L().Error(e.Error())
		return nil, e
	}

	zap.L().Debug("Exiting loadCertPool with success", zap.String("caFile", caFile))
	return pool, nil
}

// -------------------------------------------------------------------------
// SINGLE-CONN LISTENER (FIXED)
// -------------------------------------------------------------------------

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

type closeNotifyConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.onClose) // call onClose exactly once
	return err
}

// newSingleConnListener creates a singleConnListener for one net.Conn.
func newSingleConnListener(c net.Conn) *singleConnListener {
	s := &singleConnListener{
		doneChan: make(chan struct{}),
	}

	// Wrap the net.Conn so that when *this* connection is closed,
	// the listener learns about it.
	s.conn = &closeNotifyConn{
		Conn: c,
		onClose: func() {
			s.mu.Lock()
			defer s.mu.Unlock()

			if !s.closed {
				// Mark the listener closed so that subsequent Accept() returns net.ErrClosed.
				s.closed = true
				close(s.doneChan) // unblock anything waiting in Accept()
			}
		},
	}

	return s
}

func (s *singleConnListener) Accept() (net.Conn, error) {
	s.mu.Lock()

	// If the listener is already closed, bail out immediately.
	if s.closed {
		s.mu.Unlock()
		return nil, net.ErrClosed
	}

	// If we haven't given out the connection yet, do so now.
	if !s.used {
		s.used = true
		conn := s.conn
		s.mu.Unlock()
		return conn, nil
	}

	// Any subsequent Accept call must block until the connection is closed,
	// then return net.ErrClosed.
	s.mu.Unlock()

	<-s.doneChan // block until either the connection or the listener is closed
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
		// This will eventually trigger onClose() as well, but we guard with s.closed so it’s safe.
		_ = s.conn.Close()
	}
	close(s.doneChan)
	return nil
}

func (s *singleConnListener) Addr() net.Addr {
	return s.conn.LocalAddr()
}
