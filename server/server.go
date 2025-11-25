package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/Suhaibinator/SuhaibServer/internal/backend"
	"github.com/Suhaibinator/SuhaibServer/internal/config"
	"github.com/Suhaibinator/SuhaibServer/internal/proxy_router"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// parseLogLevel tries to parse the user-provided level string into a zapcore.Level.
func parseLogLevel(levelStr string) zapcore.Level {
	if levelStr == "" {
		return zapcore.InfoLevel
	}

	lvl, err := zapcore.ParseLevel(strings.ToLower(levelStr))
	if err != nil {
		fmt.Printf("Unknown log level %q; defaulting to INFO\n", levelStr)
		return zapcore.InfoLevel
	}
	log.Printf("Log level set to %s\n", lvl)
	return lvl
}

// RunWithConfigFile loads the YAML configuration from the provided path and starts
// SuhaibServer. The call blocks until the provided context is cancelled or an error occurs.
func RunWithConfigFile(ctx context.Context, configFilePath string) error {
	cfg, err := config.LoadConfig(configFilePath)
	if err != nil {
		return err
	}
	return Run(ctx, cfg)
}

// Run builds SuhaibServer from the supplied configuration and serves traffic until the
// context is cancelled or a fatal error occurs.
func Run(ctx context.Context, cfg *config.Config) error {
	if ctx == nil {
		ctx = context.Background()
	}

	lvl := parseLogLevel(cfg.LogLevel)

	zapCfg := zap.NewProductionConfig()
	zapCfg.Level = zap.NewAtomicLevelAt(lvl)

	logger, err := zapCfg.Build()
	if err != nil {
		return err
	}
	defer logger.Sync()
	zap.ReplaceGlobals(logger)

	sniffer := proxy_router.SniSniffer{
		MaxReadSize: cfg.SniSniffer.MaxReadSize,
		Timeout:     cfg.SniSniffer.Timeout.Duration,
	}

	hookPlans, err := cfg.ResolveBackendHooks()
	if err != nil {
		return err
	}

	backends := make(map[string]*backend.Backend)
	for _, bcfg := range cfg.Backends {
		plan := hookPlans[bcfg.Hostname]
		be, err := backend.NewBackendFromConfig(bcfg, plan)
		if err != nil {
			return fmt.Errorf("failed to create backend for HostName=%s: %w", bcfg.Hostname, err)
		}
		backends[bcfg.Hostname] = be
	}

	myProxy := backend.NewProxy(sniffer, backends, nil)

	httpPort := cfg.HttpPort
	if httpPort == "" {
		httpPort = "80"
	}

	redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backend := myProxy.GetBackend(r.Host)
		if backend == nil {
			http.Error(w, "No such host", http.StatusNotFound)
			return
		}
		if backend.TerminateTLS {
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		myProxy.HandleConnection(conn)
	})

	redirectSrv := &http.Server{
		Addr:    ":" + httpPort,
		Handler: redirectHandler,
	}

	go func() {
		zap.S().Infof("Starting HTTP->HTTPS redirect server on port %s", httpPort)
		if err := redirectSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zap.S().Fatalf("Could not start HTTP->HTTPS redirect server: %v", err)
		}
	}()

	httpsPort := cfg.HttpsPort
	if httpsPort == "" {
		httpsPort = "443"
	}

	ln, err := net.Listen("tcp", ":"+httpsPort)
	if err != nil {
		return fmt.Errorf("error listening on port %s: %w", httpsPort, err)
	}
	defer ln.Close()

	zap.S().Infof("Listening on port %s (log level: %s)", httpsPort, lvl.String())

	stopChan := make(chan struct{})
	go func() {
		<-ctx.Done()
		_ = redirectSrv.Shutdown(context.Background())
		_ = ln.Close()
		close(stopChan)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				<-stopChan
				return ctx.Err()
			default:
			}
			zap.S().Errorf("Accept error: %v", err)
			continue
		}
		go myProxy.HandleConnection(conn)
	}
}
