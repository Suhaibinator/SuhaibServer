package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Suhaibinator/SuhaibServer/internal/backend"
	"github.com/Suhaibinator/SuhaibServer/internal/config"
	"github.com/Suhaibinator/SuhaibServer/internal/proxy_router"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// parseLogLevel tries to parse the user-provided level string into a zapcore.Level.
func parseLogLevel(levelStr string) zapcore.Level {
	// If blank, default to info.
	if levelStr == "" {
		return zapcore.InfoLevel
	}

	// zapcore.ParseLevel handles "debug", "info", "warn", "error", "dpanic", "panic", and "fatal"
	// (case-insensitive).
	lvl, err := zapcore.ParseLevel(strings.ToLower(levelStr))
	if err != nil {
		// If parse fails, default to info.
		fmt.Printf("Unknown log level %q; defaulting to INFO\n", levelStr)
		return zapcore.InfoLevel
	}
	return lvl
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <config-file>\n", os.Args[0])
		os.Exit(1)
	}
	configFilePath := os.Args[1]

	// 1) Load your config (which has LogLevel now).
	cfg, err := config.LoadConfig(configFilePath)
	if err != nil {
		panic(err)
	}

	// 2) Parse the log level from config.
	lvl := parseLogLevel(cfg.LogLevel)

	// 3) Create a zap.Config (production or development) and override the level.
	//    Here we start with production defaults but you could also build from scratch.
	zapCfg := zap.NewProductionConfig()
	zapCfg.Level = zap.NewAtomicLevelAt(lvl)

	// 4) Build and replace global logger.
	logger, err := zapCfg.Build()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()
	zap.ReplaceGlobals(logger)

	// You can now use `zap.L()` or `zap.S()` anywhere in your code.

	// 5) Create your SNI sniffer from config.
	sniffer := proxy_router.SniSniffer{
		MaxReadSize: cfg.SniSniffer.MaxReadSize,
		Timeout:     cfg.SniSniffer.Timeout.Duration,
	}

	// 6) Build backends map.
	backends := make(map[string]*backend.Backend)
	for _, bcfg := range cfg.Backends {
		be, err := backend.NewBackendFromConfig(bcfg)
		if err != nil {
			zap.S().Fatalf("Failed to create backend for HostName=%s: %v", bcfg.Hostname, err)
		}
		backends[bcfg.Hostname] = be
	}

	// Optionally handle default backend.

	// 7) Build the Proxy object (assuming NewProxy is in backend or elsewhere).
	myProxy := backend.NewProxy(sniffer, backends, nil)

	// 8) Determine listening port.
	port := cfg.Port
	if port == "" {
		port = "443"
	}

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		zap.S().Fatalf("Error listening on port %s: %v", port, err)
	}
	zap.S().Infof("Listening on port %s (log level: %s)", port, lvl.String())

	// 9) Accept connections
	for {
		conn, err := ln.Accept()
		if err != nil {
			zap.S().Errorf("Accept error: %v", err)
			continue
		}
		go myProxy.HandleConnection(conn)
	}
}

// initLogger creates and returns a single Zap logger instance.
// You can replace NewProduction() with NewDevelopment() or a custom config.
func initLogger() *zap.Logger {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	return logger
}

// parseCLIArgs checks we have at least one argument (the config file) and returns its path.
func parseCLIArgs() string {
	if len(os.Args) < 2 {
		zap.S().Fatalf("Usage: %s <config-file>", os.Args[0])
	}
	return os.Args[1]
}

// loadConfig loads your YAML/JSON config file into the typed config struct.
func loadConfig(filePath string) *config.Config {
	cfg, err := config.LoadConfig(filePath)
	if err != nil {
		zap.S().Fatalf("Error loading config file %q: %v", filePath, err)
	}
	return cfg
}

// createSniffer constructs the SNI sniffer based on your loaded config.
func createSniffer(cfg *config.Config) proxy_router.SniSniffer {
	return proxy_router.SniSniffer{
		MaxReadSize: cfg.SniSniffer.MaxReadSize,
		Timeout:     cfg.SniSniffer.Timeout.Duration,
	}
}

// buildBackends iterates over your config’s BackendConfig slices and builds them.
func buildBackends(cfg *config.Config) map[string]*backend.Backend {
	backends := make(map[string]*backend.Backend)
	for _, bcfg := range cfg.Backends {
		be, err := backend.NewBackendFromConfig(bcfg)
		if err != nil {
			zap.S().Fatalf("Failed to create backend for HostName=%s: %v", bcfg.Hostname, err)
		}
		backends[bcfg.Hostname] = be
	}
	return backends
}

// startListening opens a TCP listener on the given port.
func startListening(port string) net.Listener {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		zap.S().Fatalf("Error listening: %v", err)
	}
	return ln
}

// acceptLoop continuously accepts connections and hands them to the proxy.
func acceptLoop(ln net.Listener, myProxy *backend.Proxy) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			zap.S().Errorf("Accept error: %v", err)
			continue
		}
		go myProxy.HandleConnection(conn)
	}
}
