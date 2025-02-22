package main

import (
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Suhaibinator/SuhaibServer/internal/backend"
	"github.com/Suhaibinator/SuhaibServer/internal/config"
	"github.com/Suhaibinator/SuhaibServer/internal/proxy_router"
)

func main() {
	// Expect the config file path as a CLI argument, e.g. "./SuhaibServer config.yaml"
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <config-file>", os.Args[0])
	}
	configFilePath := os.Args[1]

	// 1) Load the config (YAML or JSON) into a typed structure.
	cfg, err := config.LoadConfig(configFilePath)
	if err != nil {
		log.Fatalf("Error loading config file %q: %v", configFilePath, err)
	}

	// 2) Create our SNI sniffer from the loaded config.
	sniffer := proxy_router.SniSniffer{
		MaxReadSize: cfg.SniSniffer.MaxReadSize,
		Timeout:     cfg.SniSniffer.Timeout.Duration,
	}

	// 3) Create a map of SNI hostname -> Backend from the config.
	backends := make(map[string]*backend.Backend)
	for _, bcfg := range cfg.Backends {
		be, err := backend.NewBackendFromConfig(bcfg)
		if err != nil {
			log.Fatalf("Failed to create backend for HostName=%s: %v", bcfg.Hostname, err)
		}
		backends[bcfg.Hostname] = be
	}

	// Optional: if your config has a notion of a default backend, set it here:
	// var defaultBck *backend.Backend
	// if cfg.DefaultBackend != nil {
	//     defaultBck, err = backend.NewBackendFromConfig(*cfg.DefaultBackend)
	//     if err != nil {
	//         log.Fatalf("Failed to create default backend: %v", err)
	//     }
	// }

	// 4) Build the Proxy object
	myProxy := NewProxy(sniffer, backends, nil)

	// 5) Start listening on

	port := os.Getenv("PORT")
	if port == "" {
		port = "443"
	}

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Error listening: %v", err)
	}
	log.Println("Listening on port " + port)

	// 6) Accept connections in a loop
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go myProxy.handleConnection(conn)
	}
}

// Proxy wraps a sniffer, a map of backends, and an optional default backend.
type Proxy struct {
	sniffer    proxy_router.SniSniffer
	mu         sync.RWMutex
	backends   map[string]*backend.Backend
	defaultBck *backend.Backend // optional fallback
}

func NewProxy(sniffer proxy_router.SniSniffer, backends map[string]*backend.Backend, defaultBackend *backend.Backend) *Proxy {
	return &Proxy{
		sniffer:    sniffer,
		backends:   backends,
		defaultBck: defaultBackend,
	}
}

func (p *Proxy) handleConnection(conn net.Conn) {
	// e.g. 10s overall deadline for the handshake sniff
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	sni, peekedData, err := p.sniffer.SniffSNI(conn)
	if err != nil {
		log.Printf("Error sniffing SNI from %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	log.Printf("Connection from %s with SNI=%q", conn.RemoteAddr(), sni)

	// Create a PeekedConn so further reads see the same initial bytes
	pconn := proxy_router.NewPeekedConn(conn, peekedData)

	// 1) Look up the matching backend
	p.mu.RLock()
	chosenBackend, ok := p.backends[sni]
	p.mu.RUnlock()

	// 2) If no match, maybe fallback
	if !ok {
		if p.defaultBck != nil {
			chosenBackend = p.defaultBck
			log.Printf("No direct match for SNI=%q, using default backend", sni)
		} else {
			log.Printf("No route for SNI=%q, closing.", sni)
			pconn.Close()
			return
		}
	}

	// 3) Use the chosen backend to handle the connection
	if err := chosenBackend.Handle(pconn, sni); err != nil {
		log.Printf("Error handling backend for SNI=%q: %v", sni, err)
		pconn.Close()
	}
}
