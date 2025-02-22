package main

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/Suhaibinator/SuhaibServer/backend"
	"github.com/Suhaibinator/SuhaibServer/proxy_router"
)

func main() {
	ln, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("Error listening: %v", err)
	}
	log.Println("Listening on :443")

	myProxy := Proxy{
		sniffer: proxy_router.SniSniffer{
			MaxReadSize: 65536,
			Timeout:     5 * time.Second,
		},
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go myProxy.handleConnection(conn)
	}
}

type Proxy struct {
	sniffer    proxy_router.SniSniffer
	mu         sync.RWMutex
	backends   map[string]*backend.Backend
	defaultBck *backend.Backend // optional: a default if no match
}

func NewProxy(sniffer proxy_router.SniSniffer, backends map[string]*backend.Backend, defaultBackend *backend.Backend) *Proxy {
	return &Proxy{
		sniffer:    sniffer,
		backends:   backends,
		defaultBck: defaultBackend,
	}
}

// handleConnection is called for each incoming connection.
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

	// 1) Lock and find the matching backend
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
