package backend

import (
	"net"
	"sync"
	"time"

	"github.com/Suhaibinator/SuhaibServer/internal/proxy_router"
	"go.uber.org/zap"
)

// Proxy wraps a sniffer, a map of backends, and an optional default backend.
type Proxy struct {
	sniffer    proxy_router.SniSniffer
	mu         sync.RWMutex
	backends   map[string]*Backend
	defaultBck *Backend // optional fallback
}

func NewProxy(sniffer proxy_router.SniSniffer, backends map[string]*Backend, defaultBackend *Backend) *Proxy {
	return &Proxy{
		sniffer:    sniffer,
		backends:   backends,
		defaultBck: defaultBackend,
	}
}

func (p *Proxy) HandleConnection(conn net.Conn) {
	// e.g. 10s overall deadline for the handshake sniff
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	sni, peekedData, err := p.sniffer.SniffSNI(conn)
	if err != nil {
		zap.S().Errorf("Error sniffing SNI from %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	zap.S().Infof("Connection from %s with SNI=%q", conn.RemoteAddr(), sni)

	// Create a PeekedConn so further reads see the same initial bytes
	pconn := proxy_router.NewPeekedConn(conn, peekedData)

	// Look up the matching backend
	p.mu.RLock()
	chosenBackend, ok := p.backends[sni]
	p.mu.RUnlock()

	// If no match, maybe fallback
	if !ok {
		if p.defaultBck != nil {
			chosenBackend = p.defaultBck
			zap.S().Infof("No direct match for SNI=%q, using default backend", sni)
		} else {
			zap.S().Warnf("No route for SNI=%q; closing connection.", sni)
			pconn.Close()
			return
		}
	}

	// Use the chosen backend to handle the connection
	if err := chosenBackend.Handle(pconn, sni); err != nil {
		zap.S().Errorf("Error handling backend for SNI=%q: %v", sni, err)
		pconn.Close()
	}
}

func (p *Proxy) GetBackend(host string) *Backend {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.backends[host]
}
