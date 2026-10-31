package server

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/example/ipad-proxy/internal/protocol"
)

const (
	maxUDPPeers = 256
	udpPeerTTL  = 60 * time.Second
)

type udpPeerSet struct {
	mu       sync.Mutex
	peers    map[netip.AddrPort]time.Time
	capacity int
	ttl      time.Duration
}

func newUDPPeerSet() *udpPeerSet {
	return newUDPPeerSetWithLimits(maxUDPPeers, udpPeerTTL)
}

func newUDPPeerSetWithLimits(capacity int, ttl time.Duration) *udpPeerSet {
	return &udpPeerSet{
		peers:    make(map[netip.AddrPort]time.Time, capacity),
		capacity: capacity,
		ttl:      ttl,
	}
}

// allow records an endpoint contacted by this association. It returns false
// when a new endpoint would exceed the bounded peer table.
func (p *udpPeerSet) allow(addr *net.UDPAddr) bool {
	return p.allowAt(addr, time.Now())
}

func (p *udpPeerSet) allowAt(addr *net.UDPAddr, now time.Time) bool {
	key, ok := canonicalUDPAddr(addr)
	if !ok {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked(now)
	if _, exists := p.peers[key]; !exists && len(p.peers) >= p.capacity {
		return false
	}
	p.peers[key] = now
	return true
}

func (p *udpPeerSet) contains(addr *net.UDPAddr) bool {
	return p.containsAt(addr, time.Now())
}

func (p *udpPeerSet) containsAt(addr *net.UDPAddr, now time.Time) bool {
	key, ok := canonicalUDPAddr(addr)
	if !ok {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked(now)
	if _, allowed := p.peers[key]; !allowed {
		return false
	}
	p.peers[key] = now
	return true
}

func (p *udpPeerSet) pruneLocked(now time.Time) {
	cutoff := now.Add(-p.ttl)
	for peer, lastSeen := range p.peers {
		if !lastSeen.After(cutoff) {
			delete(p.peers, peer)
		}
	}
}

func canonicalUDPAddr(addr *net.UDPAddr) (netip.AddrPort, bool) {
	if addr == nil || addr.Port <= 0 || addr.Port > 65535 {
		return netip.AddrPort{}, false
	}
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(addr.Port)), true
}

func (s *Server) handleUDP(ctx context.Context, tunnel net.Conn) {
	if !s.udp.tryAcquire() {
		s.writeResponse(tunnel, protocol.StatusInternal, "UDP capacity reached")
		return
	}
	defer s.udp.release()

	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		s.writeResponse(tunnel, protocol.StatusInternal, "UDP unavailable")
		return
	}
	defer udp.Close()
	s.track(udp, true)
	defer s.track(udp, false)
	if !s.writeResponse(tunnel, protocol.StatusOK, "") {
		return
	}
	_ = tunnel.SetDeadline(time.Time{})
	s.cfg.Logger.Info("UDP association opened", "remote", remoteIP(tunnel))

	associationCtx, cancel := context.WithCancel(ctx)
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		<-associationCtx.Done()
		_ = udp.Close()
		_ = tunnel.SetDeadline(time.Now())
	}()

	peers := newUDPPeerSet()
	errs := make(chan error, 2)
	go func() { errs <- s.udpTunnelToNetwork(associationCtx, tunnel, udp, peers) }()
	go func() { errs <- s.udpNetworkToTunnel(tunnel, udp, peers) }()
	<-errs
	cancel()
	<-errs
	<-watcherDone
}

func (s *Server) udpTunnelToNetwork(ctx context.Context, tunnel net.Conn, udp *net.UDPConn, peers *udpPeerSet) error {
	for {
		_ = tunnel.SetReadDeadline(time.Now().Add(s.cfg.UDPIdleTimeout))
		body, err := protocol.ReadFrame(tunnel)
		if err != nil {
			return err
		}
		d, err := protocol.ParseDatagram(body)
		if err != nil {
			return err
		}
		// Activity in either direction keeps the association alive.
		_ = udp.SetReadDeadline(time.Now().Add(s.cfg.UDPIdleTimeout))
		lookupCtx, cancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
		ips, forbidden, err := s.resolveAllowed(lookupCtx, d.Target)
		cancel()
		if forbidden {
			continue
		}
		if err != nil {
			continue
		}
		for _, ip := range ips {
			addr := &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: int(d.Target.Port)}
			// Only endpoints explicitly contacted by this association may send
			// datagrams back through the tunnel. Register before WriteToUDP so a
			// very fast response cannot race the allow-list update.
			if !peers.allow(addr) {
				continue
			}
			_ = udp.SetWriteDeadline(time.Now().Add(s.cfg.IOTimeout))
			if _, err = udp.WriteToUDP(d.Payload, addr); err == nil {
				break
			}
		}
	}
}

func (s *Server) udpNetworkToTunnel(tunnel net.Conn, udp *net.UDPConn, peers *udpPeerSet) error {
	buf := make([]byte, protocol.MaxUDPPayload+1)
	for {
		_ = udp.SetReadDeadline(time.Now().Add(s.cfg.UDPIdleTimeout))
		n, source, err := udp.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		if n > protocol.MaxUDPPayload || !peers.contains(source) {
			continue
		}
		// Activity in either direction keeps the association alive.
		_ = tunnel.SetReadDeadline(time.Now().Add(s.cfg.UDPIdleTimeout))
		target, err := addrFromNet(source)
		if err != nil {
			continue
		}
		body, err := (protocol.Datagram{Target: target, Payload: buf[:n]}).MarshalBinary()
		if err != nil {
			continue
		}
		_ = tunnel.SetWriteDeadline(time.Now().Add(s.cfg.IOTimeout))
		if err := protocol.WriteFrame(tunnel, body); err != nil {
			return err
		}
	}
}
