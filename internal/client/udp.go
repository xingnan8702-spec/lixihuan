package client

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/example/ipad-proxy/internal/protocol"
)

func (c *Client) handleUDP(ctx context.Context, control net.Conn, requested protocol.Address) {
	tunnel, response, err := c.openTunnel(ctx, protocol.CommandUDPAssociate, nil)
	if err != nil {
		_ = writeSocksReply(control, repHostUnreachable, nil)
		return
	}
	defer tunnel.Close()
	c.track(tunnel, true)
	defer c.track(tunnel, false)
	if response.Status != protocol.StatusOK {
		_ = writeSocksReply(control, statusToReply(response.Status), nil)
		return
	}

	bindIP := net.ParseIP("127.0.0.1")
	if tcpAddr, ok := control.LocalAddr().(*net.TCPAddr); ok && tcpAddr.IP.To4() == nil {
		bindIP = net.ParseIP("::1")
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP})
	if err != nil {
		_ = writeSocksReply(control, repGeneralFailure, nil)
		return
	}
	defer udp.Close()
	c.track(udp, true)
	defer c.track(udp, false)
	if err := writeSocksReply(control, repSuccess, udp.LocalAddr()); err != nil {
		return
	}
	_ = control.SetDeadline(time.Time{})

	peerIP := remoteAddrIP(control)
	var endpointMu sync.RWMutex
	var endpoint *net.UDPAddr
	if requested.Port != 0 {
		ip := requested.IP
		if !ip.IsValid() || ip.IsUnspecified() {
			ip = peerIP
		}
		if ip == peerIP {
			endpoint = &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: int(requested.Port)}
		}
	}

	var once sync.Once
	done := make(chan struct{})
	stop := func() { once.Do(func() { close(done); _ = udp.Close(); _ = tunnel.Close(); _ = control.Close() }) }
	defer stop()
	go func() {
		select {
		case <-ctx.Done():
			stop()
		case <-done:
		}
	}()
	errs := make(chan error, 3)
	go func() { errs <- c.udpLocalToTunnel(udp, tunnel, peerIP, &endpointMu, &endpoint) }()
	go func() { errs <- c.udpTunnelToLocal(tunnel, udp, &endpointMu, &endpoint) }()
	go func() { var b [1]byte; _, err := control.Read(b[:]); errs <- err }()
	<-errs
}

func (c *Client) udpLocalToTunnel(udp *net.UDPConn, tunnel net.Conn, peerIP netip.Addr, mu *sync.RWMutex, endpoint **net.UDPAddr) error {
	buf := make([]byte, protocol.MaxFrameSize+3)
	for {
		_ = udp.SetReadDeadline(time.Now().Add(c.cfg.UDPIdleTimeout))
		n, source, err := udp.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		sourceIP, ok := netip.AddrFromSlice(source.IP)
		if !ok || sourceIP.Unmap() != peerIP.Unmap() {
			continue
		}
		d, frag, err := parseUDPRequest(buf[:n])
		if err != nil || frag != 0 {
			continue
		}
		// Activity in either direction keeps the association alive.
		_ = tunnel.SetReadDeadline(time.Now().Add(c.cfg.UDPIdleTimeout))
		mu.Lock()
		if *endpoint == nil {
			copyAddr := *source
			*endpoint = &copyAddr
		}
		allowed := sameUDPAddr(*endpoint, source)
		mu.Unlock()
		if !allowed {
			continue
		}
		body, err := d.MarshalBinary()
		if err != nil {
			continue
		}
		_ = tunnel.SetWriteDeadline(time.Now().Add(c.cfg.IOTimeout))
		if err := protocol.WriteFrame(tunnel, body); err != nil {
			return err
		}
	}
}

func (c *Client) udpTunnelToLocal(tunnel net.Conn, udp *net.UDPConn, mu *sync.RWMutex, endpoint **net.UDPAddr) error {
	for {
		_ = tunnel.SetReadDeadline(time.Now().Add(c.cfg.UDPIdleTimeout))
		body, err := protocol.ReadFrame(tunnel)
		if err != nil {
			return err
		}
		d, err := protocol.ParseDatagram(body)
		if err != nil {
			return err
		}
		// Activity in either direction keeps the association alive.
		_ = udp.SetReadDeadline(time.Now().Add(c.cfg.UDPIdleTimeout))
		packet, err := marshalUDPResponse(d)
		if err != nil {
			continue
		}
		mu.RLock()
		destination := *endpoint
		if destination != nil {
			copyAddr := *destination
			destination = &copyAddr
		}
		mu.RUnlock()
		if destination == nil {
			continue
		}
		_ = udp.SetWriteDeadline(time.Now().Add(c.cfg.IOTimeout))
		if _, err := udp.WriteToUDP(packet, destination); err != nil {
			return err
		}
	}
}

func remoteAddrIP(conn net.Conn) netip.Addr {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}
	}
	ip, _ := netip.ParseAddr(host)
	return ip.Unmap()
}
func sameUDPAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}
