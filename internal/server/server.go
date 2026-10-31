package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/example/ipad-proxy/internal/netutil"
	"github.com/example/ipad-proxy/internal/protocol"
)

type Config struct {
	TLSConfig                *tls.Config
	TokenHashes              [][32]byte
	AllowPrivateDestinations bool
	HandshakeTimeout         time.Duration
	DialTimeout              time.Duration
	IOTimeout                time.Duration
	UDPIdleTimeout           time.Duration
	ShutdownTimeout          time.Duration
	Logger                   *slog.Logger
	Resolver                 *net.Resolver
}

type Server struct {
	cfg    Config
	mu     sync.Mutex
	active map[net.Conn]struct{}
	wg     sync.WaitGroup
}

func New(cfg Config) (*Server, error) {
	if cfg.TLSConfig == nil || len(cfg.TokenHashes) == 0 {
		return nil, errors.New("TLS config and token hashes are required")
	}
	if cfg.TLSConfig.MinVersion != tls.VersionTLS13 || cfg.TLSConfig.MaxVersion != tls.VersionTLS13 {
		return nil, errors.New("TLS must be restricted to version 1.3")
	}
	if !contains(cfg.TLSConfig.NextProtos, protocol.ALPN) {
		return nil, errors.New("required ALPN is missing")
	}
	if cfg.HandshakeTimeout <= 0 || cfg.DialTimeout <= 0 || cfg.IOTimeout <= 0 || cfg.UDPIdleTimeout <= 0 || cfg.ShutdownTimeout <= 0 {
		return nil, errors.New("all timeouts must be positive")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	return &Server{cfg: cfg, active: make(map[net.Conn]struct{})}, nil
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				s.waitForShutdown()
				return nil
			}
			return err
		}
		tlsConn := tls.Server(raw, s.cfg.TLSConfig)
		s.track(tlsConn, true)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.track(tlsConn, false)
			defer tlsConn.Close()
			s.handle(ctx, tlsConn)
		}()
	}
}

func (s *Server) waitForShutdown() {
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return
	case <-time.After(s.cfg.ShutdownTimeout):
		s.closeActive()
		<-done
	}
}

func (s *Server) track(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.active[c] = struct{}{}
	} else {
		delete(s.active, c)
	}
}
func (s *Server) closeActive() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.active {
		_ = c.Close()
	}
}

func (s *Server) handle(parent context.Context, conn *tls.Conn) {
	ctx, cancel := context.WithTimeout(parent, s.cfg.HandshakeTimeout)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		s.cfg.Logger.Warn("TLS handshake failed", "remote", remoteIP(conn))
		return
	}
	if conn.ConnectionState().NegotiatedProtocol != protocol.ALPN {
		s.cfg.Logger.Warn("ALPN negotiation failed", "remote", remoteIP(conn))
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	body, err := protocol.ReadFrame(conn)
	if err != nil {
		s.cfg.Logger.Warn("initial frame rejected", "remote", remoteIP(conn))
		return
	}
	req, err := protocol.ParseAuthRequest(body)
	if err != nil {
		s.writeResponse(conn, protocol.StatusBadRequest, "invalid request")
		return
	}
	if !s.authenticate(req.Token) {
		s.writeResponse(conn, protocol.StatusAuthFailed, "authentication failed")
		return
	}
	_ = conn.SetDeadline(time.Time{})
	switch req.Command {
	case protocol.CommandTCPConnect:
		s.handleTCP(parent, conn, *req.Target)
	case protocol.CommandUDPAssociate:
		s.handleUDP(parent, conn)
	}
}

func (s *Server) authenticate(token [32]byte) bool {
	h := sha256.Sum256(token[:])
	matched := 0
	for i := range s.cfg.TokenHashes {
		matched |= subtle.ConstantTimeCompare(h[:], s.cfg.TokenHashes[i][:])
	}
	return matched == 1
}

func (s *Server) writeResponse(conn net.Conn, status protocol.Status, message string) bool {
	body, err := (protocol.Response{Status: status, Message: message}).MarshalBinary()
	if err != nil {
		return false
	}
	_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.IOTimeout))
	return protocol.WriteFrame(conn, body) == nil
}

func (s *Server) handleTCP(ctx context.Context, client net.Conn, target protocol.Address) {
	upstream, forbidden, err := s.dialTCP(ctx, target)
	if forbidden {
		s.writeResponse(client, protocol.StatusForbidden, "destination denied")
		return
	}
	if err != nil {
		s.writeResponse(client, protocol.StatusDialFailed, "connection failed")
		return
	}
	defer upstream.Close()
	s.track(upstream, true)
	defer s.track(upstream, false)
	if !s.writeResponse(client, protocol.StatusOK, "") {
		return
	}
	_ = client.SetDeadline(time.Time{})
	s.cfg.Logger.Info("TCP relay opened", "remote", remoteIP(client), "target_type", target.Type)
	if err := netutil.Relay(client, upstream, s.cfg.IOTimeout); err != nil {
		s.cfg.Logger.Debug("TCP relay ended", "error", err)
	}
}

func (s *Server) dialTCP(ctx context.Context, target protocol.Address) (net.Conn, bool, error) {
	ips, forbidden, err := s.resolveAllowed(ctx, target)
	if err != nil || forbidden {
		return nil, forbidden, err
	}
	dialer := net.Dialer{Timeout: s.cfg.DialTimeout}
	var last error
	for _, ip := range ips {
		address := net.JoinHostPort(ip.String(), strconv.Itoa(int(target.Port)))
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			return conn, false, nil
		}
		last = err
	}
	return nil, false, last
}

func (s *Server) resolveAllowed(ctx context.Context, target protocol.Address) ([]netip.Addr, bool, error) {
	var ips []netip.Addr
	if target.Type == protocol.AddressDomain {
		lookupCtx, cancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
		defer cancel()
		resolved, err := s.cfg.Resolver.LookupNetIP(lookupCtx, "ip", target.Domain)
		if err != nil {
			return nil, false, err
		}
		ips = resolved
	} else {
		ips = []netip.Addr{target.IP.Unmap()}
	}
	if len(ips) == 0 {
		return nil, false, errors.New("target resolved to no addresses")
	}
	for _, ip := range ips {
		if !s.cfg.AllowPrivateDestinations && forbiddenIP(ip.Unmap()) {
			return nil, true, nil
		}
	}
	return ips, false, nil
}

func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return "unknown"
	}
	return host
}

func addrFromNet(addr *net.UDPAddr) (protocol.Address, error) {
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		return protocol.Address{}, fmt.Errorf("invalid UDP address")
	}
	return protocol.AddressFromHostPort(ip.Unmap().String(), uint16(addr.Port))
}
