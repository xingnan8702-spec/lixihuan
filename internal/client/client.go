package client

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/example/ipad-proxy/internal/netutil"
	"github.com/example/ipad-proxy/internal/protocol"
)

type Config struct {
	TLSConfig        *tls.Config
	ServerAddress    string
	Token            [32]byte
	HandshakeTimeout time.Duration
	IOTimeout        time.Duration
	UDPIdleTimeout   time.Duration
	ShutdownTimeout  time.Duration
	Logger           *slog.Logger
}

type Client struct {
	cfg    Config
	mu     sync.Mutex
	active map[net.Conn]struct{}
	wg     sync.WaitGroup
}

func New(cfg Config) (*Client, error) {
	if cfg.TLSConfig == nil || cfg.ServerAddress == "" {
		return nil, errors.New("TLS config and server address are required")
	}
	if cfg.TLSConfig.MinVersion != tls.VersionTLS13 || cfg.TLSConfig.MaxVersion != tls.VersionTLS13 {
		return nil, errors.New("TLS must be restricted to version 1.3")
	}
	if !contains(cfg.TLSConfig.NextProtos, protocol.ALPN) {
		return nil, errors.New("required ALPN is missing")
	}
	if cfg.HandshakeTimeout <= 0 || cfg.IOTimeout <= 0 || cfg.UDPIdleTimeout <= 0 || cfg.ShutdownTimeout <= 0 {
		return nil, errors.New("all timeouts must be positive")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Client{cfg: cfg, active: make(map[net.Conn]struct{})}, nil
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func ValidateLoopbackListen(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return errors.New("SOCKS listener must use an explicit loopback IP address")
	}
	return nil
}

func (c *Client) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				c.waitForShutdown()
				return nil
			}
			return err
		}
		c.track(conn, true)
		c.wg.Add(1)
		go func() { defer c.wg.Done(); defer c.track(conn, false); defer conn.Close(); c.handle(ctx, conn) }()
	}
}

func (c *Client) waitForShutdown() {
	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()
	select {
	case <-done:
		return
	case <-time.After(c.cfg.ShutdownTimeout):
		c.closeActive()
		<-done
	}
}

func (c *Client) track(conn net.Conn, add bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if add {
		c.active[conn] = struct{}{}
	} else {
		delete(c.active, conn)
	}
}
func (c *Client) closeActive() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for conn := range c.active {
		_ = conn.Close()
	}
}

func (c *Client) handle(ctx context.Context, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(c.cfg.IOTimeout))
	if err := negotiate(conn); err != nil {
		return
	}
	req, err := readSocksRequest(conn)
	if err != nil {
		_ = writeSocksReply(conn, repAddressUnsupported, nil)
		return
	}
	switch req.Command {
	case socksConnect:
		c.handleTCP(ctx, conn, req.Target)
	case socksUDPAssociate:
		c.handleUDP(ctx, conn, req.Target)
	default:
		_ = writeSocksReply(conn, repCommandUnsupported, nil)
	}
}

func (c *Client) handleTCP(ctx context.Context, local net.Conn, target protocol.Address) {
	tunnel, response, err := c.openTunnel(ctx, protocol.CommandTCPConnect, &target)
	if err != nil {
		_ = writeSocksReply(local, repHostUnreachable, nil)
		return
	}
	defer tunnel.Close()
	c.track(tunnel, true)
	defer c.track(tunnel, false)
	if response.Status != protocol.StatusOK {
		_ = writeSocksReply(local, statusToReply(response.Status), nil)
		return
	}
	if err := writeSocksReply(local, repSuccess, tunnel.LocalAddr()); err != nil {
		return
	}
	_ = local.SetDeadline(time.Time{})
	_ = tunnel.SetDeadline(time.Time{})
	if err := netutil.Relay(local, tunnel, c.cfg.IOTimeout); err != nil {
		c.cfg.Logger.Debug("TCP client relay ended", "error", err)
	}
}

func statusToReply(status protocol.Status) byte {
	switch status {
	case protocol.StatusForbidden, protocol.StatusAuthFailed:
		return repNotAllowed
	case protocol.StatusDialFailed:
		return repConnectionRefused
	case protocol.StatusBadRequest:
		return repAddressUnsupported
	default:
		return repGeneralFailure
	}
}
