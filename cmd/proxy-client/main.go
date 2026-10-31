package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/ipad-proxy/internal/client"
	"github.com/example/ipad-proxy/internal/config"
	"github.com/example/ipad-proxy/internal/protocol"
)

func main() {
	configPath := flag.String("config", "/etc/ipad-proxy/client.json", "path to JSON configuration")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(*configPath, logger); err != nil {
		logger.Error("client stopped", "error", err)
		os.Exit(1)
	}
}

func run(path string, logger *slog.Logger) error {
	cfg, err := config.LoadClient(path)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.Listen == "" || cfg.ServerAddress == "" {
		return fmt.Errorf("listen and server_address are required")
	}
	if err := client.ValidateLoopbackListen(cfg.Listen); err != nil {
		return err
	}
	token, err := config.DecodeToken(cfg.Token)
	if err != nil {
		return err
	}
	roots, err := loadRoots(cfg.RootCAFile)
	if err != nil {
		return err
	}
	serverName := cfg.ServerName
	if serverName == "" {
		serverName, _, err = net.SplitHostPort(cfg.ServerAddress)
		if err != nil {
			return fmt.Errorf("server_address: %w", err)
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{protocol.ALPN}, RootCAs: roots, ServerName: serverName}
	proxy, err := client.New(client.Config{TLSConfig: tlsConfig, ServerAddress: cfg.ServerAddress, Token: token, HandshakeTimeout: cfg.HandshakeTimeout.Value(10 * time.Second), IOTimeout: cfg.IOTimeout.Value(5 * time.Minute), UDPIdleTimeout: cfg.UDPIdleTimeout.Value(2 * time.Minute), ShutdownTimeout: cfg.ShutdownTimeout.Value(10 * time.Second), Logger: logger})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()
	logger.Info("SOCKS5 client listening", "address", ln.Addr().String())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return proxy.Serve(ctx, ln)
}

func loadRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read root CA: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("root_ca_file contains no certificates")
	}
	return pool, nil
}
