package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/ipad-proxy/internal/config"
	"github.com/example/ipad-proxy/internal/protocol"
	"github.com/example/ipad-proxy/internal/server"
)

func main() {
	configPath := flag.String("config", "/etc/ipad-proxy/server.json", "path to JSON configuration")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(*configPath, logger); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(path string, logger *slog.Logger) error {
	cfg, err := config.LoadServer(path)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.Listen == "" || cfg.CertificateFile == "" || cfg.PrivateKeyFile == "" {
		return fmt.Errorf("listen, certificate_file, and private_key_file are required")
	}
	hashes, err := config.DecodeTokenHashes(cfg.TokenSHA256)
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.PrivateKeyFile)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{protocol.ALPN}}
	srv, err := server.New(server.Config{TLSConfig: tlsConfig, TokenHashes: hashes, AllowPrivateDestinations: cfg.AllowPrivateDestinations, HandshakeTimeout: cfg.HandshakeTimeout.Value(10 * time.Second), DialTimeout: cfg.DialTimeout.Value(10 * time.Second), IOTimeout: cfg.IOTimeout.Value(5 * time.Minute), UDPIdleTimeout: cfg.UDPIdleTimeout.Value(2 * time.Minute), ShutdownTimeout: cfg.ShutdownTimeout.Value(10 * time.Second), Logger: logger})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()
	logger.Info("proxy server listening", "address", ln.Addr().String(), "private_destinations_allowed", cfg.AllowPrivateDestinations)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Serve(ctx, ln)
}
