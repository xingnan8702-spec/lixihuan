package server

import (
	"crypto/sha256"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/example/ipad-proxy/internal/protocol"
)

func TestAuthentication(t *testing.T) {
	token := [32]byte{1, 2, 3}
	hash := sha256.Sum256(token[:])
	s := &Server{cfg: Config{TokenHashes: [][32]byte{hash}}}
	if !s.authenticate(token) {
		t.Fatal("valid token rejected")
	}
	token[0] ^= 1
	if s.authenticate(token) {
		t.Fatal("invalid token accepted")
	}
}

func TestDestinationPolicy(t *testing.T) {
	denied := []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "224.0.0.1", "::", "::1", "fe80::1", "ff02::1"}
	for _, value := range denied {
		if DestinationAllowed(netip.MustParseAddr(value), false) {
			t.Errorf("allowed %s", value)
		}
	}
	if !DestinationAllowed(netip.MustParseAddr("192.0.2.1"), false) {
		t.Fatal("denied public/documentation address")
	}
	if !DestinationAllowed(netip.MustParseAddr("127.0.0.1"), true) {
		t.Fatal("development override failed")
	}
}

func TestNewValidation(t *testing.T) {
	_, err := New(Config{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{protocol.ALPN}}, TokenHashes: [][32]byte{{}}, HandshakeTimeout: time.Second, DialTimeout: time.Second, IOTimeout: time.Second, UDPIdleTimeout: time.Second, ShutdownTimeout: time.Second, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUDPPeerSetOnlyAllowsContactedEndpoints(t *testing.T) {
	peers := newUDPPeerSet()
	allowed := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 443}
	mapped := &net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.10"), Port: 443}
	wrongPort := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 444}
	other := &net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 443}

	if peers.contains(allowed) {
		t.Fatal("uncontacted endpoint was allowed")
	}
	peers.allow(allowed)
	if !peers.contains(allowed) || !peers.contains(mapped) {
		t.Fatal("contacted endpoint was not allowed")
	}
	if peers.contains(wrongPort) || peers.contains(other) || peers.contains(nil) {
		t.Fatal("unrelated endpoint was allowed")
	}
}

func TestUDPPeerSetIsBoundedAndExpiresIdlePeers(t *testing.T) {
	peers := newUDPPeerSetWithLimits(2, time.Minute)
	now := time.Unix(1_000, 0)
	first := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1001}
	second := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1002}
	third := &net.UDPAddr{IP: net.ParseIP("192.0.2.3"), Port: 1003}

	if !peers.allowAt(first, now) || !peers.allowAt(second, now) {
		t.Fatal("valid peers were rejected below capacity")
	}
	if peers.allowAt(third, now) {
		t.Fatal("peer table accepted an entry above capacity")
	}
	if !peers.containsAt(first, now.Add(30*time.Second)) {
		t.Fatal("active peer expired too early")
	}
	if !peers.allowAt(third, now.Add(61*time.Second)) {
		t.Fatal("expired peer capacity was not reclaimed")
	}
	if peers.containsAt(second, now.Add(61*time.Second)) {
		t.Fatal("idle peer remained allowed after expiry")
	}
}

func TestNewConnectionLimitDefaultsAndValidation(t *testing.T) {
	base := Config{
		TLSConfig:        &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{protocol.ALPN}},
		TokenHashes:      [][32]byte{{}},
		HandshakeTimeout: time.Second,
		DialTimeout:      time.Second,
		IOTimeout:        time.Second,
		UDPIdleTimeout:   time.Second,
		ShutdownTimeout:  time.Second,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	s, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.MaxConnections != DefaultMaxConnections || s.cfg.MaxHandshakes != DefaultMaxHandshakes || s.cfg.MaxUDPAssociations != DefaultMaxUDPAssociations {
		t.Fatalf("defaults = %d/%d/%d", s.cfg.MaxConnections, s.cfg.MaxHandshakes, s.cfg.MaxUDPAssociations)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "connections", mutate: func(c *Config) { c.MaxConnections = -1 }},
		{name: "handshakes", mutate: func(c *Config) { c.MaxHandshakes = -1 }},
		{name: "UDP associations", mutate: func(c *Config) { c.MaxUDPAssociations = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("accepted negative limit")
			}
		})
	}
}

func TestPermitConcurrentCapacityAndRelease(t *testing.T) {
	const capacity = 8
	const workers = 64
	p := newPermit(capacity)
	start := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			<-start
			if !p.tryAcquire() {
				return
			}
			<-release
			p.release()
		}()
	}
	close(start)
	waitFor(t, time.Second, func() bool { return p.active.Load()+int64(p.rejected.Load()) == workers })
	if got := p.active.Load(); got != capacity {
		t.Fatalf("active permits = %d, want %d", got, capacity)
	}
	if got := p.rejected.Load(); got != workers-capacity {
		t.Fatalf("rejected permits = %d, want %d", got, workers-capacity)
	}
	close(release)
	wg.Wait()
	if got := p.active.Load(); got != 0 {
		t.Fatalf("active permits after release = %d", got)
	}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

func TestPermitActiveMetricNeverExceedsCapacity(t *testing.T) {
	const capacity = 4
	const workers = 32
	const attempts = 500
	p := newPermit(capacity)
	start := make(chan struct{})
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			<-start
			for range attempts {
				if p.tryAcquire() {
					runtime.Gosched()
					p.release()
				}
				runtime.Gosched()
			}
		}()
	}
	go func() {
		wg.Wait()
		close(done)
	}()
	close(start)
	for {
		select {
		case <-done:
			if active := p.active.Load(); active != 0 {
				t.Fatalf("active permits after workers stopped = %d", active)
			}
			return
		default:
			active := p.active.Load()
			if active < 0 || active > capacity {
				t.Fatalf("active permits = %d, want range [0,%d]", active, capacity)
			}
			runtime.Gosched()
		}
	}
}
