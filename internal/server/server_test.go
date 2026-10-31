package server

import (
	"crypto/sha256"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/netip"
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
