package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/example/ipad-proxy/internal/protocol"
)

type runningServer struct {
	server    *Server
	address   string
	clientTLS *tls.Config
	token     [32]byte
	cancel    context.CancelFunc
	done      chan struct{}
	serveErr  error
}

func TestTotalConnectionCapRejectsCapPlusOne(t *testing.T) {
	r := startRunningServer(t, 1, 1, 1)
	first := dialRaw(t, r.address)
	defer first.Close()
	waitFor(t, time.Second, func() bool { return r.server.Snapshot().ActiveSessions == 1 })

	second := dialRaw(t, r.address)
	defer second.Close()
	waitFor(t, time.Second, func() bool { return r.server.Snapshot().RejectedConnections == 1 })
	assertClosedSoon(t, second)

	snapshot := r.server.Snapshot()
	if snapshot.ActiveSessions != 1 || snapshot.ActiveHandshakes != 1 {
		t.Fatalf("snapshot after rejection = %+v", snapshot)
	}
}

func TestSlowHandshakeCapRejectsBeforeTLS(t *testing.T) {
	r := startRunningServer(t, 3, 1, 1)
	first := dialRaw(t, r.address)
	defer first.Close()
	waitFor(t, time.Second, func() bool { return r.server.Snapshot().ActiveHandshakes == 1 })

	second := dialRaw(t, r.address)
	defer second.Close()
	waitFor(t, time.Second, func() bool { return r.server.Snapshot().RejectedHandshakes == 1 })
	assertClosedSoon(t, second)
	waitFor(t, time.Second, func() bool {
		snapshot := r.server.Snapshot()
		return snapshot.ActiveSessions == 1 && snapshot.ActiveHandshakes == 1
	})

	snapshot := r.server.Snapshot()
	if snapshot.ActiveSessions != 1 || snapshot.ActiveHandshakes != 1 {
		t.Fatalf("snapshot after handshake rejection = %+v", snapshot)
	}
}

func TestAuthenticationFailureReleasesHandshakePermit(t *testing.T) {
	r := startRunningServer(t, 2, 1, 1)
	badToken := [32]byte{9}
	conn, response := sendRequest(t, r, badToken, protocol.CommandUDPAssociate)
	conn.Close()
	if response.Status != protocol.StatusAuthFailed {
		t.Fatalf("status = %d, want AUTH_FAILED", response.Status)
	}
	waitFor(t, time.Second, func() bool {
		snapshot := r.server.Snapshot()
		return snapshot.ActiveSessions == 0 && snapshot.ActiveHandshakes == 0
	})

	next := dialTLS(t, r)
	defer next.Close()
	waitFor(t, time.Second, func() bool { return r.server.Snapshot().ActiveHandshakes == 1 })
}

func TestUDPAssociationCapRejectsBeforeOK(t *testing.T) {
	r := startRunningServer(t, 3, 3, 1)
	first, firstResponse := sendRequest(t, r, r.token, protocol.CommandUDPAssociate)
	defer first.Close()
	if firstResponse.Status != protocol.StatusOK {
		t.Fatalf("first status = %d, want OK", firstResponse.Status)
	}
	waitFor(t, time.Second, func() bool { return r.server.Snapshot().ActiveUDPAssociations == 1 })

	second, secondResponse := sendRequest(t, r, r.token, protocol.CommandUDPAssociate)
	defer second.Close()
	if secondResponse.Status != protocol.StatusInternal {
		t.Fatalf("second status = %d, want INTERNAL", secondResponse.Status)
	}
	waitFor(t, time.Second, func() bool {
		return r.server.Snapshot().RejectedUDPAssociations == 1
	})
	if got := r.server.Snapshot().ActiveUDPAssociations; got != 1 {
		t.Fatalf("active UDP associations = %d, want 1", got)
	}
}

func TestShutdownWaitsForUDPPumps(t *testing.T) {
	r := startRunningServer(t, 2, 2, 1)
	conn, response := sendRequest(t, r, r.token, protocol.CommandUDPAssociate)
	defer conn.Close()
	if response.Status != protocol.StatusOK {
		t.Fatalf("status = %d, want OK", response.Status)
	}
	waitFor(t, time.Second, func() bool { return r.server.Snapshot().ActiveUDPAssociations == 1 })

	r.cancel()
	select {
	case <-r.done:
		if r.serveErr != nil {
			t.Fatal(r.serveErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after shutdown")
	}
	if snapshot := r.server.Snapshot(); snapshot.ActiveSessions != 0 || snapshot.ActiveHandshakes != 0 || snapshot.ActiveUDPAssociations != 0 {
		t.Fatalf("active work remained after shutdown: %+v", snapshot)
	}
}

func startRunningServer(t *testing.T, maxConnections, maxHandshakes, maxUDPAssociations int) *runningServer {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	token := [32]byte{1, 3, 3, 7}
	hash := sha256.Sum256(token[:])
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := New(Config{
		TLSConfig:          serverTLS,
		TokenHashes:        [][32]byte{hash},
		MaxConnections:     maxConnections,
		MaxHandshakes:      maxHandshakes,
		MaxUDPAssociations: maxUDPAssociations,
		HandshakeTimeout:   2 * time.Second,
		DialTimeout:        time.Second,
		IOTimeout:          time.Second,
		UDPIdleTimeout:     2 * time.Second,
		ShutdownTimeout:    time.Second,
		Logger:             logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	r := &runningServer{server: s, address: ln.Addr().String(), clientTLS: clientTLS, token: token, cancel: cancel, done: done}
	go func() {
		r.serveErr = s.Serve(ctx, ln)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("server cleanup timed out")
		}
	})
	return r
}

func dialRaw(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func dialTLS(t *testing.T, r *runningServer) *tls.Conn {
	t.Helper()
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := tls.DialWithDialer(&dialer, "tcp", r.address, r.clientTLS.Clone())
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func sendRequest(t *testing.T, r *runningServer, token [32]byte, command protocol.Command) (*tls.Conn, protocol.Response) {
	t.Helper()
	conn := dialTLS(t, r)
	body, err := (protocol.AuthRequest{Command: command, Token: token}).MarshalBinary()
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if err := protocol.WriteFrame(conn, body); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	responseBody, err := protocol.ReadFrame(conn)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	response, err := protocol.ParseResponse(responseBody)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, response
}

func assertClosedSoon(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("rejected connection remained open")
	}
}

func testTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{protocol.ALPN}}
	clientTLS := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{protocol.ALPN}}
	return serverTLS, clientTLS
}
