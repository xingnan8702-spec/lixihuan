package client

import (
	"bytes"
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
	"net/netip"
	"testing"
	"time"

	"github.com/example/ipad-proxy/internal/protocol"
	proxyserver "github.com/example/ipad-proxy/internal/server"
)

func TestLocalEndToEndTCPAndUDP(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	token := [32]byte{1, 3, 3, 7}
	hash := sha256.Sum256(token[:])
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	relayListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := proxyserver.New(proxyserver.Config{TLSConfig: serverTLS, TokenHashes: [][32]byte{hash}, AllowPrivateDestinations: true, HandshakeTimeout: 2 * time.Second, DialTimeout: 2 * time.Second, IOTimeout: 3 * time.Second, UDPIdleTimeout: 3 * time.Second, ShutdownTimeout: time.Second, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = relay.Serve(ctx, relayListener) }()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := New(Config{TLSConfig: clientTLS, ServerAddress: relayListener.Addr().String(), Token: token, HandshakeTimeout: 2 * time.Second, IOTimeout: 3 * time.Second, UDPIdleTimeout: 3 * time.Second, ShutdownTimeout: time.Second, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = proxy.Serve(ctx, proxyListener) }()

	t.Run("authentication rejection", func(t *testing.T) {
		bad := &Client{cfg: Config{TLSConfig: clientTLS.Clone(), ServerAddress: relayListener.Addr().String(), Token: [32]byte{9}, HandshakeTimeout: 2 * time.Second}}
		tunnel, response, err := bad.openTunnel(ctx, protocol.CommandUDPAssociate, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tunnel.Close()
		if response.Status != protocol.StatusAuthFailed {
			t.Fatalf("status %d, want AUTH_FAILED", response.Status)
		}
	})
	t.Run("TCP half-close", func(t *testing.T) { testTCPEndToEnd(t, proxyListener.Addr().String()) })
	t.Run("UDP boundaries and fragment drop", func(t *testing.T) { testUDPEndToEnd(t, proxyListener.Addr().String()) })
}

func testTCPEndToEnd(t *testing.T, proxyAddress string) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		body, err := io.ReadAll(conn)
		if err == nil {
			_, _ = conn.Write(append([]byte("reply:"), body...))
		}
	}()

	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	socksGreeting(t, conn)
	target := addressFor(t, upstream.Addr())
	request, err := appendSocksAddress([]byte{5, socksConnect, 0}, target, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	if rep := readSocksReply(t, conn); rep != repSuccess {
		t.Fatalf("CONNECT reply %d", rep)
	}
	if _, err := conn.Write([]byte("half-close")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "reply:half-close" {
		t.Fatalf("got %q", got)
	}
}

func testUDPEndToEnd(t *testing.T, proxyAddress string) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buf[:n], addr)
		}
	}()

	control, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(5 * time.Second))
	socksGreeting(t, control)
	associate := []byte{5, socksUDPAssociate, 0, byte(protocol.AddressIPv4), 0, 0, 0, 0, 0, 0}
	if _, err := control.Write(associate); err != nil {
		t.Fatal(err)
	}
	rep, bind := readSocksReplyAddress(t, control)
	if rep != repSuccess {
		t.Fatalf("UDP ASSOCIATE reply %d", rep)
	}

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	target := addressFor(t, echo.LocalAddr())
	packet, err := appendSocksAddress([]byte{0, 0, 1}, target, false)
	if err != nil {
		t.Fatal(err)
	}
	packet = append(packet, []byte("drop-me")...)
	if _, err := udp.WriteToUDP(packet, bind); err != nil {
		t.Fatal(err)
	}
	_ = udp.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, _, err := udp.ReadFromUDP(make([]byte, 128)); err == nil {
		t.Fatal("fragmented datagram was forwarded")
	}

	packet[2] = 0
	packet = packet[:len(packet)-len("drop-me")]
	packet = append(packet, []byte("one-datagram")...)
	if _, err := udp.WriteToUDP(packet, bind); err != nil {
		t.Fatal(err)
	}
	_ = udp.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := udp.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	d, frag, err := parseUDPRequest(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if frag != 0 || !bytes.Equal(d.Payload, []byte("one-datagram")) {
		t.Fatalf("bad UDP response: frag=%d payload=%q", frag, d.Payload)
	}
}

func socksGreeting(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply != [2]byte{5, 0} {
		t.Fatalf("greeting reply %v", reply)
	}
}

func readSocksReply(t *testing.T, r io.Reader) byte {
	t.Helper()
	rep, _ := readSocksReplyAddress(t, r)
	return rep
}
func readSocksReplyAddress(t *testing.T, r io.Reader) (byte, *net.UDPAddr) {
	t.Helper()
	var h [3]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		t.Fatal(err)
	}
	if h[0] != 5 || h[2] != 0 {
		t.Fatalf("invalid reply header %v", h)
	}
	a, err := readSocksAddress(r)
	if err != nil {
		t.Fatal(err)
	}
	ip := a.IP
	if !ip.IsValid() {
		ip = netip.MustParseAddr("127.0.0.1")
	}
	return h[1], &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: int(a.Port)}
}

func addressFor(t *testing.T, addr net.Addr) protocol.Address {
	t.Helper()
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := parsePort(portText)
	if err != nil {
		t.Fatal(err)
	}
	a, err := protocol.AddressFromHostPort(host, uint16(port))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func testTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
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
