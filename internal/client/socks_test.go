package client

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/example/ipad-proxy/internal/protocol"
)

func TestSocksNegotiation(t *testing.T) {
	rw := &readWriter{Reader: bytes.NewReader([]byte{5, 2, 2, 0})}
	if err := negotiate(rw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rw.w.Bytes(), []byte{5, 0}) {
		t.Fatalf("reply %v", rw.w.Bytes())
	}
}

type readWriter struct {
	*bytes.Reader
	w bytes.Buffer
}

func (r *readWriter) Write(p []byte) (int, error) { return r.w.Write(p) }

func TestSocksRequestAddresses(t *testing.T) {
	cases := []protocol.Address{
		{Type: protocol.AddressIPv4, IP: netip.MustParseAddr("192.0.2.2"), Port: 80},
		{Type: protocol.AddressIPv6, IP: netip.MustParseAddr("2001:db8::2"), Port: 443},
		{Type: protocol.AddressDomain, Domain: "example.test", Port: 53},
	}
	for _, target := range cases {
		body := []byte{5, socksConnect, 0}
		var err error
		body, err = appendSocksAddress(body, target, false)
		if err != nil {
			t.Fatal(err)
		}
		got, err := readSocksRequest(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if got.Command != socksConnect || got.Target != target {
			t.Fatalf("got %+v want %+v", got, target)
		}
	}
}

func TestUDPCodecAndFragment(t *testing.T) {
	target := protocol.Address{Type: protocol.AddressDomain, Domain: "example.test", Port: 53}
	packet, err := appendSocksAddress([]byte{0, 0, 0}, target, false)
	if err != nil {
		t.Fatal(err)
	}
	packet = append(packet, []byte("payload")...)
	d, frag, err := parseUDPRequest(packet)
	if err != nil {
		t.Fatal(err)
	}
	if frag != 0 || d.Target != target || string(d.Payload) != "payload" {
		t.Fatalf("bad datagram: %+v", d)
	}
	packet[2] = 1
	_, frag, err = parseUDPRequest(packet)
	if err != nil || frag != 1 {
		t.Fatalf("fragment not surfaced: %d %v", frag, err)
	}
}

func TestRejectInvalidSocks(t *testing.T) {
	if _, err := readSocksRequest(bytes.NewReader([]byte{4, 1, 0})); err == nil {
		t.Fatal("accepted bad version")
	}
	packet := []byte{0, 1, 0, 1, 127, 0, 0, 1, 0, 53}
	if _, _, err := parseUDPRequest(packet); err == nil {
		t.Fatal("accepted bad reserved field")
	}
}

func TestSocksPortEncoding(t *testing.T) {
	a := protocol.Address{Type: protocol.AddressIPv4, IP: netip.MustParseAddr("127.0.0.1"), Port: 0x1234}
	b, err := appendSocksAddress(nil, a, false)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(b[len(b)-2:]) != 0x1234 {
		t.Fatal("port is not network byte order")
	}
}

func TestValidateLoopbackListen(t *testing.T) {
	for _, address := range []string{"127.0.0.1:1080", "[::1]:1080"} {
		if err := ValidateLoopbackListen(address); err != nil {
			t.Errorf("rejected %s: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:1080", "192.0.2.1:1080", "localhost:1080", ":1080"} {
		if err := ValidateLoopbackListen(address); err == nil {
			t.Errorf("accepted %s", address)
		}
	}
}
