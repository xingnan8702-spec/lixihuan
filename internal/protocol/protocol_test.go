package protocol

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

func TestAddressRoundTrip(t *testing.T) {
	tests := []Address{
		{Type: AddressIPv4, IP: netip.MustParseAddr("192.0.2.1"), Port: 443},
		{Type: AddressIPv6, IP: netip.MustParseAddr("2001:db8::1"), Port: 53},
		{Type: AddressDomain, Domain: "example.test", Port: 8080},
	}
	for _, want := range tests {
		b, err := want.AppendTo(nil)
		if err != nil {
			t.Fatal(err)
		}
		got, n, err := ParseAddress(b)
		if err != nil {
			t.Fatal(err)
		}
		if n != len(b) || got != want {
			t.Fatalf("got %+v/%d, want %+v/%d", got, n, want, len(b))
		}
	}
}

func TestFrameBoundsAndShortReads(t *testing.T) {
	body := []byte("hello")
	var buf bytes.Buffer
	if err := WriteFrame(&buf, body); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&oneByteReader{r: bytes.NewReader(buf.Bytes())})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("got %q", got)
	}
	for _, n := range []uint32{0, MaxFrameSize + 1} {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], n)
		if _, err := ReadFrame(bytes.NewReader(h[:])); err == nil {
			t.Fatalf("accepted length %d", n)
		}
	}
}

type oneByteReader struct{ r *bytes.Reader }

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.r.Read(p)
}

func TestMessages(t *testing.T) {
	token := [32]byte{1, 2, 3}
	target := Address{Type: AddressDomain, Domain: "example.test", Port: 443}
	for _, req := range []AuthRequest{{Command: CommandTCPConnect, Token: token, Target: &target}, {Command: CommandUDPAssociate, Token: token}} {
		b, err := req.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseAuthRequest(b)
		if err != nil {
			t.Fatal(err)
		}
		if got.Command != req.Command || got.Token != req.Token {
			t.Fatalf("request mismatch: %+v", got)
		}
	}
	resp := Response{Status: StatusForbidden, Message: "destination denied"}
	b, err := resp.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseResponse(b)
	if err != nil || got != resp {
		t.Fatalf("response: %+v %v", got, err)
	}
	if _, err := (Response{Message: strings.Repeat("x", MaxMessageSize+1)}).MarshalBinary(); err == nil {
		t.Fatal("accepted oversized message")
	}
}

func TestRejectMalformedMessages(t *testing.T) {
	valid := make([]byte, 3+TokenSize)
	valid[0], valid[1], valid[2] = Version, byte(CommandUDPAssociate), TokenSize
	cases := [][]byte{nil, append(append([]byte(nil), valid...), 1), {2, 2, 32}, {1, 9, 32}}
	for i, b := range cases {
		if _, err := ParseAuthRequest(b); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}

func TestDatagramDynamicFrameBound(t *testing.T) {
	d := Datagram{Target: Address{Type: AddressDomain, Domain: strings.Repeat("a", 253), Port: 53}, Payload: make([]byte, MaxUDPPayload)}
	if _, err := d.MarshalBinary(); err == nil {
		t.Fatal("accepted datagram exceeding frame bound")
	}
}
