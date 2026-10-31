package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/example/ipad-proxy/internal/protocol"
)

const (
	socksVersion          = 5
	socksConnect          = 1
	socksUDPAssociate     = 3
	repSuccess            = 0
	repGeneralFailure     = 1
	repNotAllowed         = 2
	repNetworkUnreachable = 3
	repHostUnreachable    = 4
	repConnectionRefused  = 5
	repCommandUnsupported = 7
	repAddressUnsupported = 8
)

type socksRequest struct {
	Command byte
	Target  protocol.Address
}

func negotiate(rw io.ReadWriter) error {
	var header [2]byte
	if _, err := io.ReadFull(rw, header[:]); err != nil {
		return err
	}
	if header[0] != socksVersion || header[1] == 0 {
		return errors.New("invalid SOCKS greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(rw, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == 0 {
			_, err := rw.Write([]byte{socksVersion, 0})
			return err
		}
	}
	_, _ = rw.Write([]byte{socksVersion, 0xff})
	return errors.New("no supported authentication method")
}

func readSocksRequest(r io.Reader) (socksRequest, error) {
	var h [3]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return socksRequest{}, err
	}
	if h[0] != socksVersion || h[2] != 0 {
		return socksRequest{}, errors.New("invalid SOCKS request")
	}
	a, err := readSocksAddress(r)
	if err != nil {
		return socksRequest{}, err
	}
	return socksRequest{Command: h[1], Target: a}, nil
}

func readSocksAddress(r io.Reader) (protocol.Address, error) {
	var typ [1]byte
	if _, err := io.ReadFull(r, typ[:]); err != nil {
		return protocol.Address{}, err
	}
	var host string
	switch protocol.AddressType(typ[0]) {
	case protocol.AddressIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return protocol.Address{}, err
		}
		host = netip.AddrFrom4(b).String()
	case protocol.AddressIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return protocol.Address{}, err
		}
		host = netip.AddrFrom16(b).String()
	case protocol.AddressDomain:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return protocol.Address{}, err
		}
		if n[0] == 0 {
			return protocol.Address{}, errors.New("empty SOCKS domain")
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return protocol.Address{}, err
		}
		host = string(b)
	default:
		return protocol.Address{}, errors.New("unsupported SOCKS address type")
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return protocol.Address{}, err
	}
	port := binary.BigEndian.Uint16(p[:])
	// UDP ASSOCIATE commonly uses 0.0.0.0:0 to ask the proxy to learn the
	// client's datagram endpoint. Tunnel protocol targets still reject port 0.
	if port == 0 {
		a, err := protocol.AddressFromHostPort(host, 1)
		if err != nil {
			return protocol.Address{}, err
		}
		a.Port = 0
		return a, nil
	}
	return protocol.AddressFromHostPort(host, port)
}

func writeSocksReply(w io.Writer, rep byte, addr net.Addr) error {
	body := []byte{socksVersion, rep, 0}
	var a protocol.Address
	var err error
	if addr != nil {
		host, portText, splitErr := net.SplitHostPort(addr.String())
		var port uint64
		if splitErr == nil {
			port, splitErr = parsePort(portText)
		}
		if splitErr == nil {
			a, err = protocol.AddressFromHostPort(host, uint16(port))
		} else {
			err = splitErr
		}
	} else {
		a, err = protocol.AddressFromHostPort("0.0.0.0", 1)
		a.Port = 0
	}
	if err != nil {
		return err
	}
	body, err = appendSocksAddress(body, a, addr == nil)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func appendSocksAddress(dst []byte, a protocol.Address, permitZero bool) ([]byte, error) {
	dst = append(dst, byte(a.Type))
	switch a.Type {
	case protocol.AddressIPv4:
		v := a.IP.As4()
		dst = append(dst, v[:]...)
	case protocol.AddressIPv6:
		v := a.IP.As16()
		dst = append(dst, v[:]...)
	case protocol.AddressDomain:
		if len(a.Domain) > 255 {
			return nil, errors.New("domain too long")
		}
		dst = append(dst, byte(len(a.Domain)))
		dst = append(dst, a.Domain...)
	default:
		return nil, errors.New("invalid address type")
	}
	if a.Port == 0 && !permitZero {
		return nil, errors.New("zero port")
	}
	return binary.BigEndian.AppendUint16(dst, a.Port), nil
}

func parsePort(s string) (uint64, error) {
	var p uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid port")
		}
		p = p*10 + uint64(c-'0')
		if p > 65535 {
			return 0, fmt.Errorf("invalid port")
		}
	}
	return p, nil
}

func parseUDPRequest(packet []byte) (protocol.Datagram, byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 {
		return protocol.Datagram{}, 0, errors.New("invalid SOCKS UDP packet")
	}
	frag := packet[2]
	a, n, err := protocol.ParseAddress(packet[3:])
	if err != nil {
		return protocol.Datagram{}, frag, err
	}
	return protocol.Datagram{Target: a, Payload: append([]byte(nil), packet[3+n:]...)}, frag, nil
}

func marshalUDPResponse(d protocol.Datagram) ([]byte, error) {
	body, err := appendSocksAddress([]byte{0, 0, 0}, d.Target, false)
	if err != nil {
		return nil, err
	}
	return append(body, d.Payload...), nil
}
