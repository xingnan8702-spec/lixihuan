package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"unicode/utf8"
)

const (
	Version        = 1
	ALPN           = "ipad-proxy/1"
	MaxFrameSize   = 65600
	MaxMessageSize = 512
	MaxUDPPayload  = 65507
	TokenSize      = 32
)

type Command byte

const (
	CommandTCPConnect   Command = 1
	CommandUDPAssociate Command = 2
)

type Status byte

const (
	StatusOK Status = iota
	StatusAuthFailed
	StatusBadRequest
	StatusDialFailed
	StatusForbidden
	StatusInternal
)

type AddressType byte

const (
	AddressIPv4   AddressType = 1
	AddressIPv6   AddressType = 2
	AddressDomain AddressType = 3
)

var (
	ErrInvalidFrame   = errors.New("invalid frame")
	ErrInvalidMessage = errors.New("invalid protocol message")
)

type Address struct {
	Type   AddressType
	IP     netip.Addr
	Domain string
	Port   uint16
}

func AddressFromHostPort(host string, port uint16) (Address, error) {
	if port == 0 {
		return Address{}, fmt.Errorf("%w: zero port", ErrInvalidMessage)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			return Address{Type: AddressIPv4, IP: ip, Port: port}, nil
		}
		return Address{Type: AddressIPv6, IP: ip, Port: port}, nil
	}
	if len(host) == 0 || len(host) > 253 || !utf8.ValidString(host) {
		return Address{}, fmt.Errorf("%w: invalid domain", ErrInvalidMessage)
	}
	return Address{Type: AddressDomain, Domain: host, Port: port}, nil
}

func (a Address) Host() string {
	if a.Type == AddressDomain {
		return a.Domain
	}
	return a.IP.String()
}

func (a Address) String() string { return net.JoinHostPort(a.Host(), fmt.Sprint(a.Port)) }

func (a Address) AppendTo(dst []byte) ([]byte, error) {
	if a.Port == 0 {
		return nil, fmt.Errorf("%w: zero port", ErrInvalidMessage)
	}
	dst = append(dst, byte(a.Type))
	switch a.Type {
	case AddressIPv4:
		ip := a.IP.Unmap()
		if !ip.IsValid() || !ip.Is4() {
			return nil, fmt.Errorf("%w: invalid IPv4", ErrInvalidMessage)
		}
		v := ip.As4()
		dst = append(dst, v[:]...)
	case AddressIPv6:
		if !a.IP.IsValid() || !a.IP.Is6() || a.IP.Is4In6() {
			return nil, fmt.Errorf("%w: invalid IPv6", ErrInvalidMessage)
		}
		v := a.IP.As16()
		dst = append(dst, v[:]...)
	case AddressDomain:
		if len(a.Domain) == 0 || len(a.Domain) > 253 || !utf8.ValidString(a.Domain) {
			return nil, fmt.Errorf("%w: invalid domain", ErrInvalidMessage)
		}
		dst = append(dst, byte(len(a.Domain)))
		dst = append(dst, a.Domain...)
	default:
		return nil, fmt.Errorf("%w: unknown address type", ErrInvalidMessage)
	}
	return binary.BigEndian.AppendUint16(dst, a.Port), nil
}

func ParseAddress(data []byte) (Address, int, error) {
	if len(data) < 1 {
		return Address{}, 0, io.ErrUnexpectedEOF
	}
	a := Address{Type: AddressType(data[0])}
	off := 1
	switch a.Type {
	case AddressIPv4:
		if len(data) < off+4+2 {
			return Address{}, 0, io.ErrUnexpectedEOF
		}
		var raw [4]byte
		copy(raw[:], data[off:off+4])
		a.IP = netip.AddrFrom4(raw)
		off += 4
	case AddressIPv6:
		if len(data) < off+16+2 {
			return Address{}, 0, io.ErrUnexpectedEOF
		}
		var raw [16]byte
		copy(raw[:], data[off:off+16])
		a.IP = netip.AddrFrom16(raw)
		off += 16
	case AddressDomain:
		if len(data) < off+1 {
			return Address{}, 0, io.ErrUnexpectedEOF
		}
		n := int(data[off])
		off++
		if n == 0 || n > 253 || len(data) < off+n+2 || !utf8.Valid(data[off:off+n]) {
			return Address{}, 0, fmt.Errorf("%w: invalid domain", ErrInvalidMessage)
		}
		a.Domain = string(data[off : off+n])
		off += n
	default:
		return Address{}, 0, fmt.Errorf("%w: unknown address type", ErrInvalidMessage)
	}
	a.Port = binary.BigEndian.Uint16(data[off : off+2])
	off += 2
	if a.Port == 0 {
		return Address{}, 0, fmt.Errorf("%w: zero port", ErrInvalidMessage)
	}
	return a, off, nil
}

func ReadFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxFrameSize {
		return nil, fmt.Errorf("%w: length %d", ErrInvalidFrame, n)
	}
	body := make([]byte, int(n))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

func WriteFrame(w io.Writer, body []byte) error {
	if len(body) == 0 || len(body) > MaxFrameSize {
		return fmt.Errorf("%w: length %d", ErrInvalidFrame, len(body))
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, body)
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

type AuthRequest struct {
	Command Command
	Token   [TokenSize]byte
	Target  *Address
}

func (r AuthRequest) MarshalBinary() ([]byte, error) {
	if r.Command != CommandTCPConnect && r.Command != CommandUDPAssociate {
		return nil, fmt.Errorf("%w: command", ErrInvalidMessage)
	}
	body := make([]byte, 0, 3+TokenSize+32)
	body = append(body, Version, byte(r.Command), TokenSize)
	body = append(body, r.Token[:]...)
	if r.Command == CommandTCPConnect {
		if r.Target == nil {
			return nil, fmt.Errorf("%w: missing target", ErrInvalidMessage)
		}
		return r.Target.AppendTo(body)
	}
	if r.Target != nil {
		return nil, fmt.Errorf("%w: UDP target is trailing data", ErrInvalidMessage)
	}
	return body, nil
}

func ParseAuthRequest(body []byte) (AuthRequest, error) {
	if len(body) < 3+TokenSize || body[0] != Version || body[2] != TokenSize {
		return AuthRequest{}, ErrInvalidMessage
	}
	r := AuthRequest{Command: Command(body[1])}
	copy(r.Token[:], body[3:3+TokenSize])
	rest := body[3+TokenSize:]
	switch r.Command {
	case CommandTCPConnect:
		a, n, err := ParseAddress(rest)
		if err != nil || n != len(rest) {
			return AuthRequest{}, ErrInvalidMessage
		}
		r.Target = &a
	case CommandUDPAssociate:
		if len(rest) != 0 {
			return AuthRequest{}, ErrInvalidMessage
		}
	default:
		return AuthRequest{}, ErrInvalidMessage
	}
	return r, nil
}

type Response struct {
	Status  Status
	Message string
}

func (r Response) MarshalBinary() ([]byte, error) {
	if r.Status > StatusInternal || len(r.Message) > MaxMessageSize || !utf8.ValidString(r.Message) {
		return nil, ErrInvalidMessage
	}
	body := []byte{Version, byte(r.Status), 0, 0}
	binary.BigEndian.PutUint16(body[2:4], uint16(len(r.Message)))
	return append(body, r.Message...), nil
}

func ParseResponse(body []byte) (Response, error) {
	if len(body) < 4 || body[0] != Version || Status(body[1]) > StatusInternal {
		return Response{}, ErrInvalidMessage
	}
	n := int(binary.BigEndian.Uint16(body[2:4]))
	if n > MaxMessageSize || len(body) != 4+n || !utf8.Valid(body[4:]) {
		return Response{}, ErrInvalidMessage
	}
	return Response{Status: Status(body[1]), Message: string(body[4:])}, nil
}

type Datagram struct {
	Target  Address
	Payload []byte
}

func (d Datagram) MarshalBinary() ([]byte, error) {
	if len(d.Payload) > MaxUDPPayload {
		return nil, ErrInvalidMessage
	}
	body, err := d.Target.AppendTo([]byte{Version})
	if err != nil {
		return nil, err
	}
	if len(body)+len(d.Payload) > MaxFrameSize {
		return nil, ErrInvalidFrame
	}
	return append(body, d.Payload...), nil
}

func ParseDatagram(body []byte) (Datagram, error) {
	if len(body) < 1 || body[0] != Version {
		return Datagram{}, ErrInvalidMessage
	}
	a, n, err := ParseAddress(body[1:])
	if err != nil {
		return Datagram{}, err
	}
	payload := body[1+n:]
	if len(payload) > MaxUDPPayload {
		return Datagram{}, ErrInvalidMessage
	}
	return Datagram{Target: a, Payload: bytes.Clone(payload)}, nil
}
