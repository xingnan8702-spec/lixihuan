package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/example/ipad-proxy/internal/protocol"
)

func (c *Client) openTunnel(parent context.Context, command protocol.Command, target *protocol.Address) (*tls.Conn, protocol.Response, error) {
	ctx, cancel := context.WithTimeout(parent, c.cfg.HandshakeTimeout)
	defer cancel()
	dialer := net.Dialer{Timeout: c.cfg.HandshakeTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", c.cfg.ServerAddress)
	if err != nil {
		return nil, protocol.Response{}, err
	}
	tunnel := tls.Client(raw, c.cfg.TLSConfig)
	if err := tunnel.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, protocol.Response{}, err
	}
	if tunnel.ConnectionState().NegotiatedProtocol != protocol.ALPN {
		tunnel.Close()
		return nil, protocol.Response{}, errors.New("server did not negotiate required ALPN")
	}
	request := protocol.AuthRequest{Command: command, Token: c.cfg.Token, Target: target}
	body, err := request.MarshalBinary()
	if err != nil {
		tunnel.Close()
		return nil, protocol.Response{}, err
	}
	_ = tunnel.SetDeadline(time.Now().Add(c.cfg.HandshakeTimeout))
	if err := protocol.WriteFrame(tunnel, body); err != nil {
		tunnel.Close()
		return nil, protocol.Response{}, err
	}
	body, err = protocol.ReadFrame(tunnel)
	if err != nil {
		tunnel.Close()
		return nil, protocol.Response{}, err
	}
	response, err := protocol.ParseResponse(body)
	if err != nil {
		tunnel.Close()
		return nil, protocol.Response{}, err
	}
	_ = tunnel.SetDeadline(time.Time{})
	return tunnel, response, nil
}
