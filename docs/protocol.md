# Tunnel protocol v1

## Transport

The v1 transport is TLS 1.3 over TCP with ALPN `ipad-proxy/1`. The client performs normal hostname and certificate validation. Every proxied TCP flow uses a separate TLS connection. Every SOCKS5 UDP association uses one TLS connection carrying length-delimited datagram records.

All integers use network byte order. Every protocol message is prefixed by an unsigned 32-bit body length. A receiver rejects zero-length bodies, bodies above 65,600 bytes, unknown versions, unknown commands, malformed addresses, and trailing fields where none are allowed.

## Authentication request

The first frame sent by the client is:

```text
version       u8 = 1
command       u8: 1 TCP_CONNECT, 2 UDP_ASSOCIATE
token_length  u8 = 32
token         32 bytes
[target]      Address, required only for TCP_CONNECT
```

`Address` is:

```text
address_type  u8: 1 IPv4, 2 IPv6, 3 domain
address       4 bytes, 16 bytes, or u8 length + UTF-8 domain
port          u16
```

Domains are 1 through 253 bytes. Ports must be non-zero for TCP requests and UDP datagrams.

## Response

```text
version       u8 = 1
status        u8: 0 OK, 1 AUTH_FAILED, 2 BAD_REQUEST,
                  3 DIAL_FAILED, 4 FORBIDDEN, 5 INTERNAL
message_len   u16
message       UTF-8, at most 512 bytes
```

Messages must not contain secrets or detailed internal network information.

## UDP datagram

After a successful UDP association response, each direction exchanges framed datagrams:

```text
version       u8 = 1
target        Address
payload       remaining frame bytes, at most 65,507 bytes
```

Datagram boundaries are preserved. SOCKS5 fragmentation is not supported; packets with a non-zero FRAG field are dropped. Idle UDP associations expire.

## Lifecycle

- Handshake reads and target dialing have deadlines.
- A successful TCP response is followed by bidirectional byte relay.
- TCP half-close is propagated where supported.
- Closing the UDP association TLS connection releases all associated sockets.
- Invalid, oversized, or unauthenticated input closes the connection.

## Future QUIC mapping

The control request maps to the first bytes of each QUIC bidirectional stream. A TCP target maps one-to-one to a QUIC stream. UDP maps to QUIC Datagram only after iPad interoperability and path-MTU behavior pass the compatibility gate. Version 1 does not advertise QUIC support.

## Shared compatibility fixture

`testdata/protocol-v1.json` is the single golden-wire source consumed by both `internal/protocol/fixture_test.go` and `ios/Tests/IPadProxyCoreTests/SharedProtocolFixtureTests.swift`. Any intentional wire-format change must update the protocol version and both decoders; changing only one implementation must fail CI/local tests.