# Test and release gates

## Automated checks

Run before every release:

```sh
gofmt -w cmd internal
go test ./...
go vet ./...
go test -race ./...
go build ./...
cd ios && swift test
```

Current tests cover:

- Framing limits and short reads
- IPv4, IPv6, and domain address codecs
- Request, response, token, and datagram validation
- Authentication success and rejection
- Server destination policy
- SOCKS5 negotiation and address formats
- SOCKS5 UDP fragmentation rejection
- End-to-end TLS, TCP half-close, and UDP datagram boundaries
- UDP response endpoint allow-listing
- Strict JSON configuration
- Swift/Go protocol-compatible field layouts
- Ordered routing rules, domain suffix boundaries, IPv4/IPv6 CIDR, ports, and fallback

## v0.1 release gate

- All commands above exit successfully.
- No race detector findings.
- No known crash, deadlock, authentication bypass, frame-allocation bypass, or unintended private-network access.
- TCP and UDP local end-to-end tests pass repeatedly.

## iPad release gate, not yet executable here

A future installable build must additionally pass on a physical iPad:

- Packet Tunnel start and stop, repeated 100 times
- IPv4, IPv6, DNS A/AAAA, TCP DNS, and Fake IP lifecycle
- DIRECT, PROXY, and REJECT behavior
- TCP half-close, retransmission, large downloads, and at least 500 concurrent flows
- UDP DNS, HTTP/3, STUN, video calling, and idle expiration
- Wi-Fi to cellular transitions, sleep/wake, captive portal, and server restart
- 72-hour soak test with memory, CPU, battery, and reconnect measurements
- Imported China-domain and China-IP rules with signature, rollback, and stale-data behavior

No installable iPad build should be described as stable before these gates pass.
