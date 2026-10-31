# Roadmap

## v0.1: protocol baseline, delivered

- Go TLS relay server
- Go local SOCKS5 client
- TCP CONNECT and UDP ASSOCIATE
- IPv4, IPv6, and domain targets
- Token generation and authentication
- Importable rule schema
- Swift protocol and rule core
- Packet Tunnel fail-closed integration template

## v0.2: iPad packet data path, in progress

- Xcode containing app and Packet Tunnel targets
- Keychain and App Group configuration storage
- Reviewed lwIP adapter with bounded buffers
- DIRECT connector using Network.framework
- TLS PROXY connector matching protocol v1
- DNS proxy, Fake IP allocator, TTL cache, A/AAAA and TCP DNS
- Imported rule package storage and atomic activation
- Tunnel status and diagnostic UI

## v0.2.1: stability core, delivered

- Fake IP flow lease, correlation grace, and reuse quarantine
- Bounded item/byte queues and flow admission permits
- Platform-independent tunnel lifecycle controller
- Go total-session, handshake, and UDP-association limits
- Joined UDP shutdown and aggregate server metrics
- Shared Go/Swift protocol-v1 golden fixtures

## v0.3: high-performance UDP

- Swift Network.framework to Go QUIC interoperability spike
- One QUIC stream per proxied TCP flow
- QUIC Datagram compatibility and path-MTU gate
- UDP-over-TLS fallback policy
- Network transition and reconnection state machine

QUIC is promoted from experimental only after stream, datagram, MTU, loss, sleep/wake, and network-switch tests pass on the target iPadOS versions.

## v0.4: rule distribution and operational hardening

- Signed China-domain and IPv4/IPv6 rule packages
- Background update, atomic rollback, and stale-data handling
- Metrics without destination or payload logging
- Server package, upgrade, backup, and certificate renewal automation
- 72-hour soak and load-test release gate

## Explicit exclusions

- Browser fingerprint impersonation
- Active-probe evasion
- Custom cryptography
- MITM or HTTPS decryption
- Per-application routing without supported platform metadata
