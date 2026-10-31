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

## v0.2.2: managed flow and DNS core, ready for review

- Managed flow ownership across permit, Fake IP lease, transport, EOF, error, and close
- Registry-backed `closeAll()` for tunnel shutdown
- Fail-closed classification of unknown addresses inside Fake IP pools
- Action-preserving DIRECT/PROXY DNS upstream service
- Upstream response binding validation, timeout, inflight cap, and same-action TCP retry
- 101 passing Swift tests in debug and release

This version is published on its review branch. The Apple Packet Tunnel still needs a real user-space stack and adapters.

## v0.2.3: basic iPad app shell, local only

- SwiftUI iPad configuration and status UI
- Shared Keychain token storage and App Group non-secret configuration
- JSON rule file import with security-scoped access and size limits
- Reused `NETunnelProviderManager` profile with install/start/stop/status observation
- XcodeGen App and Packet Tunnel Extension targets, plists, and entitlements
- Fail-closed extension entry until the packet stack is integrated

## v0.2.5: local UDP and DNS integration, awaiting Apple validation

- Strict SOCKS5 UDP ASSOCIATE control and UDP datagram codecs
- Loopback UDP relay with 256 fixed-target sessions and 60-second idle expiry
- Separate literal-IP DIRECT and PROXY DNS upstream configuration
- Action-preserving DNS UDP/TCP transport adapters and Fake DNS interception
- HEV UDP mode and fail-closed Packet Tunnel composition
- Swift core tests complete; Xcode typecheck and physical-iPad validation remain release gates

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
