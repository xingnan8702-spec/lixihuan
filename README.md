# iPad Proxy

A personal, standards-based proxy prototype with a Go relay server, a local SOCKS5 client, and an iPad client architecture.

## v0.1 scope

- TLS 1.3 transport with normal certificate verification
- Per-device 256-bit token authentication
- SOCKS5 TCP CONNECT
- SOCKS5 UDP ASSOCIATE
- IPv4, IPv6, and domain-name targets
- Bounded frame parsing, deadlines, private-destination protection, and graceful shutdown
- Importable routing-rule format; no bundled routing data
- Swift core package and Packet Tunnel integration boundary

QUIC is intentionally deferred until Apple Network.framework interoperability can be tested on a real iPad. The v0.1 UDP path preserves datagram boundaries over TLS but inherits TCP head-of-line blocking.

## Repository layout

- `cmd/proxy-server`: relay server
- `cmd/proxy-client`: local SOCKS5 client
- `cmd/proxy-token`: token generator
- `internal/protocol`: authenticated tunnel wire format
- `internal/server`: TCP and UDP relay implementation
- `internal/client`: SOCKS5 frontend and tunnel client
- `rules`: import format and examples
- `ios`: Swift core and Packet Tunnel integration notes
- `deploy`: service and configuration examples
- `docs`: architecture, security, testing, and roadmap

## v0.2.1 status

The Go relay and local SOCKS5 client are runnable and covered by local TCP/UDP end-to-end tests. The relay now bounds total sessions, concurrent handshakes, UDP associations, and contacted UDP peers. The Swift core adds Fake IP flow leases with grace/quarantine, bounded byte queues, flow permits, and a platform-independent tunnel lifecycle controller.

Go and Swift both consume `testdata/protocol-v1.json`, so protocol changes must preserve the same exact golden wire bytes in both implementations. Apple-only templates still provide Network.framework TLS and DIRECT adapters, Keychain/App Group storage, and a fail-closed Packet Tunnel bridge.

The Packet Tunnel remains an integration template rather than an installable VPN because the repository does not yet contain a reviewed lwIP adapter, Xcode targets, entitlements, provisioning, or physical-iPad validation. See `docs/v0.2-design.md` and `docs/v0.2-acceptance.md` for the exact boundary.

See `docs/quickstart.md` for local Go setup and `docs/testing.md` for the verified release gates.

## Security scope

This project uses standard TLS and does not implement traffic impersonation, fingerprint spoofing, active-probe evasion, or custom cryptography.
