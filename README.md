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

## v0.2.5 local UDP and DNS integration

The local v0.2.5 recovery adds strict SOCKS5 UDP ASSOCIATE and UDP datagram codecs, a loopback UDP relay with 256 fixed-target sessions and 60-second idle expiry, action-preserving DIRECT/PROXY DNS upstream adapters, Fake DNS UDP/TCP interception, and separate literal-IP DNS settings (`223.5.5.5` for DIRECT and `1.1.1.1` for PROXY by default). Legacy v0.2.4.1 provider JSON receives only those two defaults; unknown fields still fail closed.

HEV now uses `udp: 'udp'`, and the extension installs the Fake DNS settings only after constructing both resolvers, `DNSProxyService`, the UDP relay, and the SOCKS bridge. Resolver, routing, and transport errors never switch DIRECT/PROXY action. Linux Swift debug/release tests and syntax/config parsing are local evidence only. Apple target typechecking/linking, Tun2SocksKit 5.16.0 behavior, utun startup, UDP path MTU, DNS interception, stop cancellation, and memory bounds still require Xcode and a physical iPad before release. See `docs/v0.2.5-status.md` and `THIRD_PARTY_NOTICES.md`.

## v0.2.3 local app shell

The current local branch adds an iPad-only SwiftUI containing app, secure relay/token configuration, JSON rule import, `NETunnelProviderManager` lifecycle control, App Group/Keychain sharing, Packet Tunnel target metadata, entitlements, and an XcodeGen project description. The extension intentionally remains fail closed until a reviewed packet stack and local SOCKS bridge are integrated.

These v0.2.3 changes have not been pushed.

## v0.2.2 status

The `feature/ipad-proxy-v0.2.2-local` branch adds managed TCP/UDP flow ownership, a registry-backed `closeAll()`, fail-closed Fake IP restoration, and an action-preserving DNS upstream service with response validation, timeout, inflight limits, and same-route TCP retry. Swift debug and release suites contain 101 passing tests.

The branch name retains its local-development suffix for history, but this version is now ready for review through GitHub.

## v0.2.1 status

The Go relay and local SOCKS5 client are runnable and covered by local TCP/UDP end-to-end tests. The relay now bounds total sessions, concurrent handshakes, UDP associations, and contacted UDP peers. The Swift core adds Fake IP flow leases with grace/quarantine, bounded byte queues, flow permits, and a platform-independent tunnel lifecycle controller.

Go and Swift both consume `testdata/protocol-v1.json`, so protocol changes must preserve the same exact golden wire bytes in both implementations. Apple-only templates still provide Network.framework TLS and DIRECT adapters, Keychain/App Group storage, and a fail-closed Packet Tunnel bridge.

The Packet Tunnel remains an integration template rather than an installable VPN because the repository does not yet contain a reviewed lwIP adapter, Xcode targets, entitlements, provisioning, or physical-iPad validation. See `docs/v0.2-design.md` and `docs/v0.2-acceptance.md` for the exact boundary.

See `docs/quickstart.md` for local Go setup and `docs/testing.md` for the verified release gates.

## Security scope

This project uses standard TLS and does not implement traffic impersonation, fingerprint spoofing, active-probe evasion, or custom cryptography.
