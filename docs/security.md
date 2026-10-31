# Security model

## Protected assets

- Device authentication token
- TLS private key
- Proxied payload confidentiality and integrity
- Server-side private networks
- Client routing decisions

## Controls in v0.1

- TLS 1.3 only, standard certificate and hostname verification, fixed private ALPN.
- A random 256-bit token per device. The server stores SHA-256 token digests and compares them in constant time.
- Frame lengths are checked before allocation; protocol parsers reject malformed, truncated, oversized, or trailing data.
- The server denies loopback, private, link-local, multicast, and unspecified destinations by default, including addresses obtained from DNS.
- A UDP association accepts responses only from endpoints it previously contacted.
- The local SOCKS5 listener accepts only literal loopback bind addresses.
- Logs omit authentication tokens and application payloads.
- Services run as an unprivileged user with systemd hardening.

## Operational requirements

- Treat the client configuration as a secret because it contains the bearer token.
- Use file mode `0600` and never commit production configurations.
- Issue one token per device so one device can be revoked independently.
- Rotate certificates and tokens before expiration or after suspected exposure.
- Keep `allow_private_destinations` disabled in production.
- Restrict administrative access to the server separately from the proxy listener.

## Known limits

- A bearer token can be replayed if stolen. TLS protects it in transit but cannot protect a compromised endpoint.
- v0.1 UDP uses a TLS byte stream. It preserves message boundaries but inherits TCP head-of-line blocking.
- One server is a single point of failure.
- The iPad Packet Tunnel, lwIP adapter, DNS recovery, rule-package signature verification, and QUIC transport are not yet integrated.
- This project does not claim traffic impersonation or resistance to network classification.
