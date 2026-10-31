# Architecture

## Priorities

1. Correctness and predictable failure
2. Stable operation
3. Throughput and latency
4. Feature count
5. Degree of custom implementation

## Data path

```text
Application
  -> iPad Packet Tunnel
  -> user-space TCP/IP stack
  -> DNS/domain recovery
  -> imported rule engine
  -> DIRECT or PROXY decision
  -> transport backend
  -> Go relay
  -> destination
```

The v0.1 runnable data path begins at a local SOCKS5 listener. This isolates and validates protocol, authentication, TCP relay, and UDP relay before adding Packet Tunnel and lwIP.

## Boundaries

- `protocol` owns serialization, bounds, versions, and statuses.
- `client` owns SOCKS5 and outbound TLS connections.
- `server` owns authentication, target policy, dialing, and relay.
- `rules` is data-driven and ships without geographic data.
- `transport` will abstract TLS and future QUIC implementations.
- The iPad extension owns packet processing and must not contain UI logic.

## Reliability rules

- No unbounded queues or frame allocations.
- Every network operation has a deadline or cancellation path.
- One blocked flow cannot block unrelated TCP flows.
- UDP associations have idle expiration.
- Logs omit tokens and payloads.
- Private, loopback, link-local, multicast, and unspecified server-side destinations are denied by default.
- Configuration errors fail startup rather than weakening security.

## Single-node limitation

The client can reconnect and switch between UDP/QUIC and TCP/TLS transports in a future version, but one VPS remains a single point of failure. Client correctness cannot provide availability while that host or route is unavailable.
