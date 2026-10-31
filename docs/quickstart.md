# Local quick start

This procedure verifies the Go relay and SOCKS5 client on one development machine. It deliberately enables private destinations so the integration test can reach local echo or web services. Never carry that setting into a public deployment unless access to private server-side networks is intentional.

## 1. Build

```sh
make check
make build
```

The binaries are written to `bin/`.

## 2. Generate a device token

```sh
./bin/proxy-token
```

The command prints:

```text
token=<64 hexadecimal characters>
sha256=<64 hexadecimal characters>
```

Put `token` only in the client configuration. Put `sha256` only in the server configuration. Do not commit either value.

## 3. Create a development certificate

```sh
mkdir -p .local
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout .local/server.key \
  -out .local/server.crt \
  -days 7 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 .local/server.key
```

Use a publicly trusted certificate for production.

## 4. Create local configurations

Create `.local/server.json` from `configs/server.example.json` with:

```json
{
  "listen": "127.0.0.1:8443",
  "certificate_file": ".local/server.crt",
  "private_key_file": ".local/server.key",
  "token_sha256": ["REPLACE_WITH_SHA256"],
  "allow_private_destinations": true,
  "handshake_timeout": "10s",
  "dial_timeout": "10s",
  "io_timeout": "5m",
  "udp_idle_timeout": "2m",
  "shutdown_timeout": "10s"
}
```

Create `.local/client.json` with:

```json
{
  "listen": "127.0.0.1:1080",
  "server_address": "127.0.0.1:8443",
  "server_name": "localhost",
  "root_ca_file": ".local/server.crt",
  "token": "REPLACE_WITH_TOKEN",
  "handshake_timeout": "10s",
  "io_timeout": "5m",
  "udp_idle_timeout": "2m",
  "shutdown_timeout": "10s"
}
```

Protect both files:

```sh
chmod 600 .local/server.json .local/client.json
```

## 5. Run

In separate terminals:

```sh
./bin/proxy-server -config .local/server.json
./bin/proxy-client -config .local/client.json
```

Verify TCP through SOCKS5:

```sh
curl --proxy socks5h://127.0.0.1:1080 https://example.com/
```

Run the automated TCP and UDP end-to-end checks with:

```sh
go test ./internal/client -run TestLocalEndToEndTCPAndUDP -v
```

## Production differences

- Use a real domain and publicly trusted TLS certificate.
- Listen on the intended public address and firewall TCP access.
- Keep `allow_private_destinations` set to `false`.
- Run under the supplied systemd unit and dedicated unprivileged account.
- Keep configuration and private keys readable only by that account.
- Rotate tokens by temporarily configuring old and new hashes, updating the client, then removing the old hash.
