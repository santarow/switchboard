# Switchboard

Connects a phone to a computer that has no public address. Both connect out to Switchboard; it
relays sealed messages between paired keys and never holds a key that can open them.

```
  phone                       Switchboard                       Mac
 ┌───────┐  sealed box  ┌─────────────────────┐  sealed box  ┌───────┐
 │ keys  │ ───────────▶ │ reads only "to/from"│ ───────────▶ │ keys  │
 │       │ ◀─────────── │ can't open the box  │ ◀─────────── │       │
 └───────┘   outbound   └─────────────────────┘   outbound   └───────┘
             WebSocket     no disk, no keys       WebSocket
```

## Why Switchboard

- **No VPN, no open ports.** The computer stays behind its router; both ends dial out over HTTPS.
  Works behind a Cloudflare Tunnel, on a small VPS, or anywhere that runs one binary.
- **The relay can't read your messages.** Every message is sealed in the apps with X25519 +
  ChaCha20-Poly1305 (Apple CryptoKit has all of it). Switchboard only routes by public key.
- **Not an open relay.** The computer tells Switchboard which phones may reach it; pairing uses a
  one-time code from a QR.
- **Nothing to run beside it.** One Go binary, one dependency, no database, nothing on disk.

## Docs

- Writing a client or working on the code: [AGENTS.md](AGENTS.md)
- Wire protocol: [docs/protocol.md](docs/protocol.md), with [test vectors](docs/test-vectors.json)
- Design and choices: [docs/design.md](docs/design.md)
- Security: [SECURITY.md](SECURITY.md) and [docs/security-review.md](docs/security-review.md)

## Run

```bash
go build -o switchboard . && ./switchboard -addr 127.0.0.1:8790 -stun stun:stun.cloudflare.com:3478
```

`-stun` is the STUN server clients use to try a direct call first; Switchboard passes it on and needs
no UDP itself. `-host` pins the host name logins are signed for; set it in production.

`GET /healthz` answers `{"ok":true}`. Clients connect to `GET /v1/connect` (WebSocket). Put it behind
TLS (for example a Cloudflare Tunnel pointed at the address above).

Linux: `GOOS=linux GOARCH=amd64 go build -o switchboard-linux .`

## Test

```bash
go test -race ./...
```

Client side, with Python's `cryptography` and `websockets`:

```bash
python3 -m venv testkit/.venv && testkit/.venv/bin/pip install cryptography websockets
testkit/.venv/bin/python testkit/vectors.py      # test vectors still match the reference client
testkit/.venv/bin/python testkit/echo_peer.py    # a stand-in computer to test your client against
```

See [AGENTS.md](AGENTS.md#check-your-client).

## Third-party

| name | license | used for |
|---|---|---|
| Go standard library | BSD-3-Clause | HTTP, Ed25519 |
| [github.com/coder/websocket](https://github.com/coder/websocket) | ISC | WebSocket server |
| [cryptography](https://cryptography.io) (tests only) | Apache-2.0 OR BSD-3-Clause | test clients: X25519, HKDF, ChaCha20-Poly1305 |
| [websockets](https://websockets.readthedocs.io) (tests only) | BSD-3-Clause | test clients |

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
