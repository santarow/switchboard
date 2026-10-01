# Switchboard

Connects a phone to a computer that has no public address. Both connect out to Switchboard; it
relays sealed messages between paired keys and never holds a key that can open them.

- Design and choices: [docs/design.md](docs/design.md)
- Wire protocol (what clients implement): [docs/protocol.md](docs/protocol.md)

## Run

```bash
go build -o switchboard . && ./switchboard -addr 127.0.0.1:8790 -stun stun:stun.cloudflare.com:3478
```

`-stun` is the STUN server clients use to try a direct call first; Switchboard passes it on and needs
no UDP itself.

`GET /healthz` answers `{"ok":true}`. Clients connect to `GET /v1/connect` (WebSocket). Put it behind
TLS (for example a Cloudflare Tunnel pointed at the address above).

Linux: `GOOS=linux GOARCH=amd64 go build -o switchboard-linux .`

## Test

```bash
go test -race ./...
```

End to end on localhost, with Buddy's `scripts/mock_workshop.py` as the computer:

```bash
python3 -m venv testkit/.venv && testkit/.venv/bin/pip install cryptography websockets
testkit/.venv/bin/python testkit/e2e.py
```

## Third-party

| name | license | used for |
|---|---|---|
| Go standard library | BSD-3-Clause | HTTP, Ed25519 |
| [github.com/coder/websocket](https://github.com/coder/websocket) | ISC | WebSocket server |
| [cryptography](https://cryptography.io) (tests only) | Apache-2.0 OR BSD-3-Clause | test clients: X25519, HKDF, ChaCha20-Poly1305 |
| [websockets](https://websockets.readthedocs.io) (tests only) | BSD-3-Clause | test clients |

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
