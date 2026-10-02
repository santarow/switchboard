# AGENTS.md

Notes for coding agents (and people) working on Switchboard or writing a client for it.

## What it is

Switchboard lets a phone reach a computer that has no public address. Both connect **out** to it
over one WebSocket, log in with an Ed25519 key, and it forwards sealed frames between keys that the
computer allows. Everything is sealed end to end in the apps, so Switchboard can't read anything.

## Commands

```bash
go build -o switchboard .                       # one static binary
./switchboard -addr 127.0.0.1:8790 -stun stun:stun.cloudflare.com:3478
curl -s 127.0.0.1:8790/healthz                  # {"ok":true,"version":"dev"}
go test -race ./...                             # relay tests
GOOS=linux GOARCH=amd64 go build -o switchboard-linux .

python3 -m venv testkit/.venv && testkit/.venv/bin/pip install cryptography websockets
testkit/.venv/bin/python testkit/vectors.py     # docs/test-vectors.json still matches the client
testkit/.venv/bin/python testkit/echo_peer.py --switchboard http://127.0.0.1:8790   # a Mac to test against
```

Flags: `-addr` (listen address), `-stun` (STUN servers handed to clients, comma separated), `-host`
(the public host name logins must be signed for; set it whenever the relay is reachable other than
through a proxy that routes by host name).

## Repo map

| path | what |
|---|---|
| `main.go` | flags, HTTP server, `/healthz`, `/v1/connect` |
| `relay/relay.go` | the whole relay: login, policy, routing, queues, rate limit |
| `relay/relay_test.go` | relay tests (`go test -race ./...`) |
| `docs/protocol.md` | **the wire format. Read this before writing a client** |
| `docs/design.md` | why it is built this way, alternatives considered |
| `docs/test-vectors.json` | fixed keys and nonces with the expected login, ticket, keys and box |
| `docs/security-review.md` | threat model check of the relay, known limits |
| `testkit/sb.py` | reference client in Python: keys, login, sealing, frames |
| `testkit/echo_peer.py` | stand-in Mac that pairs and echoes, for testing a client |
| `testkit/vectors.py` | writes and checks `docs/test-vectors.json` |
| `testkit/e2e.py`, `testkit/mac_bridge.py` | end-to-end test with the SantaRow apps' mock server (not in this repo) |

## The protocol in ten lines

Full detail: [docs/protocol.md](docs/protocol.md). All keys and ids are base64url without padding.

1. Each device has an Ed25519 **identity** key (its address, `id`) and an X25519 **box** key (`key`).
2. The Mac shows a QR with its `url`, `mac_id`, `mac_key` and a one-time pairing `code`.
3. Connect to `wss://<host>/v1/connect`; get `{"t":"challenge","nonce":…}`.
4. Sign `"switchboard-v1 login\n" + host + "\n" + nonce` and send `{"t":"login","id":…,"sig":…}`.
5. Get `{"t":"ready","id":…,"ice":[…]}`, then send your policy `{"t":"policy","allow":[…],"tickets":[…]}`.
6. Every message is binary frames: 2-byte header length, JSON header (`to`, `id`, `seq`, `last`), slice of the box.
7. Box: X25519 → HKDF-SHA256 (salt `from ‖ to`, info `"switchboard-v1 envelope"`) → ChaCha20-Poly1305,
   additional data `to ‖ from ‖ id`, sent as `nonce ‖ ciphertext ‖ tag`.
8. Pairing: the first request carries `key` (your box key) and `ticket` (SHA-256 hex of the code) in the header.
9. Switchboard sets `from`; it answers `{"t":"error","re":id,"error":…}` when it can't deliver.
10. Inside the box: `[4-byte head length][head JSON][body]`, an HTTP-shaped `req` or `res`.

## Implement a client, step by step

1. **Keys.** Make an Ed25519 key and an X25519 key once per install; keep them in the Keychain (or
   the platform's equivalent), device only. In CryptoKit: `Curve25519.Signing.PrivateKey` and
   `Curve25519.KeyAgreement.PrivateKey`.
2. **Login.** Open the WebSocket. `host` is the URL's host with its port if it has one. Sign the login
   bytes from step 4 above with the identity key. A wrong signature closes the socket with 1008.
3. **Policy.** Right after `ready`: a phone sends `allow: [mac_id]`; a Mac sends its paired phones'
   ids and a ticket per live pairing code. Re-send the whole policy whenever it changes and after
   every reconnect. Switchboard remembers nothing.
4. **Seal.** Use a fresh random 16-byte `id` and a fresh random 12-byte nonce per message. Derive
   the key with salt `sender_id ‖ recipient_id`; to open, the salt is still `from ‖ to` from the
   header. Drop any `id` you have already opened.
5. **Frame.** Cut the box into slices of at most 256 KB, same `id`, `seq` from 0, `last` on the
   final one. Reassemble by `(from, id)` and open when `last` arrives.
6. **Pair.** Send the pairing request with `key` and `ticket` in the header. The Mac opens it with
   that `key`, checks the code, stores the phone's id and key, adds it to `allow`, then answers.
7. **Errors.**
   - `offline`: the Mac isn't connected. Try the next route if the app has one.
   - `not_allowed`: this Switchboard won't carry you to that Mac right now. Try the next route and
     **keep the pairing**. Only the Mac itself, inside a sealed answer, can say you are unpaired.
   - `slow`, `rate_limited`: treat as no answer. `too_big`, `bad_frame`: a bug on your side.
8. **Stay up.** Switchboard pings every 30 s. On a drop: reconnect, log in, re-send the policy. A
   newer login with the same key replaces the older connection.
9. **Live audio (optional).** WebRTC signaling goes as sealed `{"t":"call",…}` messages; if direct
   fails, 20 ms frames go as sealed `{"t":"media",…}` messages with `lossy: true` (16 KB max).

## Check your client

1. **Test vectors.** [docs/test-vectors.json](docs/test-vectors.json) gives fixed private keys,
   nonces and ids, and the expected public keys, login bytes, login signature, ticket, both envelope
   keys, and a sealed box. Reproduce every output. Ed25519 in CryptoKit signs with randomness, so
   check `login_sig` by verifying it, not by comparing bytes; everything else must match exactly.
   The vectors have been checked against Apple CryptoKit.
2. **Against a live relay.** Run `./switchboard -addr 127.0.0.1:8790`, then
   `testkit/echo_peer.py`. It prints a route and a code. Pair with them from your client, then send
   requests; each body comes back sealed. Try an unpaired request first: it must get `not_allowed`.

## Self-host

1. Build: `go build -o switchboard .` (or the Linux build above). Nothing else to install.
2. Keep it on `127.0.0.1` and put TLS in front. The simplest is a Cloudflare Tunnel:
   `cloudflared tunnel --url http://127.0.0.1:8790` for a quick test, or a named tunnel with a
   `switchboard.example.com` hostname for a fixed address. Pass `-host switchboard.example.com`.
3. Run it as a service.

macOS, `~/Library/LaunchAgents/com.example.switchboard.plist`, then
`launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.example.switchboard.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.example.switchboard</string>
  <key>ProgramArguments</key><array>
    <string>/usr/local/bin/switchboard</string>
    <string>-addr</string><string>127.0.0.1:8790</string>
    <string>-host</string><string>switchboard.example.com</string>
    <string>-stun</string><string>stun:stun.cloudflare.com:3478</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
```

Linux, `/etc/systemd/system/switchboard.service`, then `systemctl enable --now switchboard`:

```ini
[Unit]
Description=Switchboard relay
After=network-online.target

[Service]
ExecStart=/usr/local/bin/switchboard -addr 127.0.0.1:8790 -host switchboard.example.com -stun stun:stun.cloudflare.com:3478
DynamicUser=yes
Restart=always

[Install]
WantedBy=multi-user.target
```

A Cloudflare Tunnel carries no UDP, so behind one, live audio falls back to the WebSocket. That is
expected.

## Rules that must not change

- **Never log** envelope contents, tickets, tokens, or full keys. Logs carry connects, disconnects,
  errors and the first 8 characters of a key, nothing more.
- **Nothing on disk.** No database, no queue, no files. A restart loses nothing; clients re-send
  their policy.
- **No server-side keys** that can open a message. All sealing happens in the clients.
- **The relay sets `from`** and strips `ticket`. A client can never choose who a frame claims to be from.
- **Not an open relay.** A frame reaches a device only if that device allowed the sender, or the
  frame carries a live ticket it registered, or it recently sent the sender a ticketed frame.
- Dependencies stay permissive (MIT, BSD, ISC, Apache-2.0). No GPL, AGPL or LGPL.
- `docs/protocol.md` is the contract. Change it first, then the code, then `docs/test-vectors.json`.

## Style

Plain words in docs and comments, short sentences. Go standard library first. Keep the relay small
enough to read in one sitting.
