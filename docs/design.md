# Switchboard design

Switchboard is a message relay. A phone and a computer both connect **out** to it, and it connects
them. It forwards sealed envelopes and never sees plaintext. The exact wire format is
[protocol.md](protocol.md), which wins where the two differ.

It was built for SantaRow, where an iPhone app (Buddy) talks to a Mac app (Workshop) without a VPN.
Nothing in the relay is specific to those apps.

## Decision in one table

| question | answer | why |
|---|---|---|
| Language | **Go** | one static binary for macOS and Linux (`GOOS=linux go build`), and the whole field below is Go, so TURN can be embedded later in the same binary |
| Message relay | **write our own**, about 350 lines | the job is "two known keys, forward opaque frames". That is small enough to own outright |
| Transport | **one WebSocket over HTTPS** | the only thing a Cloudflare Tunnel carries besides plain HTTP. Same path works at home and on a VPS |
| Encryption | **end to end in the apps**: X25519 + HKDF-SHA256 + ChaCha20-Poly1305, Ed25519 to log in | all four are in Apple CryptoKit. The server holds no key that can open a message |
| Call media | **WebRTC direct**, fallback by where Switchboard runs (below) | Cloudflare Tunnel cannot carry UDP, so TURN cannot live behind it |
| State | **none on disk** | the Mac re-sends who may reach it each time it connects. A restart loses nothing |

## The candidates

| candidate | license | what it is | fit | verdict |
|---|---|---|---|---|
| LiveKit server v1.13.7 (Sep 2026) | Apache-2.0 | WebRTC SFU: rooms, many participants, Go on Pion | built for group rooms. Needs UDP ports or TCP 7881 open, which a Tunnel can't give. The SFU sees media unless its E2EE is turned on. Messages and pairing are out of scope | **not now.** Revisit only for group calls |
| coturn | BSD-3-Clause | TURN/STUN server, C, its own daemon | does TURN well, but it is a second process, and TURN is UDP | **no.** pion/turn does the same inside our binary |
| pion/turn v5.1.1 (Sep 2026) | MIT | TURN/STUN as a Go library | embeddable, same binary | **yes, later**, only where UDP is reachable (VPS) |
| NATS | Apache-2.0 | pub/sub broker, Go | a full broker with its own auth model, a second process, and clustering we don't need | **no.** Too much for forwarding between paired keys |
| Centrifugo v6 | Apache-2.0 (PRO is commercial) | real-time pub/sub over WebSocket, Go | channels plus JWT auth; fine, but the auth and channel model fight "route by public key" | **no** |
| Headscale + DERP | BSD-3-Clause both | self-hosted Tailscale control server; DERP = Tailscale's encrypted relay | Headscale means every phone runs a VPN, which is what Switchboard exists to avoid. DERP is the right **shape** (route by public key, relay sees only ciphertext) but its wire format is Tailscale's | **borrow DERP's design, not its code** |
| coder/websocket | ISC | Go WebSocket library, zero dependencies | the one piece Go's standard library lacks | **yes** |

Hosted options (LiveKit Cloud, Cloudflare Realtime for TURN) stay open for a hosted service later.
Nothing here is AGPL, GPL or LGPL.

## Why Go, not Swift

| | Go | Swift |
|---|---|---|
| One binary, Mac and Linux | yes, cross-compile from the Mac | Linux needs the static Linux SDK; works, more moving parts |
| WebRTC / TURN libraries | Pion (MIT), mature, used by LiveKit | thin; no server-side TURN |
| Sharing code with the apps | no | yes, but the server does **no crypto** (end to end), so there is little to share |
| Boring server tech | standard library `net/http`, TLS, context | Vapor or Hummingbird on top |

The deciding point: the server forwards bytes. The apps do the crypto in CryptoKit either way.

## How it works

### Who is who

- Every device has two keys made on the device, kept in its Keychain:
  - **Ed25519 identity key.** Its public key is the device's address on Switchboard.
  - **X25519 key** for sealing envelopes.
- The Mac's two public keys go in the QR (`mac_id`, `mac_key`), so the phone never learns them from
  Switchboard. Switchboard can't swap them.

### Connecting

1. Device opens `wss://<switchboard>/v1/connect`.
2. Switchboard sends a random 32-byte challenge.
3. Device answers with its Ed25519 public key and its signature over the challenge plus the host name.
4. Switchboard checks the signature. That key is now online. No accounts, no passwords.

### Who may send to a Mac

Switchboard must not be an open relay to the Mac. After logging in, the Mac sends:

- `allow`: the identity keys of its paired phones.
- `ticket`: SHA-256 of each live pairing code from a QR on screen, with its expiry.

A phone may send to a Mac only if it is in that Mac's `allow` list, or its message carries a ticket
the Mac registered (pairing). Everything is in memory; the Mac re-sends both lists on every connect.

### Pairing over Switchboard

1. Phone scans the QR: it holds a broker route with `url`, `mac_id`, `mac_key`, and a one-time code.
2. Phone connects with its own identity key, then sends a pairing request sealed to `mac_key`,
   tagged with the ticket. Inside the envelope: the code and the phone's own two public keys.
3. The Mac checks the code, answers, and adds the phone's identity key to `allow`.

### Envelopes

```
outer (Switchboard reads):  {"to": "<identity key>", "from": "<identity key>", "id": "<16 random bytes>",
                             "ticket": "<optional>", "box": "<base64 ciphertext>"}
inner (only the two ends):  {"t": "req", "method": "POST", "path": "/notes", "headers": {…}} + body bytes
```

- Seal: X25519(sender, recipient) → HKDF-SHA256 (salt = both identity keys) → ChaCha20-Poly1305,
  random 12-byte nonce, `to`+`from`+`id` as additional data so Switchboard can't re-address a box.
- The inner message can be an HTTP-shaped request and answer, so an app's existing endpoints work
  unchanged. A bearer token rides inside.
- Bodies above 256 KB go as numbered frames (a recorded voice turn can be MBs).
- Offline recipient: `{"error": "offline"}` right away. Switchboard queues nothing.

Known gap: static-static keys mean no forward secrecy. A later version can add an ephemeral handshake
(Noise IK pattern) without changing Switchboard, which never sees inside.

### Calls

Calls made of whole recorded turns are ordinary requests and need nothing extra. Live audio adds:

1. **Signaling:** SDP offer and answer and ICE candidates travel as envelopes. Sealed, so the DTLS
   fingerprints can't be swapped by Switchboard.
2. **Direct:** WebRTC peer to peer. Switchboard tells clients which STUN server to use (`-stun`).
3. **Fallback:**

| where Switchboard runs | fallback when direct fails |
|---|---|
| behind a Cloudflare Tunnel | audio frames as sealed envelopes on the same WebSocket. TCP, a little more delay, works everywhere the Tunnel does |
| VPS or hosted, UDP open | pion/turn embedded, short-lived credentials minted per call (not built yet) |

Apps need a WebRTC library for the direct path (Google's libwebrtc, BSD-3-Clause).

### Running it

| | |
|---|---|
| Binary | `switchboard`, darwin/arm64 and linux/amd64 |
| Listens | `127.0.0.1:8790` by default; a TLS proxy or `cloudflared` points a hostname at it |
| Keepalive | ping every 30 s (Cloudflare drops idle sockets around 100 s) |
| Logs | connects, disconnects, errors, and the first 8 characters of a key. **Never** envelope contents, tickets or full keys |
| Limits | 2 KB header and 256 KB per frame, 16 KB per live audio frame, 400 frames per second per connection |

## Testing

`go test -race ./...` covers the relay. End to end, `testkit/e2e.py` runs the SantaRow apps' mock
server behind `testkit/mac_bridge.py` and a test phone. `testkit/echo_peer.py` is a stand-in Mac for
testing any client. Python's standard library has no X25519 or ChaCha20-Poly1305, so the test side
needs `cryptography` and `websockets` in a venv.

## Third-party

| name | license | why |
|---|---|---|
| Go toolchain and standard library | BSD-3-Clause | language, HTTP, TLS, Ed25519 verify |
| github.com/coder/websocket | ISC | WebSocket server, zero dependencies |
| github.com/pion/turn (later, UDP hosts only) | MIT | embedded TURN/STUN |
| Apple CryptoKit (in the apps) | Apple system framework | X25519, Ed25519, HKDF, ChaCha20-Poly1305 |
| Google libwebrtc (in the apps) | BSD-3-Clause | WebRTC calls |
| Python `cryptography` (tests only) | Apache-2.0 OR BSD-3-Clause | test clients |
| Python `websockets` (tests only) | BSD-3-Clause | test clients |
| Cloudflare Tunnel (`cloudflared`) | Apache-2.0 | reaching a home machine without opening ports |

Switchboard's own license: Apache-2.0.
