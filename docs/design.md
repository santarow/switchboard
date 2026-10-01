# Switchboard design (spike, board #138)

Switchboard is SantaRow's message broker. Buddy (iPhone) and Workshop (Mac) both connect **out** to
it, and it connects them. It forwards sealed envelopes and never sees plaintext. It is the `broker`
route in `buddy/docs/pairing.md` section 1: only the route changes, never the rest of that contract.

Status: proposal, waiting for Jason's OK before any code (#139, #140).

## Decision in one table

| question | answer | why |
|---|---|---|
| Language | **Go** | one static binary for macOS and Linux (`GOOS=linux go build`), and the whole field below is Go, so TURN can be embedded later in the same binary |
| Message relay | **write our own**, about 500 lines | the job is "two known keys, forward opaque frames". That is simple, so the license policy says build it |
| Transport | **one WebSocket over HTTPS** | the only thing a Cloudflare Tunnel carries besides plain HTTP. Same path works on the Studio and on a VPS |
| Encryption | **end to end in the apps**: X25519 + HKDF-SHA256 + ChaCha20-Poly1305, Ed25519 to log in | all four are in Apple CryptoKit. The server holds no key that can open a message |
| Call media | **WebRTC direct**, fallback by where Switchboard runs (below) | Cloudflare Tunnel cannot carry UDP, so TURN cannot live behind it |
| State | **none on disk** | the Mac re-sends who may reach it each time it connects. A restart loses nothing |

## The candidates

| candidate | license | what it is | fit | verdict |
|---|---|---|---|---|
| LiveKit server v1.13.7 (Sep 2026) | Apache-2.0 | WebRTC SFU: rooms, many participants, Go on Pion | built for group rooms. Needs UDP ports or TCP 7881 open, which a Tunnel can't give. The SFU sees media unless its E2EE is turned on. Messages and pairing are out of scope | **not now.** Revisit only for group calls |
| coturn | BSD-3-Clause | TURN/STUN server, C, its own daemon | does TURN well, but it is a second process, and TURN is UDP | **no.** pion/turn does the same inside our binary |
| pion/turn v5.1.1 (Sep 2026) | MIT | TURN/STUN as a Go library | embeddable, same binary | **yes, later (#140)**, only where UDP is reachable (VPS) |
| NATS | Apache-2.0 (stayed so after the 2025 Synadia/CNCF dispute) | pub/sub broker, Go | a full broker with its own auth model, a second process, and clustering we don't need | **no.** Too much for forwarding between paired keys |
| Centrifugo v6 | Apache-2.0 (PRO is commercial) | real-time pub/sub over WebSocket, Go | channels plus JWT auth; fine, but the auth and channel model fight "route by public key". PRO features would tempt lock-in | **no** |
| Headscale + DERP | BSD-3-Clause both | self-hosted Tailscale control server; DERP = Tailscale's encrypted relay | Headscale means every phone runs a VPN, which is what the broker exists to avoid (one VPN slot, work VPN clash). DERP is the right **shape** (route by public key, relay sees only ciphertext) but its wire format is Tailscale's | **borrow DERP's design, not its code** |
| coder/websocket | ISC | Go WebSocket library, zero dependencies | the one piece Go's standard library lacks | **yes** |

Notes:
- LiveKit's own hosted product and Cloudflare Realtime (hosted TURN) stay options for the hosted tier
  (step 3 in pairing.md). Neither is needed for v0.
- Nothing here is AGPL, GPL or LGPL.

## Why Go, not Swift

| | Go | Swift |
|---|---|---|
| One binary, Mac and Linux | yes, cross-compile from the Mac | Linux needs the static Linux SDK; works, more moving parts |
| WebRTC / TURN libraries | Pion (MIT), mature, used by LiveKit | thin; no server-side TURN |
| Sharing code with the apps | no | yes, but the server does **no crypto** (end to end), so there is little to share |
| Boring server tech | standard library `net/http`, TLS, context | Vapor or Hummingbird on top |

The deciding point: the server forwards bytes. The apps do the crypto in CryptoKit either way.

Not installed yet: Go on this Mac (`brew install go`, BSD-3-Clause). Needs Jason's OK.

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

Same as pairing.md section 3, sealed:

1. Phone scans the QR: `routes` holds a broker route with `url`, `mac_id`, `mac_key`.
2. Phone connects with its own identity key, then sends `POST /buddy/pair` sealed to `mac_key`,
   tagged with the ticket. Inside the envelope: the code and the phone's own two public keys.
3. Workshop answers as today (token, routes, holly) and adds the phone's identity key to `allow`.

### Envelopes

```
outer (Switchboard reads):  {"to": "<identity key>", "from": "<identity key>", "id": "<16 random bytes>",
                             "ticket": "<optional>", "box": "<base64 ciphertext>"}
inner (only the two ends):  {"method": "POST", "path": "/buddy/call/turn?start=…", "headers": {…}, "body": "<bytes>"}
```

- Seal: X25519(sender, recipient) → HKDF-SHA256 (salt = both identity keys) → ChaCha20-Poly1305,
  random 12-byte nonce, `to`+`from`+`id` as additional data so Switchboard can't re-address a box.
- The inner message is the same HTTP request and response as the tailnet route. The bearer token
  rides inside, so Workshop's endpoints don't change.
- Bodies above 256 KB go as numbered chunks (a turn's WAV can be MBs). Limit 25 MB, as pairing.md.
- Offline recipient: `{"error": "offline"}` right away. Switchboard queues nothing.

Known gap, v0: static-static keys mean no forward secrecy. A later version can add an ephemeral
handshake (Noise IK pattern) without changing Switchboard, which never sees inside.

### Calls (#140)

Protocol 1 calls are HTTP turns, so they already work over envelopes (above) with no extra code.
#140 adds live audio for protocol 2:

1. **Signaling:** SDP offer and answer and ICE candidates travel as envelopes. Sealed, so the DTLS
   fingerprints can't be swapped by Switchboard.
2. **Direct:** WebRTC peer to peer with STUN (pion, served by Switchboard where UDP is reachable).
3. **Fallback:**

| where Switchboard runs | fallback when direct fails |
|---|---|
| Mac Studio behind Cloudflare Tunnel | audio frames as sealed envelopes on the same WebSocket. TCP, a little more delay, works everywhere the Tunnel does |
| VPS or hosted, UDP open | pion/turn embedded, short-lived credentials minted per call |

Apps need a WebRTC library for this (Google's libwebrtc, BSD-3-Clause). That is the Buddy and
Workshop side, flagged now so it isn't a surprise.

### Running it

| | |
|---|---|
| Binary | `switchboard`, darwin/arm64 and linux/amd64 |
| Listens | `127.0.0.1:8790`; `cloudflared` points a hostname at it (like `api.underdrafter.com`) |
| Keepalive | ping every 30 s (Cloudflare drops idle sockets around 100 s) |
| Logs | connects, disconnects, sizes, errors. **Never** envelope contents, tickets or keys in full |
| Limits | frame size, messages per second per key, connections per IP |

## Testing (#139)

End to end on localhost with `buddy/scripts/mock_workshop.py` playing the Mac and a small client
playing the phone. Python's standard library has no X25519 or ChaCha20-Poly1305, so the test side
needs `cryptography` (Apache-2.0 OR BSD-3-Clause) in a venv. The mock stays stdlib for the tailnet
route; only its broker mode needs it.

## Third-party

| name | license | why |
|---|---|---|
| Go toolchain and standard library | BSD-3-Clause | language, HTTP, TLS, Ed25519 verify |
| github.com/coder/websocket | ISC | WebSocket server, zero dependencies |
| github.com/pion/turn (#140, hosted only) | MIT | embedded TURN/STUN |
| Apple CryptoKit (in the apps) | Apple system framework | X25519, Ed25519, HKDF, ChaCha20-Poly1305 |
| Google libwebrtc (in the apps, #140) | BSD-3-Clause | WebRTC calls |
| Python `cryptography` (tests only) | Apache-2.0 OR BSD-3-Clause | test client and mock broker mode |
| Cloudflare Tunnel (`cloudflared`) | Apache-2.0 | reaching the Studio, already used |

Switchboard's own license at v1: Apache-2.0 or MIT, Jason's pick. Apache-2.0 suggested for its patent
grant.

## Open for Jason

1. OK to build in Go, and to `brew install go`?
2. Apache-2.0 or MIT for Switchboard?
3. OK to add `cryptography` to a test venv for #139?
