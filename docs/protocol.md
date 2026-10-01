# Switchboard wire protocol, v1

What Buddy and Workshop implement to use a `broker` route. Everything in `buddy/docs/pairing.md`
sections 2 to 8 stays the same: the same requests and answers travel inside sealed envelopes.
Reference code: `testkit/sb.py` (client side) and `relay/relay.go` (Switchboard).

All keys and ids are 32 or 16 raw bytes, written as **base64url without padding**.

## 1. Keys, one pair per device

| key | CryptoKit | used for |
|---|---|---|
| identity | `Curve25519.Signing.PrivateKey` (Ed25519) | logging in. Its public key is the device's address (`id`) |
| box | `Curve25519.KeyAgreement.PrivateKey` (X25519) | sealing envelopes. Its public key is `key` |

Both live in the Keychain (`ThisDeviceOnly`). Made once per install.

## 2. The broker route

```json
{"kind": "broker", "url": "https://switchboard.example", "mac_id": "<Mac identity>", "mac_key": "<Mac box key>"}
```

In the QR's `routes` and in the `routes` of `pair` and `hello` answers, as pairing.md section 1.
The phone trusts `mac_id` and `mac_key` only from the QR, never from Switchboard.

## 3. Connecting

1. Open a WebSocket to `url` + `/v1/connect` (`https` → `wss`).
2. Switchboard sends text `{"t": "challenge", "nonce": "<32 bytes>"}`.
3. Send text `{"t": "login", "id": "<identity>", "sig": "<Ed25519 signature>"}` over the bytes
   `"switchboard-v1 login\n" + host + "\n" + nonce`, where `host` is the URL's host with its port if
   it has one (`switchboard.example`, `127.0.0.1:8790`).
4. Switchboard answers `{"t": "ready", "id": "<identity>", "ice": [{"urls": ["stun:…"]}]}`, or closes
   with code 1008 (bad login). `ice` lists STUN/TURN servers for direct calls (section 8), in WebRTC's
   `RTCIceServer` shape; it may be empty.
5. Send your policy (section 4) right away, and again whenever it changes.

Switchboard pings every 30 s. A newer login with the same identity replaces the older connection.
On a drop: reconnect, log in, re-send the policy. Switchboard remembers nothing across connections.

## 4. Policy: who may reach you

Text frame, replaces the previous one whole:

```json
{"t": "policy", "allow": ["<identity>", …], "tickets": [{"hash": "<64 hex>", "exp": 1790000000}]}
```

| who | allow | tickets |
|---|---|---|
| Mac | identities of its paired phones | `hash` = lowercase hex SHA-256 of each live pairing `code` (UTF-8), `exp` = the QR's `exp` |
| phone | `[mac_id]` | none |

A frame from A reaches B only if one of these holds:

- A is in B's `allow`;
- the frame carries a `ticket` that is in B's `tickets` and not expired;
- B sent A a ticketed frame in the last 2 minutes (so the Mac can answer a phone that is pairing,
  including with `code_used`).

The Mac drops a ticket as soon as its code is used, and adds the phone to `allow` before answering.
On unpair it removes the phone after sending the answer.

## 5. Frames

Every message is one or more **binary** frames:

```
[2 bytes: header length, big-endian] [header JSON] [payload: a slice of the sealed box]
```

```json
{"to": "<identity>", "id": "<16 random bytes>", "seq": 0, "last": true, "key": "<optional>", "ticket": "<optional>"}
```

| field | meaning |
|---|---|
| `to` | recipient identity |
| `id` | new random id per message, same on all its frames |
| `seq`, `last` | the box is cut into slices of at most **256 KB**; `seq` counts from 0, `last` marks the final one |
| `key` | sender's box key. Only on the pairing request, when the Mac doesn't know it yet |
| `ticket` | only on the pairing request: SHA-256 hex of the QR `code` |
| `lossy` | live audio only (section 8). Must fit one frame. Sent ahead of anything queued, and dropped, with no error, when the recipient is behind |

Switchboard sets `from` (the sender's logged-in identity, so it can't be faked), strips `ticket`, and
passes the rest on. The receiver joins the slices in `seq` order when `last` arrives, then opens the
box. Max header 2 KB. Max message: the 25 MB body limit of pairing.md plus a little.

If Switchboard can't deliver, it sends the sender text `{"t": "error", "re": "<id>", "error": "…"}`:

| error | meaning | Buddy does |
|---|---|---|
| `offline` | the Mac isn't connected | this route has no answer: try the next route (pairing.md section 1) |
| `not_allowed` | the Mac's policy on this Switchboard doesn't list you (for example, paired over another route) | this route can't reach the Mac: try the next route and **keep the pairing** (#192). Only the Mac's own `401 unpaired`, inside a sealed answer, means unpaired |
| `too_big` / `bad_frame` | a bug on the sender | show an error |
| `slow` / `rate_limited` | Mac not reading fast enough / over 400 frames per second | treat as no answer |

## 6. Sealing

```
shared = X25519(my box key, their box key)
k      = HKDF-SHA256(ikm: shared, salt: from_identity ‖ to_identity, info: "switchboard-v1 envelope", 32 bytes)
box    = ChaChaPoly.seal(plaintext, key: k, nonce: 12 random bytes,
                         authenticating: to_identity ‖ from_identity ‖ id).combined
```

`‖` joins the raw bytes (32 + 32 + 16 for the authenticated data). `combined` = nonce ‖ ciphertext ‖
16-byte tag, which is CryptoKit's layout. The salt puts sender first, so each direction has its own
key. To open, swap the roles: salt is still `from ‖ to` as written in the header.

The receiver keeps the `id`s it has opened recently and drops a repeat.

## 7. What's inside: an HTTP request or answer

```
[4 bytes: head length, big-endian] [head JSON] [body bytes]
```

```json
{"t": "req", "method": "POST", "path": "/buddy/call/turn?start=…&during=0", "headers": {"Authorization": "Bearer …", "Content-Type": "audio/wav"}}
{"t": "res", "re": "<id of the request>", "status": 200, "headers": {"Content-Type": "audio/wav"}}
```

Paths, headers, bodies and status codes are exactly those of pairing.md. The bearer token rides
inside, so Switchboard never sees it. The Mac answers each request with one `res` whose `re` is the
request's `id`; answers may come in any order.

Pairing: the phone sends `POST /buddy/pair` with `key` and `ticket` in the frame header. The Mac
opens it with the header's `key`, and on `200` stores that identity with that key. From then on it
uses the stored key and ignores `key` in headers. A Mac answers nothing but `/buddy/pair` from an
identity it hasn't paired.

## 8. Calls: signaling and the audio fallback

For live audio (protocol 2). Protocol 1 calls are the HTTP turns of section 7 and need none of this.

Every call message is a sealed envelope whose head is not `req`/`res`:

```json
{"t": "call", "call": "<call id>", "kind": "offer",  "sdp": "…"}
{"t": "call", "call": "<call id>", "kind": "answer", "sdp": "…"}
{"t": "call", "call": "<call id>", "kind": "ice",    "candidate": "…", "sdpMid": "0", "sdpMLineIndex": 0}
{"t": "call", "call": "<call id>", "kind": "relay"}
{"t": "call", "call": "<call id>", "kind": "bye"}
```

1. **Direct first.** The phone makes a WebRTC offer using the `ice` servers from `ready`, the Mac
   answers, both trickle `ice` candidates. Media then flows peer to peer (DTLS-SRTP). The SDP is
   sealed, so Switchboard can't swap the DTLS fingerprints in it.
2. **Fallback.** If the WebRTC connection isn't up 5 seconds after the answer, either side sends
   `relay`; the other answers `relay` and both send audio through Switchboard instead:

```json
{"t": "media", "call": "<call id>", "seq": 0, "codec": "opus", "ts": 0}   + one encoded frame as the body
```

   One 20 ms frame per message, sealed like everything else, sent with `lossy: true`. `seq` counts
   frames so the receiver can spot gaps and reorder; `ts` is in samples at the codec's rate. `codec`
   is `opus` (48 kHz mono) or `pcm16` (16 kHz mono, 16-bit little-endian, for testing).
3. `bye` ends the call either way. Interrupting Holly, `where` and the rest stay HTTP requests
   (section 7) and can run during a call.

Where Switchboard runs decides the fallback:

| where | `ice` from `ready` | when direct fails |
|---|---|---|
| Mac Studio behind a Cloudflare Tunnel (no UDP) | a public STUN server (`-stun`) | relayed audio over the socket, as above |
| a server with UDP open (later) | STUN plus Switchboard's own TURN | WebRTC's own TURN relay; socket relay as last resort |

## 9. Not in v1

- Forward secrecy: the box keys are long-lived. A later version can add a per-session handshake
  (Noise IK) inside the envelopes without changing Switchboard.
- Embedded TURN (pion/turn, MIT) for a server with UDP open.
