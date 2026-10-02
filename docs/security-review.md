# Security review of the relay

A self-review of `relay/relay.go` and `main.go` against the threat model in
[design.md](design.md), 2026-10-01. Not an external audit.

## Threat model

Switchboard is run by someone the users don't have to trust with their data. It must:

1. never be able to read or change a message (sealed end to end, re-addressing detected);
2. never let a client send as another key;
3. not be an open relay: a frame reaches a device only if that device allowed it;
4. keep nothing on disk and log nothing secret;
5. stay up when one client misbehaves.

The relay operator can see routing headers (who, when, how much) and can drop messages. That is
accepted.

## What holds

| promise | how | checked |
|---|---|---|
| 1. can't read or change | the relay has no box keys; the box authenticates `to ‖ from ‖ id`, so a re-addressed or replayed-to-someone-else box fails to open | sealing in `testkit/sb.py`, vectors cross-checked with CryptoKit |
| 2. no sending as another key | Ed25519 login over a fresh 32-byte challenge plus host name; the relay overwrites `from` with the logged-in key | `TestBadSignature`, `TestAllowedForwardSetsFrom` |
| 3. not an open relay | `allowed()`: sender in recipient's `allow`, or a live ticket, or a 2-minute reply pass after a ticketed frame. Tickets are SHA-256 of a 128-bit code, so they can't be guessed | `TestNotAllowedWithoutPolicy`, `TestTicketAndReplyPass`, `TestExpiredTicket` |
| 4. no disk, no secrets in logs | no file or database code; logs hold 8 characters of a key and close codes | `e2e.py` greps the log for tokens, names, paths, audio and SDP |
| browsers can't connect cross-site | `websocket.Accept` with default options rejects a mismatched `Origin` | library default |

## Fixed in this review

| issue | risk | fix |
|---|---|---|
| A replaced connection was closed while holding the hub lock. `Close` waits up to 5 s for the old peer to answer, so one client logging in twice with a silent old socket froze all relaying for everyone | denial of service from one key | close outside the lock (`TestReplaceDoesNotBlock`, fails on the old code) |
| The login host came from the request's `Host` header. Where the relay is reachable directly, a client can name any host, so a login signature captured for another relay could be replayed here | login relay attack, only with a directly reachable relay and a victim connecting to an attacker's relay | new `-host` flag pins the host name (`TestPinnedHost`). Behind Cloudflare Tunnel the header is already fixed by routing |
| Live audio frames could be 256 KB and jump the queue | a peer the recipient allowed could crowd out everything else | live frames capped at 16 KB, else `too_big` (`TestLossyTooBig`) |
| Reply passes were deleted only when looked up again | slow memory growth from many pairing attempts | expired passes swept whenever one is added (pairing only, so cheap) |

## Known limits, not fixed

| issue | impact | suggested fix |
|---|---|---|
| **No per-IP or global connection limit.** Keys are free to make, and each connection may buffer up to 256 frames of 256 KB plus 64 live frames | memory exhaustion with many connections; a client can also allow itself and send to itself to fill its own queue. Out of scope per SECURITY.md, but worth closing before a public hosted service | cap connections per client IP (behind Cloudflare read `CF-Connecting-IP`, only when the proxy is trusted), cap queued **bytes** per connection rather than frames, and set a global connection cap |
| **Presence is visible.** `offline` vs `not_allowed` tells any logged-in key whether a given id is connected | someone who already knows a Mac's id (from its QR) learns when it is online | answer `not_allowed` whenever the sender isn't allowed, before looking at presence. Clients already treat both the same way |
| **A frame can be lost in a replace race.** If a recipient reconnects while a frame is being queued, the frame may go to the old connection's queue with no error | one message lost, the sender's request times out; not a security issue | check `to.done` before queueing, or look up the connection again |
| **A sender can be stalled up to 10 s** by a recipient that allowed it and stops reading | head-of-line blocking on that sender's socket only | per-recipient sender goroutines, if it shows up in practice |
| **No forward secrecy** | a leaked box key opens past messages recorded by the operator | a per-session handshake (Noise IK) inside the envelopes; the relay doesn't change |
| **Policy and control frames are unvalidated beyond shape** (ticket hashes aren't checked to be hex; `exp` can be far in the future) | none for others: each device only limits who reaches itself | none needed |
