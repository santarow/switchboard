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
| No per-address or global connection limit, and up to 256 frames of 256 KB queued per connection | memory exhaustion from many connections, or from a client that allows itself, sends to itself and stops reading | 256 connections in total and 16 per client address, counted from before login and refused with `503` / `429` (`TestConnectionLimits`). The address comes from `CF-Connecting-IP` only when the peer is loopback (cloudflared), so it can't be spoofed on a directly reachable relay (`TestIPHeaderOnlyFromLoopback`). Queues are 32 frames, about 8 MB, plus 1 MB of live audio. Policies capped at 256 keys and 64 tickets (`TestPolicyTooBig`) |
| `offline` vs `not_allowed` told any logged-in key whether a given id was connected | presence leak to anyone who knows a Mac's id | a sender the recipient doesn't allow always gets `not_allowed`. To still tell paired peers `offline`, the relay keeps the policy of up to 1024 recently disconnected devices in memory, oldest dropped first (`TestOfflineOnlyForAllowed`, `TestGoneKeepsNewest`). After a restart that memory is empty, so paired peers hear `not_allowed` until the device reconnects; clients treat both the same |

## Known limits, not fixed

| issue | impact | suggested fix |
|---|---|---|
| **Many addresses still add up.** With the caps above, worst case is about 256 × 9 MB of queues, held for at most the 10 s write timeout of a client that stops reading | memory pressure from a distributed attacker (an IPv6 /64 counts as many addresses) | lower `-max-conns` on a small host; cap queued bytes across the whole relay if it is ever hosted for strangers |
| **Remembered policies can be pushed out.** Someone making many keys and disconnecting them evicts older entries | a paired peer hears `not_allowed` instead of `offline` while its device is away; no access is granted | none needed while clients treat both the same |
| **The connect cap counts sockets, not keys.** One address may hold 16 connections under 16 keys | as designed; keys are free | none |
| **A frame can be lost in a replace race.** If a recipient reconnects while a frame is being queued, the frame may go to the old connection's queue with no error | one message lost, the sender's request times out; not a security issue | check `to.done` before queueing, or look up the connection again |
| **A sender can be stalled up to 10 s** by a recipient that allowed it and stops reading | head-of-line blocking on that sender's socket only | per-recipient sender goroutines, if it shows up in practice |
| **No forward secrecy** | a leaked box key opens past messages recorded by the operator | a per-session handshake (Noise IK) inside the envelopes; the relay doesn't change |
| **Policy and control frames are unvalidated beyond shape** (ticket hashes aren't checked to be hex; `exp` can be far in the future) | none for others: each device only limits who reaches itself | none needed |
