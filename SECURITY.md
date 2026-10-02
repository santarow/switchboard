# Security policy

## Reporting a problem

Please report security issues **privately**, through GitHub's private vulnerability reporting:
the **Security** tab of this repository, then **Report a vulnerability**. Don't open a public issue.

Include what you found, how to reproduce it, and what an attacker gains. We aim to answer within a
week. This is a small project with no bug bounty.

## In scope

- The relay in this repository (`main.go`, `relay/`).
- The wire protocol in `docs/protocol.md`, including the sealing scheme, as specified.
- The reference client in `testkit/sb.py`, where it would mislead someone implementing the protocol.

Examples: reading or changing a sealed message, sending as another key, reaching a device that
didn't allow you, logging in without the private key, making the relay log something secret, or
taking the relay down with little effort from one connection.

## Out of scope

- Denial of service that needs many connections or a lot of bandwidth. The relay has per-connection
  limits only; see [docs/security-review.md](docs/security-review.md) for known limits.
- Traffic analysis: who talks to whom, when, and how much. The relay sees routing headers by design.
- No forward secrecy: the box keys are long-lived (protocol.md section 9). Known and documented.
- Bugs in client apps built on the protocol, unless the protocol itself causes them.
- Your TLS proxy, Cloudflare Tunnel, or host configuration.
- Findings from automated scanners without a working example.

## Design promises

Switchboard holds no key that can open a message, keeps nothing on disk, and never logs message
contents, tickets or full keys. A break of any of these is in scope.
