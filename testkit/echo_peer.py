#!/usr/bin/env python3
"""A stand-in "Mac" to test your client against: it pairs with anyone holding its code and answers
every sealed request with the same body, sealed back.

    testkit/.venv/bin/python testkit/echo_peer.py --switchboard http://127.0.0.1:8790

It prints the broker route (`url`, `mac_id`, `mac_key`) and a pairing `code`. Your client then:

1. logs in and sends its policy `{"t": "policy", "allow": [mac_id]}`;
2. sends a sealed `{"t": "req", ...}` with `key` (its box key) and `ticket` (SHA-256 hex of the code)
   in the frame header. The echo peer adds it to `allow` and answers `{"t": "res", "status": 200}`
   with the request's body;
3. sends more requests without `key` or `ticket`; each comes back the same way.

A call message (`"t": "call"`) is echoed with its head unchanged. Keys live only in memory.
"""
import argparse, asyncio, hashlib, json, os, time

import sb

ap = argparse.ArgumentParser()
ap.add_argument("--switchboard", default="http://127.0.0.1:8790")
args = ap.parse_args()


async def main():
    keys = sb.Keys()
    code = os.urandom(16).hex()
    ticket = {"hash": hashlib.sha256(code.encode()).hexdigest(), "exp": int(time.time()) + 3600}
    peers = {}                          # identity → box key, learned from the first ticketed request

    async def on_message(h, box):
        peer, key = h["from"], peers.get(h["from"]) or h.get("key")
        if not key:
            return
        try:
            head, body = sb.parse_inner(sb.open_box(keys, peer, key, h["id"], box))
        except Exception:
            return                      # not sealed for us: drop, as a real Mac does
        if peer not in peers:
            peers[peer] = key
            await conn.policy(allow=list(peers), tickets=[ticket])
            print("paired", peer[:8], flush=True)
        if head.get("t") == "req":
            head = {"t": "res", "re": h["id"], "status": 200, "headers": head.get("headers", {})}
        msg_id = sb.b64e(os.urandom(16))
        await conn.send(peer, msg_id, sb.seal(keys, peer, key, msg_id, sb.inner(head, body)), lossy=h.get("lossy", False))

    conn = await sb.Conn(args.switchboard, keys, on_message).connect()
    await conn.policy(tickets=[ticket])
    print(json.dumps({"route": {"kind": "broker", "url": args.switchboard, "mac_id": keys.id, "mac_key": keys.key},
                      "code": code}, indent=1), flush=True)
    await conn.reader


asyncio.run(main())
