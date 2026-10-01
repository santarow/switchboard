#!/usr/bin/env python3
"""Plays Workshop's broker side: keeps a Switchboard connection open, opens each sealed request,
replays it as plain HTTP against a local Workshop (or buddy/scripts/mock_workshop.py), and seals the
answer back. Workshop's own Swift code does the same job in-process (#141).

    testkit/.venv/bin/python testkit/mac_bridge.py --switchboard http://127.0.0.1:8790 \
        --workshop http://127.0.0.1:8788 --link <mock's link.txt> --state testkit/.state

Writes <state>/broker-link.txt: the pairing link with the broker route, for the phone to scan.
Never logs bodies, tokens or keys.
"""
import argparse, asyncio, base64, hashlib, json, os, time, urllib.error, urllib.request
from collections import deque
from urllib.parse import urlparse, parse_qs

import sb

ap = argparse.ArgumentParser()
ap.add_argument("--switchboard", default="http://127.0.0.1:8790")
ap.add_argument("--workshop", default="http://127.0.0.1:8788")
ap.add_argument("--link", required=True, help="the Mac's tailnet pairing link (mock writes it to link.txt)")
ap.add_argument("--state", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".state"))
args = ap.parse_args()

os.makedirs(args.state, exist_ok=True)
STATE = os.path.join(args.state, "mac.json")


def load():
    if os.path.exists(STATE):
        return json.load(open(STATE))
    s = {"keys": sb.Keys().private(), "peers": {}}       # peers: identity → {"key"}
    save(s)
    return s


def save(s):
    with open(STATE, "w") as f:
        json.dump(s, f, indent=1)
    os.chmod(STATE, 0o600)


state = load()
keys = sb.Keys(**state["keys"])
ROUTE = {"kind": "broker", "url": args.switchboard, "mac_id": keys.id, "mac_key": keys.key}

# The pairing code from the Mac's QR becomes a ticket on Switchboard: SHA-256 of the code, hex.
qr = json.loads(sb.b64d(parse_qs(urlparse(args.link).query)["p"][0]))
tickets = [{"hash": hashlib.sha256(qr["code"].encode()).hexdigest(), "exp": qr["exp"]}]
qr["routes"] = [ROUTE] + [r for r in qr["routes"] if r.get("kind") != "broker"]
link = "santarow-buddy://pair?v=1&p=" + sb.b64e(json.dumps(qr).encode())
open(os.path.join(args.state, "broker-link.txt"), "w").write(link)

seen = deque(maxlen=4096)       # message ids already handled: a replayed box is dropped


def with_broker_route(path, status, body):
    """Workshop lists the broker route first wherever it hands out routes (pair and hello)."""
    if status != 200 or path.split("?")[0] not in ("/buddy/pair", "/buddy/hello"):
        return body
    o = json.loads(body)
    o["routes"] = [ROUTE] + [r for r in o.get("routes", []) if r.get("kind") != "broker"]
    return json.dumps(o).encode()


def http(method, path, headers, body):
    req = urllib.request.Request(args.workshop + path, data=body if method != "GET" else None,
                                 method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, {"Content-Type": r.headers.get("Content-Type", "")}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {"Content-Type": e.headers.get("Content-Type", "")}, e.read()


async def push_policy(conn):
    await conn.policy(allow=list(state["peers"]), tickets=tickets)


async def main():
    conn = None

    async def on_message(h, box):
        if (h["from"], h["id"]) in seen:
            return
        peer = state["peers"].get(h["from"])
        peer_key = peer["key"] if peer else h.get("key")
        if not peer_key:
            return
        try:
            head, body = sb.parse_inner(sb.open_box(keys, h["from"], peer_key, h["id"], box))
        except Exception:
            print("dropped a box that didn't open", flush=True)
            return
        seen.append((h["from"], h["id"]))
        path = head["path"]
        if not peer and path != "/buddy/pair":
            return                     # strangers may only pair
        status, rh, rbody = await asyncio.to_thread(http, head["method"], path, head.get("headers", {}), body)
        rbody = with_broker_route(path, status, rbody)
        if path == "/buddy/pair" and status == 200:
            state["peers"][h["from"]] = {"key": peer_key, "paired_at": int(time.time())}
            tickets.clear()            # the code is used
            save(state)
            await push_policy(conn)
        if path == "/buddy/device" and head["method"] == "DELETE" and status == 200:
            state["peers"].pop(h["from"], None)
            save(state)
        msg_id = sb.b64e(os.urandom(16))
        out = sb.seal(keys, h["from"], peer_key, msg_id,
                      sb.inner({"t": "res", "re": h["id"], "status": status, "headers": rh}, rbody))
        try:
            await conn.send(h["from"], msg_id, out)
        except Exception as e:
            print(f"answer not sent: {e}", flush=True)
        if path == "/buddy/device" and status == 200:
            await push_policy(conn)    # after the answer, so the phone still hears it
        print(f"{time.strftime('%H:%M:%S')} {head['method']} {path.split('?')[0]} → {status}", flush=True)

    while True:
        try:
            conn = await sb.Conn(args.switchboard, keys, on_message).connect()
            await push_policy(conn)
            print(f"bridge online as {keys.id[:8]}, {len(state['peers'])} paired", flush=True)
            await conn.reader
        except (OSError, Exception) as e:
            print(f"switchboard unreachable ({type(e).__name__}), retrying", flush=True)
        await asyncio.sleep(1)


asyncio.run(main())
