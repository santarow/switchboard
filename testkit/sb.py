"""Switchboard client side, for tests: keys, sealed envelopes, frames, and an asyncio connection.

This is the reference for what Buddy and Workshop implement in CryptoKit (docs/protocol.md).
Test-only: needs `cryptography` (Apache-2.0 OR BSD-3-Clause) and `websockets` (BSD-3-Clause).
"""
import asyncio, base64, json, os, struct
from urllib.parse import urlparse

import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CHUNK = 256 * 1024
RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
RAW_PRIV = dict(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption())


def b64e(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def b64d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Keys:
    """A device's two keys: Ed25519 to log in (its address), X25519 to seal envelopes."""

    def __init__(self, sign=None, box=None):
        self.sign = Ed25519PrivateKey.from_private_bytes(b64d(sign)) if sign else Ed25519PrivateKey.generate()
        self.box = X25519PrivateKey.from_private_bytes(b64d(box)) if box else X25519PrivateKey.generate()
        self.id = b64e(self.sign.public_key().public_bytes(**RAW))
        self.key = b64e(self.box.public_key().public_bytes(**RAW))

    def private(self):
        return {"sign": b64e(self.sign.private_bytes(**RAW_PRIV)), "box": b64e(self.box.private_bytes(**RAW_PRIV))}


def _key(my_box, peer_key, from_id, to_id):
    shared = my_box.exchange(X25519PublicKey.from_public_bytes(b64d(peer_key)))
    return HKDF(hashes.SHA256(), 32, salt=b64d(from_id) + b64d(to_id), info=b"switchboard-v1 envelope").derive(shared)


def seal(me, peer_id, peer_key, msg_id, plaintext):
    """nonce(12) || ciphertext || tag(16), the layout of CryptoKit's ChaChaPoly.SealedBox.combined."""
    nonce = os.urandom(12)
    aad = b64d(peer_id) + b64d(me.id) + b64d(msg_id)
    return nonce + ChaCha20Poly1305(_key(me.box, peer_key, me.id, peer_id)).encrypt(nonce, plaintext, aad)


def open_box(me, peer_id, peer_key, msg_id, box):
    aad = b64d(me.id) + b64d(peer_id) + b64d(msg_id)
    return ChaCha20Poly1305(_key(me.box, peer_key, peer_id, me.id)).decrypt(box[:12], box[12:], aad)


def inner(head, body=b""):
    h = json.dumps(head, separators=(",", ":")).encode()
    return struct.pack(">I", len(h)) + h + body


def parse_inner(data):
    n = struct.unpack(">I", data[:4])[0]
    return json.loads(data[4:4 + n]), data[4 + n:]


class Failed(Exception):
    """Switchboard couldn't deliver: offline, not_allowed, too_big, slow, rate_limited."""


class Conn:
    """One logged-in connection. on_message(header, box) is called for each whole message."""

    def __init__(self, url, keys, on_message=None):
        self.url, self.keys, self.on_message = url, keys, on_message
        self.parts = {}      # (from, id) → [bytes]
        self.pending = {}    # id → Future, for request()
        self.ws = None

    async def connect(self):
        u = urlparse(self.url)
        ws_url = ("wss" if u.scheme == "https" else "ws") + "://" + u.netloc + u.path.rstrip("/") + "/v1/connect"
        self.ws = await websockets.connect(ws_url, max_size=2 * CHUNK)
        ch = json.loads(await self.ws.recv())
        msg = b"switchboard-v1 login\n" + u.netloc.encode() + b"\n" + b64d(ch["nonce"])
        await self.ws.send(json.dumps({"t": "login", "id": self.keys.id, "sig": b64e(self.keys.sign.sign(msg))}))
        ready = json.loads(await self.ws.recv())
        assert ready.get("t") == "ready", ready
        self.reader = asyncio.create_task(self._read())
        return self

    async def policy(self, allow=(), tickets=()):
        await self.ws.send(json.dumps({"t": "policy", "allow": list(allow), "tickets": list(tickets)}))

    async def send(self, to, msg_id, box, key=None, ticket=None):
        chunks = [box[i:i + CHUNK] for i in range(0, len(box), CHUNK)] or [b""]
        for seq, part in enumerate(chunks):
            h = {"to": to, "id": msg_id, "seq": seq, "last": seq == len(chunks) - 1}
            if key: h["key"] = key
            if ticket: h["ticket"] = ticket
            hb = json.dumps(h, separators=(",", ":")).encode()
            await self.ws.send(struct.pack(">H", len(hb)) + hb + part)

    async def _read(self):
        try:
            async for data in self.ws:
                if isinstance(data, str):
                    m = json.loads(data)
                    f = self.pending.pop(m.get("re"), None)
                    if f and not f.done():
                        f.set_exception(Failed(m["error"]))
                    continue
                n = struct.unpack(">H", data[:2])[0]
                h = json.loads(data[2:2 + n])
                k = (h["from"], h["id"])
                self.parts.setdefault(k, {})[h["seq"]] = data[2 + n:]
                if h["last"]:
                    got = self.parts.pop(k)
                    if sorted(got) != list(range(h["seq"] + 1)):
                        continue        # a frame went missing; the sender's timeout handles it
                    box = b"".join(got[i] for i in range(h["seq"] + 1))
                    if self.on_message:
                        asyncio.create_task(self.on_message(h, box))
        except websockets.ConnectionClosed:
            pass
        for f in self.pending.values():
            if not f.done():
                f.set_exception(Failed("disconnected"))

    async def close(self):
        await self.ws.close()


class Phone:
    """The phone's side of a broker route: HTTP-shaped requests to one Mac, sealed end to end."""

    def __init__(self, url, keys, mac_id, mac_key):
        self.keys, self.mac_id, self.mac_key = keys, mac_id, mac_key
        self.conn = Conn(url, keys, self._on_message)

    async def connect(self):
        await self.conn.connect()
        await self.conn.policy(allow=[self.mac_id])
        return self

    async def _on_message(self, h, box):
        if h["from"] != self.mac_id:
            return
        try:
            head, body = parse_inner(open_box(self.keys, self.mac_id, self.mac_key, h["id"], box))
        except Exception:
            return              # not sealed by our Mac: drop
        f = self.conn.pending.pop(head.get("re"), None)
        if f and not f.done():
            f.set_result((head, body))

    async def request(self, method, path, headers=None, body=b"", ticket=None, timeout=30):
        msg_id = b64e(os.urandom(16))
        box = seal(self.keys, self.mac_id, self.mac_key, msg_id,
                   inner({"t": "req", "method": method, "path": path, "headers": headers or {}}, body))
        f = asyncio.get_running_loop().create_future()
        self.conn.pending[msg_id] = f
        await self.conn.send(self.mac_id, msg_id, box, key=self.keys.key if ticket else None, ticket=ticket)
        head, body = await asyncio.wait_for(f, timeout)
        return head["status"], head.get("headers", {}), body
