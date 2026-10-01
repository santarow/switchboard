#!/usr/bin/env python3
"""End to end on localhost: Switchboard + buddy's mock_workshop.py + the Mac bridge + a phone.

    testkit/.venv/bin/python testkit/e2e.py [--mock ~/repos/santarow/buddy/scripts/mock_workshop.py]

The phone pairs through Switchboard, then runs the calls in buddy/docs/pairing.md (hello, holly,
call start, a turn with a 3 MB WAV, poll, audio, stop, end), then the failures: a second scan of the
same code, a stranger, unpairing. Last, Switchboard's log must contain none of what was said.
Everything runs in a temp folder; the buddy repo is not touched.
"""
import argparse, asyncio, hashlib, io, json, os, shutil, subprocess, sys, tempfile, time, urllib.request, wave
from urllib.parse import urlparse, parse_qs

import sb

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ap = argparse.ArgumentParser()
ap.add_argument("--mock", default=os.path.expanduser("~/repos/santarow/buddy/scripts/mock_workshop.py"))
args = ap.parse_args()

SB_PORT, MOCK_PORT = 18790, 18788
SB_URL = f"http://127.0.0.1:{SB_PORT}"
tmp = tempfile.mkdtemp(prefix="switchboard-e2e-")
procs = []
failures = []


def check(ok, what):
    print(("  ok   " if ok else "  FAIL ") + what, flush=True)
    if not ok:
        failures.append(what)


def start(cmd, log, env=None, cwd=None):
    p = subprocess.Popen(cmd, stdout=open(log, "w"), stderr=subprocess.STDOUT, env={**os.environ, **(env or {})}, cwd=cwd)
    procs.append(p)
    return p


def wait_for(fn, what, secs=20):
    end = time.time() + secs
    while time.time() < end:
        try:
            if fn():
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise SystemExit(f"timed out waiting for {what}")


def wav(seconds):
    """16 kHz mono 16-bit silence: what pairing.md says the phone uploads."""
    b = io.BytesIO()
    with wave.open(b, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(16000)
        w.writeframes(b"\0\0" * int(16000 * seconds))
    return b.getvalue()


async def phone_steps(link):
    qr = json.loads(sb.b64d(parse_qs(urlparse(link).query)["p"][0]))
    route = qr["routes"][0]
    check(route["kind"] == "broker" and route["url"] == SB_URL, "QR lists the broker route first")
    ticket = hashlib.sha256(qr["code"].encode()).hexdigest()

    keys = sb.Keys()
    phone = await sb.Phone(route["url"], keys, route["mac_id"], route["mac_key"]).connect()

    # Before pairing, Switchboard refuses anything without the ticket.
    try:
        await phone.request("GET", "/buddy/hello")
        check(False, "unpaired phone is refused")
    except sb.Failed as e:
        check(str(e) == "not_allowed", f"unpaired phone is refused ({e})")

    st, _, body = await phone.request("POST", "/buddy/pair", {"Content-Type": "application/json"},
                                      json.dumps({"code": qr["code"], "device_name": "Test iPhone",
                                                  "app_version": "e2e"}).encode(), ticket=ticket)
    paired = json.loads(body)
    check(st == 200 and len(paired.get("token", "")) == 64, "pair → 200 with a token")
    check(paired.get("routes", [{}])[0].get("kind") == "broker", "pair answer lists the broker route first")
    auth = {"Authorization": "Bearer " + paired["token"]}

    st, _, body = await phone.request("GET", "/buddy/hello", auth)
    check(st == 200 and json.loads(body).get("ready") is True, "hello → ready")
    st, _, body = await phone.request("GET", "/buddy/holly", auth)
    check(st == 200 and json.loads(body).get("name") == "Holly", "holly → name")

    st, _, body = await phone.request("POST", "/buddy/call/start", auth)
    turn = json.loads(body)["turn"]
    check(st == 200, "call/start → greeting turn")

    async def poll_all(turn):
        got, n = [], 0
        for _ in range(40):
            st, _, body = await phone.request("GET", f"/buddy/call/poll?turn={turn}&from={n}&wait=1", auth)
            o = json.loads(body)
            got += o.get("audio", [])
            n = len(got)
            if o.get("done"):
                return got, o
        return got, o

    audio, _ = await poll_all(turn)
    check(len(audio) == 2, f"greeting arrives sentence by sentence ({len(audio)} sentences)")
    st, h, body = await phone.request("GET", f"/buddy/call/audio/{audio[0]}", auth)
    check(st == 200 and body[:4] == b"RIFF" and h.get("Content-Type") == "audio/wav", f"audio → WAV ({len(body)} bytes)")

    clip = wav(95)                 # about 3 MB: twelve frames on the wire
    t0 = time.time()
    st, _, body = await phone.request("POST", f"/buddy/call/turn?start={int(t0*1000)}&during=0",
                                      {**auth, "Content-Type": "audio/wav"}, clip)
    check(st == 200 and "turn" in json.loads(body), f"turn with {len(clip)//1024} KB WAV → 200 in {time.time()-t0:.2f} s")
    audio, _ = await poll_all(json.loads(body)["turn"])
    check(len(audio) == 3, "reply arrives")

    st, _, body = await phone.request("POST", "/buddy/call/turn", {**auth, "Content-Type": "audio/wav"}, b"nope")
    check(st == 400, "bad audio → 400 passes through")
    for p in ("/buddy/call/stop", "/buddy/call/end"):
        st, _, _ = await phone.request("POST", p, auth)
        check(st == 200, f"{p} → 200")

    # Same QR again from another phone: the Mac answers code_used, sealed, via the reply pass.
    other = await sb.Phone(route["url"], sb.Keys(), route["mac_id"], route["mac_key"]).connect()
    try:
        st, _, body = await other.request("POST", "/buddy/pair", {"Content-Type": "application/json"},
                                          json.dumps({"code": qr["code"]}).encode(), ticket=ticket)
        check(False, "used code's ticket is gone from Switchboard")
    except sb.Failed as e:
        check(str(e) == "not_allowed", f"used code's ticket is gone from Switchboard ({e})")

    # A stranger who knows the Mac's keys (photographed the QR) but has no token.
    try:
        await other.request("GET", "/buddy/hello", auth)
        check(False, "stranger is refused")
    except sb.Failed as e:
        check(str(e) == "not_allowed", f"stranger is refused ({e})")

    st, _, _ = await phone.request("DELETE", "/buddy/device", auth)
    check(st == 200, "unpair → 200")
    await asyncio.sleep(0.2)
    try:
        await phone.request("GET", "/buddy/hello", auth)
        check(False, "unpaired phone is cut off at Switchboard")
    except sb.Failed as e:
        check(str(e) == "not_allowed", f"unpaired phone is cut off at Switchboard ({e})")
    await phone.conn.close(); await other.conn.close()
    return paired["token"]


def main():
    print(f"work dir {tmp}")
    binary = os.path.join(tmp, "switchboard")
    subprocess.run(["go", "build", "-o", binary, "."], cwd=ROOT, check=True)
    sb_log = os.path.join(tmp, "switchboard.log")
    start([binary, "-addr", f"127.0.0.1:{SB_PORT}"], sb_log)
    wait_for(lambda: urllib.request.urlopen(SB_URL + "/healthz").status == 200, "switchboard")

    mock = os.path.join(tmp, "mock", "mock_workshop.py")
    os.makedirs(os.path.dirname(mock))
    shutil.copy(args.mock, mock)          # its .mock/ state lands in tmp, not in the buddy repo
    start([sys.executable, mock], os.path.join(tmp, "mock.log"), {"PORT": str(MOCK_PORT)})
    link_file = os.path.join(tmp, "mock", ".mock", "link.txt")
    wait_for(lambda: os.path.exists(link_file), "mock link")

    state = os.path.join(tmp, "bridge")
    start([sys.executable, os.path.join(HERE, "mac_bridge.py"), "--switchboard", SB_URL,
           "--workshop", f"http://127.0.0.1:{MOCK_PORT}", "--link", open(link_file).read().strip(),
           "--state", state], os.path.join(tmp, "bridge.log"))
    wait_for(lambda: "bridge online" in open(os.path.join(tmp, "bridge.log")).read(), "bridge")

    token = asyncio.run(phone_steps(open(os.path.join(state, "broker-link.txt")).read().strip()))

    log = open(sb_log).read()
    secrets = [token, "Holly", "mock Workshop", "Test iPhone", "buddy/", "RIFF"]
    check(not any(s in log for s in secrets), "Switchboard's log has no token, names, paths or audio")
    print("--- switchboard.log"); print(log.rstrip())


try:
    main()
finally:
    for p in procs:
        p.terminate()
    if failures:
        print(f"\n{len(failures)} FAILED (logs in {tmp})")
        sys.exit(1)
    print("\nall passed")
    shutil.rmtree(tmp, ignore_errors=True)
