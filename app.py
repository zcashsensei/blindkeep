"""Blindkeep — the app. Encrypted memory you can prove things about.

    python app.py          →  http://127.0.0.1:8743

This is the PRODUCT surface, not the maintainer dashboard. dashboard.py reports
on the repository — tests, roadmap, todos. This is what someone who uses
Blindkeep actually touches: write a memory, read it back, prove the keep has
not been rewritten behind your back.

It starts a local node if one is not already listening, creates a master key on
first run, and never sends either anywhere. Everything is encrypted on this
machine before it reaches the node, which is the whole point: the node stores
ciphertext and cannot read it.

Stdlib only.
"""
import json
import os
import pathlib
import queue
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

PORT = 8743
NODE_PORT = 8741
NODE_URL = f"http://127.0.0.1:{NODE_PORT}"
KEY_PATH = HERE / "data" / "master.key"
PIN_PATH = HERE / "data" / "pin.json"

# An app that holds a master key must not be drivable by a page you happen to
# be visiting. Localhost is not a security boundary against the browser: a
# simple cross-origin POST skips CORS preflight entirely. Minted per launch,
# injected into the page this server serves, required on every route that
# touches the keep.
TOKEN = secrets.token_urlsafe(32)

HW_RUNS: dict = {}
HW_LOCK = threading.Lock()

# Agent access. An AI agent cannot read the page, so it cannot learn the
# session token -- it needs one of its own. Off by default and minted only when
# switched on, because handing an agent a key to your memory is a decision, not
# a default. Turning it off invalidates the token immediately.
AGENT = {"on": False, "token": None}

HEARTWOOD_DIR = pathlib.Path(os.environ.get(
    "HEARTWOOD_DIR", str(HERE.parent / "heartwood")))

HW_TARGETS = {"haiku": ("anthropic", "claude-haiku-4-5", 3),
              "sonnet": ("anthropic", "claude-sonnet-5", 4),
              "opus": ("anthropic", "claude-opus-5", 5),
              "gpt5": ("openai", "gpt-5", 5),
              "local": ("ollama", "gemma:2b", 1)}
HW_DEPTH = {"quick": (12, 20), "standard": (20, 60), "thorough": (40, 150)}
HW_STRICT = {"balanced": (0.01, 0.40), "cautious": (0.001, 0.50)}


# ------------------------------------------------------------------ node ----

def node_up() -> bool:
    try:
        with urllib.request.urlopen(f"{NODE_URL}/head", timeout=1.5):
            return True
    except urllib.error.HTTPError:
        return True                      # answered, so it is listening
    except (urllib.error.URLError, OSError):
        return False


def ensure_node() -> tuple[bool, str]:
    if node_up():
        return True, "already running"
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    subprocess.Popen([sys.executable, "-m", "blindkeep", "node",
                      "--data-dir", str(HERE / "data" / "keep"),
                      "--port", str(NODE_PORT)],
                     cwd=str(HERE),
                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        if node_up():
            return True, "started"
        time.sleep(0.25)
    return False, "did not come up"


def safe_error(exc: Exception) -> dict:
    """What the browser is told, versus what the operator is told.

    Python's filesystem errors carry the absolute path -- so a plain
    str(exception) hands out the username and the directory layout, and once
    agent access is switched on it hands them to the agent as well. The type
    is enough for a user to report; the detail goes to the console, which only
    the person running this can see.
    """
    print(f"[blindkeep] {type(exc).__name__}: {exc}", file=sys.stderr)
    return {"error": type(exc).__name__,
            "hint": "details are in the terminal running this app"}


def lock_down(path: pathlib.Path) -> None:
    """Make the master key readable by its owner and nobody else.

    It inherits the parent directory's ACL otherwise, which on Windows means
    SYSTEM and every local Administrator can read it. That is a poor default
    for the one file that decrypts everything.
    """
    try:
        if os.name == "nt":
            user = os.environ.get("USERNAME") or ""
            subprocess.run(["icacls", str(path), "/inheritance:r",
                            "/grant:r", f"{user}:F"],
                           capture_output=True, check=False, timeout=15)
        else:
            os.chmod(path, 0o600)
    except Exception as exc:                                 # pragma: no cover
        print(f"[blindkeep] could not tighten permissions on {path.name}: "
              f"{type(exc).__name__}", file=sys.stderr)


def client(need_key: bool = True):
    from blindkeep.client import BlindkeepClient
    key = b""
    if need_key:
        if not KEY_PATH.exists():
            KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
            BlindkeepClient.create_keys(str(KEY_PATH))
            lock_down(KEY_PATH)
        key = BlindkeepClient.load_master_key(str(KEY_PATH))
    return BlindkeepClient(NODE_URL, key, pin_path=str(PIN_PATH))


# ------------------------------------------------------------- heartwood ----

def heartwood_modules():
    if not (HEARTWOOD_DIR / "heartwood.py").exists():
        return None, f"Heartwood not found at {HEARTWOOD_DIR}"
    try:
        if str(HEARTWOOD_DIR) not in sys.path:
            sys.path.insert(0, str(HEARTWOOD_DIR))
        import challenges, endpoint, endpoints, heartwood      # noqa: E402
        return (heartwood, challenges, endpoint, endpoints), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def hw_run(run_id, choice):
    import math
    st = HW_RUNS[run_id]
    emit = lambda **kw: st["q"].put(kw)                        # noqa: E731
    try:
        mods, err = heartwood_modules()
        if err:
            emit(stage="error", msg=err)
            return
        H, C, E, EP = mods
        provider, model, auto = HW_TARGETS[choice["target"]]
        diff = auto if choice["hardness"] == "auto" else \
            {"easy": 1, "medium": 3, "hard": 5}[choice["hardness"]]
        calib, maxq = HW_DEPTH[choice["depth"]]
        alpha, p1 = HW_STRICT[choice["strictness"]]
        ep = EP.get_endpoint(provider, model=model)
        emit(stage="info", msg=f"Checking {model}")
        emit(stage="warn", msg=("The baseline is measured through the same "
                                "endpoint being checked. A provider throttling "
                                "during this step can hide. The receipt says so."))
        pool = C.make_pool(555555, calib, diff, None)
        ok = 0
        for i, it in enumerate(pool, 1):
            resp, _ = ep.query(it["q"])
            ok += E.grade(E.extract(resp), it["a"], resp)
            emit(stage="info", msg=f"baseline {i}/{calib} · {ok}/{i} correct")
        p0 = H.lower_conf_bound(ok, calib, conf=0.99)
        if p0 <= p1:
            emit(stage="error", msg=(f"This model scores {p0:.2f} on these "
                                     f"questions — too low for the result to "
                                     f"mean anything. Choose harder ones."))
            return
        seed = int(time.time())
        pool = C.make_pool(seed, 300, diff, None)
        com = C.pool_commitment(pool)
        beacon = H.fetch_beacon()
        if not beacon.get("randomness"):
            emit(stage="error", msg="Public randomness unreachable — no receipt.")
            return
        emit(stage="info", msg=f"public randomness drawn (round {beacon['round']})")
        order = H.selection_order(com, beacon, len(pool))
        lam = H.kelly_lambda(p0, p1)
        thr = math.log10(1.0 / alpha)
        plan = {"p0": p0, "p1": p1, "alpha": alpha, "lambda": lam,
                "pool_size": 300, "max_queries": maxq, "families": None}
        tr, lw = [], 0.0
        for k, iid in enumerate(order[:maxq], 1):
            it = pool[iid]
            resp, meta = ep.query(it["q"])
            g = E.grade(E.extract(resp), it["a"], resp)
            tr.append({"item_id": iid, "question_sha256": H.sha(it["q"]),
                       "response": resp, "response_sha256": H.sha(resp),
                       "graded": g, "output_tokens": meta.get("output_tokens")})
            lw += math.log10(1.0 + lam * (p0 - g))
            emit(stage="query", n=k, of=maxq, graded=g,
                 pct=max(0.0, min(100.0, 100.0 * lw / thr)) if lw > 0 else 0.0,
                 rate=round(sum(t["graded"] for t in tr) / k, 3))
            if lw >= thr:
                break
        cal = {"source": "endpoint_self", "n": calib, "successes": ok,
               "raw_rate": ok / calib, "method": "wilson_lower_99"}
        rc = H.build_receipt(seed, diff, com, beacon, plan, cal, tr, "blindkeep-app")
        st["receipt"] = rc
        v = H.verify_receipt(rc)
        anc = H.verify_beacon_online(rc)
        r = rc["result"]
        emit(stage="done", verdict=r["verdict"], queries=r["n_queries"],
             rate=r["observed_rate"], valid=v["valid"],
             anchored=anc["anchored"], model=model)
    except Exception as exc:
        emit(stage="error", msg=f"{type(exc).__name__}: {exc}")
    finally:
        st["done"] = True


# ---------------------------------------------------------------- server ----

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _host_ok(self) -> bool:
        """Reject DNS rebinding.

        Binding to 127.0.0.1 stops the network reaching this, and the session
        token stops a cross-origin page driving it -- but neither stops DNS
        rebinding. An attacker points a domain at their own server, you visit
        it, and they re-point that domain at 127.0.0.1. The browser now treats
        their page as SAME-ORIGIN with this server, so their script may fetch
        "/" and read the token out of the HTML, then spend it.

        The Host header is what survives that: after rebinding the browser
        still sends the attacker's domain, never 127.0.0.1. Checked before
        anything else, on every route including the page itself.
        """
        host = (self.headers.get("Host") or "").split(":")[0].strip("[]")
        return host in ("127.0.0.1", "localhost", "::1", "")

    def _send(self, code, obj, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def _auth(self) -> bool:
        origin = self.headers.get("Origin")
        if origin and origin not in (f"http://127.0.0.1:{PORT}",
                                     f"http://localhost:{PORT}"):
            return False
        tok = self.headers.get("X-Blindkeep-Token") or ""
        if not tok and "?" in self.path:
            from urllib.parse import parse_qs
            tok = (parse_qs(self.path.split("?", 1)[1]).get("t") or [""])[0]
        if secrets.compare_digest(tok, TOKEN):
            return True
        # An agent token, when enabled, reaches the memory routes but never the
        # master key or the agent switch itself -- otherwise an agent could
        # grant itself more access than it was given.
        if AGENT["on"] and AGENT["token"] and secrets.compare_digest(
                tok, AGENT["token"]):
            path = self.path.split("?", 1)[0]
            return path.startswith(("/api/write", "/api/read/", "/api/state"))
        return False

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {"error": "bad host"})
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            return self._send(200, PAGE.replace("__TOKEN__", TOKEN).encode(),
                              "text/html; charset=utf-8")
        if not self._auth():
            return self._send(403, {"error": "forbidden"})
        try:
            if path == "/api/state":
                ok, how = ensure_node()
                if not ok:
                    return self._send(200, {"node": False, "why": how})
                c = client(need_key=False)
                head = c.head()
                recs = c.list()
                _, hw_err = heartwood_modules()
                return self._send(200, {
                    "node": True, "how": how,
                    "records": len(recs),
                    "tree_size": head.get("tree_size"),
                    "root": head.get("root_hash") or head.get("root"),
                    "key_exists": KEY_PATH.exists(),
                    "heartwood": hw_err is None, "heartwood_error": hw_err,
                    "list": recs[-50:]})
            if path.startswith("/api/read/"):
                # Validate before touching the keep. Bad input is the CALLER's
                # mistake and deserves a 400 saying so -- returning 500 makes a
                # typo look like a crash, and buries real failures in noise.
                token = path.rsplit("/", 1)[-1]
                if not token.isdigit():
                    return self._send(400, {"error": "that is not a record number"})
                idx = int(token)
                if idx > 10_000_000:
                    return self._send(400, {"error": "record number out of range"})
                res = client().get(idx)
                plain = res.pop("plaintext")
                try:
                    text = plain.decode("utf-8")
                except UnicodeDecodeError:
                    text = f"<{len(plain)} bytes of binary>"
                return self._send(200, {"text": text, "meta": res})
            if path == "/api/key":
                # Deliberately NOT part of /api/state. The key is only ever
                # sent when explicitly asked for, so it does not sit in a
                # response the page fetches on every refresh.
                if not KEY_PATH.exists():
                    return self._send(404, {"error": "no key yet"})
                raw = KEY_PATH.read_bytes()
                return self._send(200, {"hex": raw.hex(), "path": str(KEY_PATH),
                                        "bytes": len(raw)})
            if path == "/api/agent":
                return self._send(200, {"enabled": AGENT["on"],
                                        "token": AGENT["token"] if AGENT["on"] else None,
                                        "url": f"http://127.0.0.1:{PORT}"})
            if path == "/api/pending":
                # Jobs only a human can finish -- an authorisation click, an
                # email. They kept slipping because nothing on screen carried
                # them, so they live in a file and surface as a bar that will
                # not be ignored. One-time codes carry an expiry so the bar can
                # say "this one is dead" instead of showing a stale number.
                f = HERE / "data" / "pending.json"
                if not f.exists():
                    return self._send(200, {"items": []})
                try:
                    data = json.loads(f.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    return self._send(200, {"items": []})
                now = int(time.time())
                for it in data.get("items", []):
                    ttl = it.get("ttl") or 0
                    it["expired"] = bool(ttl and now - it.get("issued", 0) > ttl)
                    it["left"] = max(0, ttl - (now - it.get("issued", 0))) if ttl else None
                return self._send(200, data)
            if path.startswith("/api/hw/events/"):
                return self._hw_stream(path.rsplit("/", 1)[-1])
            if path.startswith("/api/hw/receipt/"):
                with HW_LOCK:
                    r = HW_RUNS.get(path.rsplit("/", 1)[-1])
                if not r or not r.get("receipt"):
                    return self._send(404, {"error": "no receipt"})
                return self._send(200, json.dumps(r["receipt"], indent=2).encode())
        except Exception as exc:
            return self._send(500, safe_error(exc))
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, {"error": "bad host"})
        path = self.path.split("?", 1)[0]
        if not self._auth():
            return self._send(403, {"error": "missing or bad session token"})
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1_000_000:
            return self._send(413, {"error": "too large"})
        try:
            body = json.loads(self.rfile.read(n) or "{}")
        except json.JSONDecodeError:
            return self._send(400, {"error": "bad JSON"})
        # Valid JSON is not necessarily an OBJECT. A bare array or string parses
        # fine and then blows up on .get() with an AttributeError, which the
        # caller sees as a 500 -- a server fault for what is a malformed request.
        if not isinstance(body, dict):
            return self._send(400, {"error": "expected a JSON object"})
        try:
            if path == "/api/write":
                raw_text = body.get("text")
                if raw_text is not None and not isinstance(raw_text, str):
                    return self._send(400, {"error": "text must be text"})
                raw_label = body.get("label")
                if raw_label is not None and not isinstance(raw_label, str):
                    return self._send(400, {"error": "label must be text"})
                text = (raw_text or "").strip()
                if not text:
                    return self._send(400, {"error": "nothing to save"})
                if len(text) > 500_000:
                    return self._send(400, {"error": "that memory is too long "
                                                     "(500,000 characters max)"})
                res = client().put(text, label=(raw_label or "")[:120])
                return self._send(200, {"ok": True, "record": res})
            if path == "/api/agent":
                # Only the page's own token may flip this. An agent holding an
                # agent token must not be able to keep itself enabled.
                supplied = self.headers.get("X-Blindkeep-Token") or ""
                if not secrets.compare_digest(supplied, TOKEN):
                    return self._send(403, {"error": "only the app can change this"})
                AGENT["on"] = bool(body.get("enabled"))
                AGENT["token"] = secrets.token_urlsafe(24) if AGENT["on"] else None
                return self._send(200, {"enabled": AGENT["on"],
                                        "token": AGENT["token"],
                                        "url": f"http://127.0.0.1:{PORT}"})
            if path == "/api/hw/run":
                clean = {
                    "target": body.get("target") if body.get("target") in HW_TARGETS else "haiku",
                    "hardness": body.get("hardness") if body.get("hardness") in
                    ("auto", "easy", "medium", "hard") else "auto",
                    "depth": body.get("depth") if body.get("depth") in HW_DEPTH else "standard",
                    "strictness": body.get("strictness") if body.get("strictness")
                    in HW_STRICT else "balanced"}
                with HW_LOCK:
                    if sum(1 for r in HW_RUNS.values() if not r["done"]) >= 1:
                        return self._send(429, {"error": "a check is already running"})
                    rid = secrets.token_urlsafe(16)
                    HW_RUNS[rid] = {"q": queue.Queue(), "receipt": None,
                                    "done": False}
                threading.Thread(target=hw_run, args=(rid, clean),
                                 daemon=True).start()
                return self._send(200, {"run": rid})
        except Exception as exc:
            if path.startswith("/api/read/"):
                print(f"[blindkeep] read failed: {type(exc).__name__}: {exc}",
                      file=sys.stderr)
                return self._send(404, {"error": "no such record"})
            return self._send(500, safe_error(exc))
        self._send(404, {"error": "not found"})

    def _hw_stream(self, rid):
        with HW_LOCK:
            st = HW_RUNS.get(rid)
        if not st:
            return self._send(404, {"error": "unknown run"})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        while True:
            try:
                ev = st["q"].get(timeout=0.5)
            except queue.Empty:
                if st["done"] and st["q"].empty():
                    return
                try:
                    self.wfile.write(b": ping\n\n"); self.wfile.flush()
                except OSError:
                    return
                continue
            try:
                self.wfile.write(f"data: {json.dumps(ev)}\n\n".encode())
                self.wfile.flush()
            except OSError:
                return


PAGE = r"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Blindkeep</title><style>
/* Same palette as the project dashboard: deep navy ground, cyan brand, blue
   interactive, gold reserved as a minor accent. The first cut of this page was
   gold-on-black throughout and read brown rather than night. */
:root{--ink:#e6edf3;--muted:#7d8794;--line:rgba(255,255,255,.08);
--panel:rgba(18,24,33,.90);--panel2:rgba(15,20,28,.94);
--cyan:#4fd0e0;--accent:#58a6ff;--gold:#e3b341;
--good:#3fb950;--bad:#f85149;--warn:#d29922;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:#0a0e14;color:var(--ink);font-family:var(--sans);
line-height:1.6;overflow-x:hidden}
#sky{position:fixed;inset:0;z-index:0;display:block}
.veil{position:fixed;inset:0;z-index:1;pointer-events:none;
background:radial-gradient(ellipse 120% 80% at 50% -15%,rgba(79,208,224,.13),transparent 62%),
radial-gradient(ellipse 80% 50% at 85% 15%,rgba(88,166,255,.07),transparent 60%),
linear-gradient(180deg,rgba(10,14,20,0) 35%,rgba(10,14,20,.88) 100%)}
.wrap{position:relative;z-index:2;max-width:60rem;margin:0 auto;padding:0 1.5rem 4rem}
header{padding:3rem 0 1.25rem}
.brand{display:flex;align-items:center;gap:1rem}
.brand svg{width:52px;height:52px;flex:none}
h1{margin:0;font-size:1.9rem;letter-spacing:-.02em;font-weight:600;color:var(--cyan)}
.tag{color:var(--muted);font-size:.86rem;font-family:var(--mono);margin-top:.15rem}
.tabs{display:flex;gap:.4rem;margin-top:1.6rem;border-bottom:1px solid var(--line);
flex-wrap:wrap}
.tab{padding:.55rem 1.05rem;border:1px solid transparent;border-bottom:none;
border-radius:.5rem .5rem 0 0;background:none;color:var(--muted);font:inherit;
font-size:.92rem;cursor:pointer;margin-bottom:-1px}
.tab[aria-selected=true]{background:var(--panel);border-color:var(--line);
color:var(--ink);font-weight:600}
.tab:focus-visible,button:focus-visible,select:focus-visible,textarea:focus-visible,
input:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.page{padding:1.75rem 0}.page[hidden]{display:none}
.card{background:var(--panel);border:1px solid var(--line);border-radius:.8rem;
padding:1.3rem 1.4rem;backdrop-filter:blur(9px);margin-bottom:1.1rem;
background-image:linear-gradient(180deg,rgba(88,166,255,.045),transparent 60%)}
h2{margin:0 0 .5rem;font-size:1.1rem}
p.note{color:var(--muted);font-size:.9rem;max-width:56ch;margin:.3rem 0 0}
textarea,input,select{width:100%;background:rgba(0,0,0,.35);color:var(--ink);
border:1px solid var(--line);border-radius:.45rem;padding:.6rem .75rem;
font:inherit;font-size:.95rem}
textarea{min-height:7rem;resize:vertical;font-family:var(--mono);font-size:.9rem}
label{display:block;font-size:.8rem;color:var(--muted);margin:.9rem 0 .3rem}
button.go{margin-top:1rem;padding:.6rem 1.5rem;border-radius:.45rem;border:none;
background:var(--accent);color:#08101c;font:inherit;font-weight:650;cursor:pointer}
button.go[disabled]{opacity:.45;cursor:not-allowed}
button.ghost{padding:.5rem 1rem;border-radius:.45rem;border:1px solid var(--line);
background:transparent;color:var(--ink);font:inherit;font-size:.88rem;cursor:pointer}
.stats{display:grid;gap:.9rem;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));
margin-top:.3rem}
.stat{background:rgba(0,0,0,.28);border:1px solid var(--line);border-radius:.6rem;
padding:.75rem .9rem}
.stat b{display:block;font-family:var(--mono);font-size:1.5rem;color:var(--cyan);
line-height:1.2}
.stat span{font-size:.76rem;color:var(--muted)}
.rec{display:flex;justify-content:space-between;gap:1rem;padding:.55rem .1rem;
border-bottom:1px solid var(--line);font-size:.9rem;cursor:pointer}
.rec:last-child{border-bottom:none}
.rec:hover{color:var(--accent)}
.rec .i{font-family:var(--mono);color:var(--muted);font-size:.8rem}
.mono{font-family:var(--mono);font-size:.8rem;color:var(--muted);word-break:break-all}
.log{margin-top:1rem;border:1px solid var(--line);border-radius:.55rem;
max-height:15rem;overflow:auto;font-family:var(--mono);font-size:.78rem;display:none}
.log div{padding:.3rem .75rem;border-bottom:1px solid var(--line)}
.bar{height:4px;background:rgba(255,255,255,.08);border-radius:3px;margin-top:.8rem;
overflow:hidden}.bar i{display:block;height:100%;width:0;background:var(--cyan);
transition:width .25s}
.res{margin-top:1rem;border-radius:.6rem;padding:1rem 1.15rem;border:1px solid var(--line)}
.grid2{display:grid;gap:1rem;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr))}
ol.steps{counter-reset:s;list-style:none;padding:0;margin:1rem 0 0}
ol.steps li{counter-increment:s;position:relative;padding:0 0 .9rem 2.4rem;
  border-left:1px solid var(--line);margin-left:.7rem;color:var(--muted);font-size:.9rem}
ol.steps li:last-child{border-left-color:transparent;padding-bottom:0}
ol.steps li::before{content:counter(s);position:absolute;left:-.72rem;top:0;
  width:1.44rem;height:1.44rem;border-radius:50%;background:var(--cyan);
  color:#08101c;font-family:var(--mono);font-size:.75rem;font-weight:700;
  display:grid;place-items:center}
ol.steps b{color:var(--ink)}
ul.plain{margin:.9rem 0 0;padding-left:1.1rem}
ul.plain li{margin-bottom:.55rem;color:var(--muted);font-size:.9rem}
ul.plain li::marker{color:var(--cyan)}
ul.plain b{color:var(--ink)}
.warnbox{border-left:3px solid var(--gold);padding:.2rem 0 .2rem .9rem;
color:var(--muted);font-size:.86rem;margin-top:.9rem}

/* Pending-actions bar. Fixed to the bottom because these are the jobs that
   kept getting lost between sessions -- a thing only a human can finish must
   not live only in a chat transcript. */
#todo{position:fixed;left:0;right:0;bottom:0;z-index:20;display:none;
  background:rgba(9,13,20,.97);border-top:1px solid rgba(88,166,255,.45);
  backdrop-filter:blur(10px);box-shadow:0 -8px 28px rgba(0,0,0,.5)}
#todo .row{max-width:60rem;margin:0 auto;padding:.7rem 1.5rem;display:flex;
  align-items:center;gap:1rem;flex-wrap:wrap}
#todo .dot{width:9px;height:9px;border-radius:50%;background:var(--accent);
  flex:none;animation:pulse 1.15s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(88,166,255,.6)}
  50%{opacity:.35;box-shadow:0 0 0 7px rgba(88,166,255,0)}}
#todo .ttl{font-weight:650;font-size:.92rem}
#todo .det{color:var(--muted);font-size:.82rem}
#todo code{font-family:var(--mono);font-size:1.05rem;letter-spacing:.09em;
  color:var(--cyan);background:rgba(79,208,224,.10);padding:.2rem .55rem;
  border-radius:.3rem;border:1px solid rgba(79,208,224,.3)}
#todo .dead code{color:var(--muted);background:rgba(255,255,255,.05);
  border-color:var(--line);text-decoration:line-through}
#todo a.open{margin-left:auto;padding:.42rem 1rem;border-radius:.4rem;
  background:var(--accent);color:#08101c;text-decoration:none;font-weight:650;
  font-size:.86rem}
#todo button.done{padding:.42rem .9rem;border-radius:.4rem;border:1px solid var(--line);
  background:transparent;color:var(--muted);font:inherit;font-size:.82rem;cursor:pointer}
@media(prefers-reduced-motion:reduce){#todo .dot{animation:none}}
body.hastodo{padding-bottom:5.5rem}
</style></head><body>
<canvas id=sky></canvas><div class=veil></div>
<div id=todo><div class=row id=todorow></div></div>
<div class=wrap>
<header>
  <div class=brand>
    <svg viewBox="0 0 96 96" aria-hidden="true">
      <path d="M48 8 L80 19 v28 c0 19-13 32-32 40 C29 79 16 66 16 47 V19 Z"
            fill="none" stroke="#F4B728" stroke-width="4" stroke-linejoin="round"/>
      <path fill-rule="evenodd" fill="#F4B728"
            d="M33 44 h6 v-7 h6 v7 h6 v-7 h6 v7 h6 v26 H33 Z M44 57 h8 v13 h-8 Z"/>
    </svg>
    <div><h1>Blindkeep</h1>
    <div class=tag id=tag>encrypted memory · the node cannot read it</div></div>
  </div>
  <div class=tabs role=tablist>
    <button class=tab id=t-keep role=tab aria-selected=true aria-controls=p-keep>Your keep</button>
    <button class=tab id=t-write role=tab aria-selected=false aria-controls=p-write>Remember</button>
    <button class=tab id=t-proof role=tab aria-selected=false aria-controls=p-proof>Proof</button>
    <button class=tab id=t-hw role=tab aria-selected=false aria-controls=p-hw>Check your AI</button>
    <button class=tab id=t-how role=tab aria-selected=false aria-controls=p-how>How it works</button>
  </div>
</header>

<section class=page id=p-keep role=tabpanel aria-labelledby=t-keep>
  <div class=card>
    <h2>Your keep</h2>
    <div class=stats id=stats></div>
    <p class=note id=keepnote></p>
  </div>
  <div class=card>
    <h2>Memories</h2>
    <p class=note>Stored encrypted. Click one to decrypt it here — the node
    only ever held ciphertext.</p>
    <div id=recs style="margin-top:.8rem">…</div>
    <div id=reader style="display:none;margin-top:1rem;border-top:1px solid var(--line);
         padding-top:1rem"><div class=mono id=readermeta></div>
      <pre id=readertext style="white-space:pre-wrap;font-size:.9rem;margin:.6rem 0 0"></pre></div>
  </div>
</section>

<section class=page id=p-write role=tabpanel aria-labelledby=t-write hidden>
  <div class=card>
    <h2>Remember something</h2>
    <p class=note>This is encrypted on this machine before it leaves. The node
    stores a blob it cannot open, and cannot tell one memory from another.</p>
    <label for=wlabel>A name for it (optional)</label>
    <input id=wlabel placeholder="e.g. bank details, notes on the grant">
    <label for=wtext>What to remember</label>
    <textarea id=wtext placeholder="Type anything. It never leaves in the clear."></textarea>
    <button class=go id=wgo>Encrypt and save</button>
    <div id=wres style="margin-top:.9rem"></div>
  </div>
</section>

<section class=page id=p-proof role=tabpanel aria-labelledby=t-proof hidden>
  <div class=card>
    <h2>Proof the keep has not been rewritten</h2>
    <p class=note>Every memory is appended to a log with a signed head. If the
    node ever silently dropped or altered a record, the head would not match
    and this client would refuse it. That check runs on every read.</p>
    <div class=stats id=proofstats style="margin-top:1rem"></div>
    <label>Current root</label><div class=mono id=root>…</div>
  </div>

  <div class=card>
    <h2>Your master key</h2>
    <p class=note>This one file is the only thing that can decrypt anything in
    your keep. <b style="color:var(--ink)">Lose it and every memory here is
    gone. Leak it and every memory here is readable.</b> Nobody can reset it —
    that is what makes the node unable to read your data.</p>
    <label>Where it lives</label>
    <div class=mono id=keypath>data/master.key</div>
    <button class=ghost id=keyshow style="margin-top:.9rem">Show me the key</button>
    <div id=keybox style="display:none;margin-top:.9rem">
      <div class=mono id=keyhex style="padding:.7rem .8rem;border:1px solid var(--line);
           border-radius:.45rem;background:rgba(0,0,0,.35);color:var(--gold)"></div>
      <button class=ghost id=keycopy style="margin-top:.6rem">Copy</button>
      <button class=ghost id=keyhide style="margin-top:.6rem">Hide</button>
      <div class=warnbox>Write this down somewhere offline, or copy the file to
      a USB stick or password manager. Anyone who has it can read your keep, so
      do not paste it into a chat, an email, or a cloud note.</div>
    </div>
  </div>

  <div class=card>
    <h2>Let an AI agent use your keep</h2>
    <p class=note>Off by default. Switched on, an agent can save and read
    memories through a token of its own — it never sees your master key and
    cannot turn this back on once you turn it off. Everything it writes is
    encrypted the same way.</p>
    <button class=go id=agenttoggle style="margin-top:.8rem">Turn on agent access</button>
    <div id=agentbox style="display:none;margin-top:1rem">
      <label>Endpoint</label><div class=mono id=agenturl></div>
      <label>Agent token</label><div class=mono id=agenttok
        style="padding:.6rem .7rem;border:1px solid var(--line);border-radius:.45rem;
        background:rgba(0,0,0,.35);color:var(--cyan)"></div>
      <label>How an agent uses it</label>
      <pre class=mono id=agentex style="white-space:pre-wrap;font-size:.76rem;
        background:rgba(0,0,0,.3);border:1px solid var(--line);border-radius:.45rem;
        padding:.7rem .8rem;overflow-x:auto"></pre>
      <div class=warnbox>The token reaches <b style="color:var(--ink)">only</b>
      saving and reading memories. It cannot fetch your master key and cannot
      change this switch. It dies when you turn this off or close the app.</div>
    </div>
  </div>
</section>

<section class=page id=p-how role=tabpanel aria-labelledby=t-how hidden>
  <div class=card>
    <h2>The problem</h2>
    <p class=note>AI assistants get more useful the more they remember about
    you. But "remembering" normally means a company holds your notes, your
    health, your finances, in a form its staff and its servers can read. You
    are asked to trade privacy for usefulness.</p>
    <p class=note style="margin-top:.7rem">Blindkeep refuses the trade. The
    thing that stores your memory <b style="color:var(--ink)">cannot read
    it</b> — not because it promises not to, but because it never has the key.</p>
  </div>

  <div class=card>
    <h2>What happens when you save something</h2>
    <ol class=steps>
      <li><b>It is encrypted on this machine.</b> Before anything leaves, your
      text is sealed with a key held only here. The storage node receives a
      blob it has no way to open.</li>
      <li><b>It is appended to a tamper-evident log.</b> Each entry is hashed
      into a structure where changing any past entry changes the root — so a
      node that quietly edits or drops your history cannot hide it.</li>
      <li><b>The node signs the new root.</b> That signature is your receipt
      that the log is in a particular state.</li>
      <li><b>Your client remembers that root.</b> Next time you read, it checks
      the node's answer against what it saw last time. A node that rewrites
      history gets caught by your own copy, not by trusting a third party.</li>
    </ol>
  </div>

  <div class=card>
    <h2>What happens when you read it back</h2>
    <ol class=steps>
      <li><b>The node returns ciphertext plus a proof</b> that this exact entry
      belongs in the log whose root it signed.</li>
      <li><b>Your client verifies the proof</b> and checks the root is
      consistent with the one it pinned earlier. If either fails it refuses the
      answer rather than showing you something unverified.</li>
      <li><b>Only then is it decrypted</b>, here, with your key.</li>
    </ol>
    <p class=note style="margin-top:.8rem">This is why "Proof" is a tab and not
    a footnote. The claim is not <i>trust us</i> — it is <i>check us</i>.</p>
  </div>

  <div class=card>
    <h2>Your master key</h2>
    <p class=note>One file on this machine. It is the only thing that can
    decrypt your keep. Nobody — not us, not a node operator — can reset it or
    recover it for you, and that limitation is the feature: an operator who
    could recover your data could also read it.</p>
    <p class=note style="margin-top:.7rem"><b style="color:var(--ink)">Back it
    up before you store anything you would miss.</b> The Proof tab shows it and
    lets you copy it.</p>
  </div>

  <div class=card>
    <h2>What it does not do</h2>
    <ul class=plain>
      <li><b>It does not protect a compromised machine.</b> If something is
      already running on your computer with your permissions, it can read your
      key. No storage design fixes that.</li>
      <li><b>It does not hide that you are using it.</b> Hiding <i>which</i>
      record you read costs a scan of the whole keep; hiding <i>who is asking</i>
      needs the oblivious path and two independently operated relays.</li>
      <li><b>It is not anonymity by default.</b> If you send a question straight
      to a cloud AI, that provider's API key identifies your account — no
      amount of local encryption changes it.</li>
      <li><b>Replication is opt-in.</b> By default your keep lives on your own
      node, on this machine. Nobody else holds a copy unless you set that up.</li>
    </ul>
  </div>

  <div class=card>
    <h2>And the other tab</h2>
    <p class=note><b style="color:var(--ink)">Check your AI</b> answers a
    different question. Blindkeep asks <i>can I stop you reading my data?</i>
    That tab asks <i>did you do the work I paid for?</i> — whether a provider
    is quietly spending less computation than you are billed for. Same posture
    toward a company you cannot audit; different object.</p>
  </div>
</section>

<section class=page id=p-hw role=tabpanel aria-labelledby=t-hw hidden>
  <div class=card>
    <h2>Is your AI doing the work you pay for?</h2>
    <p class=note>A provider can serve the model you asked for while quietly
    spending less computation on it. Answers still look fine; the bill does not
    change. This asks questions that cannot be answered without doing the work.
    <b style="color:var(--ink)">This is not privacy</b> — that is the rest of
    Blindkeep. This checks whether the work was done.</p>
    <div id=hwmissing class=mono style="display:none;color:var(--warn);margin-top:.8rem"></div>
    <div class=grid2 id=hwform style="margin-top:1.1rem">
      <div><label for=hw-target>Which AI are you checking?</label>
        <select id=hw-target>
          <option value=haiku>Claude Haiku 4.5 — fast and cheap</option>
          <option value=sonnet>Claude Sonnet 5</option>
          <option value=opus>Claude Opus 5 — top tier</option>
          <option value=gpt5>OpenAI GPT-5</option>
          <option value=local>A model on this machine</option>
        </select></div>
      <div><label for=hw-hardness>How hard should the questions be?</label>
        <select id=hw-hardness><option value=auto>Match the model automatically</option>
        <option value=easy>Easy</option><option value=medium>Medium</option>
        <option value=hard>Hard</option></select></div>
      <div><label for=hw-depth>How thorough?</label>
        <select id=hw-depth><option value=quick>Quick — about 20 questions</option>
        <option value=standard selected>Standard — about 60</option>
        <option value=thorough>Thorough — about 150</option></select></div>
      <div><label for=hw-strictness>How sure before accusing?</label>
        <select id=hw-strictness><option value=balanced selected>Balanced — 1 false alarm in 100</option>
        <option value=cautious>Cautious — 1 in 1,000</option></select></div>
    </div>
    <button class=go id=hwgo>Check it</button>
    <button class=ghost id=hwsave style="display:none;margin-left:.5rem">Download receipt</button>
    <div class=bar><i id=hwbar></i></div>
    <div id=hwres></div>
    <div class=log id=hwlog></div>
  </div>
</section>
</div>
<script>
const TOKEN = "__TOKEN__";
const $ = id => document.getElementById(id);
const esc = s => String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

/* esc() blocks breaking OUT of an attribute, but a scheme needs no special
   characters: href="javascript:..." survives escaping untouched, and clicking
   it runs in this page's context -- which holds the token that reaches the
   master key. So any URL coming from data gets its scheme checked, not just
   its characters. Anything not plainly http(s) becomes an inert '#'. */
const safeUrl = u => /^https?:\/\/[^\s"'<>]+$/i.test(String(u||'')) ? String(u) : '#';
const api = (p,o={}) => fetch(p,{...o,headers:{'X-Blindkeep-Token':TOKEN,
  ...(o.body?{'Content-Type':'application/json'}:{})}});

/* night sky: a slow drift of stars, drawn once per frame on a canvas so it
   costs nothing and never fights the text for attention. */
const cv=$('sky'), cx=cv.getContext('2d');
let stars=[], meteors=[];
function seed(){
  cv.width=innerWidth; cv.height=innerHeight;
  const n=Math.round(innerWidth*innerHeight/8000);
  stars=Array.from({length:n},()=>({x:Math.random()*cv.width,y:Math.random()*cv.height,
    r:Math.random()*1.3+.25,a:Math.random()*.6+.15,
    tw:Math.random()*.012+.003,d:Math.random()*Math.PI*2,
    v:Math.random()*.03+.006}));
}
seed(); addEventListener('resize',seed);
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;

// Meteors: a slanted streak with a fading tail, launched at random from the
// top edge. Rare enough to feel like weather rather than decoration.
function launch(){
  meteors.push({x:Math.random()*cv.width*1.2-cv.width*.1, y:-40,
    len:Math.random()*140+90, sp:Math.random()*7+6,
    ang:Math.PI/4 + (Math.random()*.18-.09), life:1});
}
function draw(t){
  cx.clearRect(0,0,cv.width,cv.height);
  for(const s of stars){
    const a = reduce ? s.a : s.a + Math.sin(t*s.tw + s.d)*.28;
    cx.globalAlpha=Math.max(.05,Math.min(1,a));
    // A few warm ones keep the gold in the mark from feeling unrelated.
    cx.fillStyle = s.r>1.2 ? '#e3b341' : (s.r>.8 ? '#9fd8e6' : '#dbe6f7');
    cx.beginPath(); cx.arc(s.x,s.y,s.r,0,6.283); cx.fill();
    if(!reduce){ s.y+=s.v; if(s.y>cv.height){ s.y=-2; s.x=Math.random()*cv.width; } }
  }
  if(!reduce){
    if(Math.random()<0.012) launch();
    for(const m of meteors){
      const dx=Math.cos(m.ang)*m.len, dy=Math.sin(m.ang)*m.len;
      const g=cx.createLinearGradient(m.x,m.y,m.x-dx,m.y-dy);
      g.addColorStop(0,`rgba(180,232,255,${.85*m.life})`);
      g.addColorStop(.35,`rgba(88,166,255,${.35*m.life})`);
      g.addColorStop(1,'rgba(88,166,255,0)');
      cx.globalAlpha=1; cx.strokeStyle=g; cx.lineWidth=1.7; cx.lineCap='round';
      cx.beginPath(); cx.moveTo(m.x,m.y); cx.lineTo(m.x-dx,m.y-dy); cx.stroke();
      m.x+=Math.cos(m.ang)*m.sp; m.y+=Math.sin(m.ang)*m.sp;
      if(m.y>cv.height*.75) m.life-=0.02;
    }
    meteors=meteors.filter(m=>m.life>0 && m.y<cv.height+120);
  }
  cx.globalAlpha=1; requestAnimationFrame(draw);
}
requestAnimationFrame(draw);

const tabs=[...document.querySelectorAll('.tab')];
tabs.forEach(t=>t.onclick=()=>tabs.forEach(o=>{const on=o===t;
  o.setAttribute('aria-selected',on); $(o.getAttribute('aria-controls')).hidden=!on;}));

async function refresh(){
  let s;
  try { s = await (await api('/api/state')).json(); }
  catch(e){ $('tag').textContent='could not reach the app'; return; }
  if(!s.node){ $('tag').textContent='node did not start: '+esc(s.why||''); return; }
  $('tag').textContent = 'encrypted memory · the node cannot read it';
  $('stats').innerHTML =
    `<div class=stat><b>${s.records}</b><span>memories kept</span></div>
     <div class=stat><b>${s.tree_size??'—'}</b><span>entries in the log</span></div>
     <div class=stat><b>${s.key_exists?'yes':'no'}</b><span>master key present</span></div>`;
  $('proofstats').innerHTML = $('stats').innerHTML;
  $('root').textContent = s.root || '—';
  $('keepnote').textContent = s.records
    ? 'Everything below was encrypted here before the node saw it.'
    : 'Nothing kept yet. Open Remember and write your first memory.';
  $('recs').innerHTML = s.list.length
    ? s.list.map((r,i)=>`<div class=rec data-i="${r.index??i}">
        <span>${esc(r.label||'(no name)')}</span>
        <span class=i>#${r.index??i}</span></div>`).reverse().join('')
    : '<span class=note>nothing yet</span>';
  document.querySelectorAll('.rec').forEach(el=>el.onclick=async()=>{
    const r = await (await api('/api/read/'+el.dataset.i)).json();
    $('reader').style.display='block';
    if(r.error){ $('readertext').textContent='could not open: '+r.error; return; }
    $('readermeta').textContent = 'record #'+el.dataset.i+' · decrypted here, not on the node';
    $('readertext').textContent = r.text;
  });
  if(!s.heartwood){ $('hwform').style.display='none'; $('hwgo').style.display='none';
    $('hwmissing').style.display='block';
    $('hwmissing').textContent='Heartwood not available: '+esc(s.heartwood_error||''); }
}
refresh();

$('wgo').onclick=async()=>{
  const text=$('wtext').value.trim(); if(!text) return;
  $('wgo').disabled=true;
  const r=await (await api('/api/write',{method:'POST',
    body:JSON.stringify({text,label:$('wlabel').value})})).json();
  $('wgo').disabled=false;
  $('wres').innerHTML = r.ok
    ? `<div class=res style="border-color:var(--good)"><b style="color:var(--good)">Kept.</b>
       <div class=mono style="margin-top:.4rem">encrypted here · the node stored a blob it cannot read</div></div>`
    : `<div class=res style="border-color:var(--bad)"><b style="color:var(--bad)">Failed.</b>
       <div class=mono>${esc(r.error||'')}</div></div>`;
  if(r.ok){ $('wtext').value=''; $('wlabel').value=''; refresh(); }
};

$('keyshow').onclick=async()=>{
  const r=await (await api('/api/key')).json();
  if(r.error){ $('keyhex').textContent=r.error; }
  else { $('keyhex').textContent=r.hex; $('keypath').textContent=r.path; }
  $('keybox').style.display='block'; $('keyshow').style.display='none';
};
$('keyhide').onclick=()=>{ $('keybox').style.display='none';
  $('keyhex').textContent=''; $('keyshow').style.display='inline-block'; };
$('keycopy').onclick=async()=>{
  try{ await navigator.clipboard.writeText($('keyhex').textContent);
       $('keycopy').textContent='Copied'; setTimeout(()=>$('keycopy').textContent='Copy',1500); }
  catch(e){ $('keycopy').textContent='select it manually'; }
};

async function agentPaint(a){
  const on=a.enabled;
  $('agenttoggle').textContent = on ? 'Turn off agent access' : 'Turn on agent access';
  $('agentbox').style.display = on ? 'block' : 'none';
  if(!on) return;
  $('agenturl').textContent = a.url;
  $('agenttok').textContent = a.token;
  $('agentex').textContent =
`# save a memory
curl -s ${a.url}/api/write \\
  -H "X-Blindkeep-Token: ${a.token}" \\
  -H "Content-Type: application/json" \\
  -d '{"text":"remember this","label":"note"}'

# read memory #0 back
curl -s "${a.url}/api/read/0" -H "X-Blindkeep-Token: ${a.token}"`;
}
$('agenttoggle').onclick=async()=>{
  const cur=$('agentbox').style.display==='block';
  const a=await (await api('/api/agent',{method:'POST',
    body:JSON.stringify({enabled:!cur})})).json();
  agentPaint(a);
};
api('/api/agent').then(r=>r.json()).then(agentPaint).catch(()=>{});

/* Pending actions. Polled rather than rendered once, so a code that expires
   while the page is open turns dead on screen instead of lying. */
let todoIdx = 0;
async function todoPaint(){
  let d;
  try { d = await (await api('/api/pending')).json(); } catch(e){ return; }
  const live = (d.items||[]).filter(i=>!i.dismissed);
  const bar = $('todo');
  if(!live.length){ bar.style.display='none'; document.body.classList.remove('hastodo'); return; }
  bar.style.display='block'; document.body.classList.add('hastodo');
  const it = live[todoIdx % live.length];
  const dead = it.expired;
  const mins = it.left!=null ? Math.ceil(it.left/60) : null;
  $('todorow').innerHTML =
    `<span class=dot></span>
     <span>
       <span class=ttl>${esc(it.title)}</span>
       ${live.length>1?`<span class=det> · ${todoIdx%live.length+1} of ${live.length}</span>`:''}
       <br><span class=det>${esc(it.detail)}${
         dead ? ' <b style="color:var(--warn)">This code has expired — ask for a new one.</b>'
              : (mins!=null ? ` <b style="color:var(--cyan)">~${mins} min left</b>` : '')}</span>
     </span>
     <span class="${dead?'dead':''}"><code>${esc(it.code||'')}</code></span>
     <a class=open href="${esc(safeUrl(it.url))}" target=_blank rel=noopener>Open</a>
     <button class=done data-id="${esc(it.id)}">Done</button>`;
  $('todorow').querySelector('.done').onclick = e => {
    it.dismissed = true;
    const all = d.items.filter(x=>x.id!==e.target.dataset.id);
    if(!all.length){ $('todo').style.display='none';
      document.body.classList.remove('hastodo'); return; }
    d.items = all; todoIdx = 0; todoPaint();
  };
  if(live.length>1) todoIdx++;
}
todoPaint(); setInterval(todoPaint, 8000);

let hwRun=null;
function hwLine(t,c){const b=$('hwlog');b.style.display='block';
  const d=document.createElement('div');if(c)d.style.color=c;d.textContent=t;
  b.appendChild(d);b.scrollTop=b.scrollHeight;}
$('hwgo').onclick=async()=>{
  const g=$('hwgo'); g.disabled=true; g.textContent='Checking…';
  $('hwlog').innerHTML=''; $('hwres').innerHTML=''; $('hwbar').style.width='0';
  $('hwsave').style.display='none';
  const res=await api('/api/hw/run',{method:'POST',body:JSON.stringify({
    target:$('hw-target').value,hardness:$('hw-hardness').value,
    depth:$('hw-depth').value,strictness:$('hw-strictness').value})});
  if(!res.ok){ hwLine((await res.json()).error||'refused','var(--bad)');
    g.disabled=false; g.textContent='Check it'; return; }
  hwRun=(await res.json()).run;
  const es=new EventSource('/api/hw/events/'+hwRun+'?t='+encodeURIComponent(TOKEN));
  es.onmessage=e=>{const d=JSON.parse(e.data);
    if(d.stage==='query'){ $('hwbar').style.width=d.pct+'%';
      hwLine(`question ${d.n}/${d.of} — ${d.graded?'answered correctly':'GOT IT WRONG'}  (${Math.round(d.rate*100)}% right)`,
        d.graded?'var(--good)':'var(--bad)');
    } else if(d.stage==='warn'){ hwLine(d.msg,'var(--warn)');
    } else if(d.stage==='error'){ hwLine(d.msg,'var(--bad)'); es.close();
      g.disabled=false; g.textContent='Check it';
    } else if(d.stage==='done'){ es.close(); g.disabled=false;
      g.textContent='Check it'; hwDone(d);
    } else hwLine(d.msg);};
  es.onerror=()=>{es.close(); g.disabled=false; g.textContent='Check it';};
};
function hwDone(d){
  const hit=d.verdict==='EFFORT_DEFICIT';
  $('hwbar').style.width='100%';
  $('hwres').innerHTML=`<div class=res style="border-color:${hit?'var(--bad)':'var(--good)'}">
    <b style="color:${hit?'var(--bad)':'var(--good)'};font-size:1.05rem">
    ${hit?'Evidence that '+esc(d.model)+' is being throttled'
         :'Nothing found against '+esc(d.model)}</b>
    <p class=note style="margin-top:.4rem">${hit
      ? `It answered ${Math.round(d.rate*100)}% of ${d.queries} questions correctly — worse than an honest endpoint plausibly would.`
      : `It answered ${Math.round(d.rate*100)}% of ${d.queries} correctly. This is <b>not</b> proof it is honest — only that nothing was shown within the questions asked.`}
      <br>Receipt ${d.valid?'valid':'INVALID'} · randomness ${d.anchored===true?'confirmed against the public chain':'NOT confirmed'}.</p></div>`;
  const s=$('hwsave'); s.style.display='inline-block';
  s.onclick=()=>{location.href='/api/hw/receipt/'+hwRun+'?t='+encodeURIComponent(TOKEN);};
}
</script></body></html>"""


def main():
    # A Windows console is cp1252 by default, so a single arrow in a print()
    # kills the process before it ever binds. This repo already solved that
    # once; dashboard.py calls the same helper on its first line.
    try:
        from blindkeep._console import use_utf8_stdout
        use_utf8_stdout()
    except Exception:
        pass

    ok, how = ensure_node()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    url = f"http://127.0.0.1:{PORT}"
    print(f"Blindkeep -> {url}")
    print(f"  node: {'up (' + how + ')' if ok else 'FAILED: ' + how}")
    print("  bound to localhost only. Ctrl-C to stop.")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
