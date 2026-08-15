"""Oblivio — the app. Encrypted memory you can prove things about.

    python app.py          →  http://127.0.0.1:8743

This is the PRODUCT surface, not the maintainer dashboard. dashboard.py reports
on the repository — tests, roadmap, todos. This is what someone who uses
Oblivio actually touches: write a memory, read it back, prove the keep has
not been rewritten behind your back.

It starts a local node if one is not already listening, creates a master key on
first run, and never sends either anywhere. Everything is encrypted on this
machine before it reaches the node, which is the whole point: the node stores
ciphertext and cannot read it.

Stdlib only.
"""
import io
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
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

PORT = 8743
NODE_PORT = 8741
NODE_URL = f"http://127.0.0.1:{NODE_PORT}"
# Legacy plaintext path — migrated away on first unlock/setup. Agents with
# filesystem access could read it; sealed-at-rest is the default now.
KEY_PATH = HERE / "data" / "master.key"
KEY_SEALED_PATH = HERE / "data" / "master.key.sealed"
PIN_PATH = HERE / "data" / "pin.json"
# Written when a sealed backup zip has been exported (or setup completed).
KEY_ACK_PATH = HERE / "data" / "key_backup.ack"

# An app that holds a master key must not be drivable by a page you happen to
# be visiting. Localhost is not a security boundary against the browser: a
# simple cross-origin POST skips CORS preflight entirely. Minted per launch,
# injected into the page this server serves, required on every route that
# touches the keep.
TOKEN = secrets.token_urlsafe(32)

HW_RUNS: dict = {}
HW_LOCK = threading.Lock()

# Working master key lives in process memory only after unlock/setup.
# Never written to disk as plaintext once sealed-at-rest is in use.
SESSION_KEY: bytes | None = None
KEY_JUST_CREATED = False

# Agent access. An AI agent cannot read the page, so it cannot learn the
# session token -- it needs one of its own. Off by default and minted only when
# switched on, because handing an agent a key to your memory is a decision, not
# a default. Turning it off invalidates the token immediately.
#
# `tier` is what the agent is TREATED as, and it is a declaration rather than a
# proof: from inside this process a local script and a frontier model behind a
# relay are both just something holding a token. It starts at the weakest tier
# and the page says plainly that Oblivio cannot verify it.
AGENT = {"on": False, "token": None, "tier": 0}

# The switch above is reversible; this list is not. Turning agent access off
# kills the token instantly and stops the next read, but it cannot reach into a
# model's context or a provider's logs and unsee what already left. Recorded so
# "turn it off" is an informed decision instead of a feeling of safety.
AGENT_READS: list = []
READS_LIMIT = 200

# Release policy: Sensitivity -> Tier, seeded from the engine's own defaults.
# NOT a second encryption. Everything in the keep is sealed under the one master
# key, and the holder of that key reads all of it. This decides only what may be
# handed to an AI, which is a different question from what is readable at all.
POLICY: dict = {}
POLICY_PATH = HERE / "data" / "policy.json"

# The node stores an empty label (see client.put_ciphertext), so a listing that
# came back from it carries nothing a person could recognise. This file is how
# the keep shows names and classes without a decrypt round-trip per row.
#
# DISPLAY ONLY, never the authority for a release decision: it is plaintext on
# disk and so editable by anything running as this user, which is exactly why
# the read route takes the class from the decrypted label instead.
CAT_PATH = HERE / "data" / "catalogue.json"


def gate_mod():
    """Imported lazily, like the client, so a broken package still renders."""
    from oblivio import memory_gate
    return memory_gate


def _read_json(path, default):
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        return d if isinstance(d, type(default)) else default
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def _write_json_locked(path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    lock_down(path)


def load_policy() -> dict:
    """Sensitivity label -> Tier value, as ints, ready for JSON."""
    m = gate_mod()
    if not POLICY:
        POLICY.update({s.label: t.value for s, t in m.DEFAULT_POLICY.items()})
        for k, v in _read_json(POLICY_PATH, {}).items():
            if k in POLICY and isinstance(v, int) and 0 <= v <= int(max(m.Tier)):
                POLICY[k] = v
        # SECRET is pinned to LOCAL and the page does not offer to move it:
        # "the operator cannot read it" is still a claim about somebody else's
        # hardware, so the top class never leaves this machine at all.
        POLICY["secret"] = int(m.Tier.LOCAL)
    return dict(POLICY)


def load_catalogue() -> list:
    return _read_json(CAT_PATH, [])


def add_to_catalogue(entries: list) -> None:
    cat = load_catalogue()
    cat.extend(entries)
    _write_json_locked(CAT_PATH, cat[-2000:])


def catalogue_entry(res: dict, label: str, sens_label: str) -> dict:
    return {"index": res.get("index"), "record_id": res.get("record_id"),
            "label": label[:120], "sensitivity": sens_label,
            "at": int(time.time())}

# Heartwood is a sibling project (throttle / effort proof). Not vendored — one
# protocol copy — but treated as a first-class Oblivio tab: we search common
# install locations and can clone the official repo on request.
HEARTWOOD_REPO = "https://github.com/zcashsensei/heartwood.git"
_HEARTWOOD_CACHED: pathlib.Path | None = None

HW_TARGETS = {"haiku": ("anthropic", "claude-haiku-4-5", 3),
              "sonnet": ("anthropic", "claude-sonnet-5", 4),
              "opus": ("anthropic", "claude-opus-5", 5),
              "gpt5": ("openai", "gpt-5", 5),
              "local": ("ollama", "gemma:2b", 1)}
HW_DEPTH = {"quick": (12, 20), "standard": (20, 60), "thorough": (40, 150)}
HW_STRICT = {"balanced": (0.01, 0.40), "cautious": (0.001, 0.50)}


def heartwood_candidates() -> list[pathlib.Path]:
    env = os.environ.get("HEARTWOOD_DIR", "").strip()
    out: list[pathlib.Path] = []
    if env:
        out.append(pathlib.Path(env))
    out.extend([
        HERE.parent / "heartwood",
        HERE / "vendor" / "heartwood",
        HERE / "third_party" / "heartwood",
        pathlib.Path.home() / "heartwood",
        pathlib.Path.home() / "src" / "heartwood",
    ])
    # de-dupe while preserving order
    seen: set[str] = set()
    uniq: list[pathlib.Path] = []
    for p in out:
        k = str(p.resolve()) if p.exists() else str(p)
        if k not in seen:
            seen.add(k)
            uniq.append(p)
    return uniq


def resolve_heartwood_dir() -> pathlib.Path | None:
    global _HEARTWOOD_CACHED
    if _HEARTWOOD_CACHED and (_HEARTWOOD_CACHED / "heartwood.py").is_file():
        return _HEARTWOOD_CACHED
    for p in heartwood_candidates():
        if (p / "heartwood.py").is_file():
            _HEARTWOOD_CACHED = p
            return p
    return None


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
    subprocess.Popen([sys.executable, "-m", "oblivio", "node",
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
    print(f"[oblivio] {type(exc).__name__}: {exc}", file=sys.stderr)
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
                           capture_output=True, check=False, timeout=15,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        else:
            os.chmod(path, 0o600)
    except Exception as exc:                                 # pragma: no cover
        print(f"[oblivio] could not tighten permissions on {path.name}: "
              f"{type(exc).__name__}", file=sys.stderr)


class KeyLocked(Exception):
    """Sealed key on disk, not yet unlocked into this process."""


def key_backed_up() -> bool:
    return KEY_ACK_PATH.is_file()


def key_sealed_at_rest() -> bool:
    return KEY_SEALED_PATH.is_file()


def key_material_exists() -> bool:
    return key_sealed_at_rest() or KEY_PATH.is_file() or SESSION_KEY is not None


def session_unlocked() -> bool:
    return SESSION_KEY is not None


def privacy_snapshot() -> dict:
    """What a stranger should be able to see at a glance about this session."""
    return {
        "bound": "loopback",                 # 127.0.0.1 only — never the LAN
        "encrypted_on_device": True,
        "key_stays_local": True,
        "key_in_memory_only": session_unlocked() and not KEY_PATH.is_file(),
        "key_sealed_at_rest": key_sealed_at_rest(),
        "unlocked": session_unlocked(),
        "key_backed_up": key_backed_up(),
        "key_just_created": KEY_JUST_CREATED and not key_backed_up(),
        "agent_access": bool(AGENT["on"]),
        "sends_data_out": False,             # this app never phones home
        "backup_format": "passphrase-sealed zip",
        # Storage privacy is not frontier-model privacy — stated in the rail.
        "frontier_private_by_default": False,
    }


# Minimum length for the passphrase that seals at rest and backup zips.
_MIN_BACKUP_PASSPHRASE = 10

_SEAL_AAD = b"oblivio-key-backup-v1"
_SEAL_MAGIC = b"BK1\0"


def seal_payload(raw_key: bytes, passphrase: str) -> bytes:
    """Scrypt + AES-GCM wrap of the 32-byte master key."""
    if not isinstance(passphrase, str) or len(passphrase) < _MIN_BACKUP_PASSPHRASE:
        raise ValueError(
            f"choose a passphrase of at least {_MIN_BACKUP_PASSPHRASE} characters")
    if len(raw_key) != 32:
        raise ValueError("master key must be 32 bytes")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    wrap = kdf.derive(passphrase.encode("utf-8"))
    nonce = os.urandom(12)
    sealed = AESGCM(wrap).encrypt(nonce, raw_key, _SEAL_AAD)
    return _SEAL_MAGIC + salt + nonce + sealed


def open_payload(payload: bytes, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    if not payload.startswith(_SEAL_MAGIC):
        raise ValueError("not a Oblivio sealed key")
    body = payload[len(_SEAL_MAGIC):]
    salt, nonce, sealed = body[:16], body[16:28], body[28:]
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    wrap = kdf.derive(passphrase.encode("utf-8"))
    return AESGCM(wrap).decrypt(nonce, sealed, _SEAL_AAD)


def seal_master_key_zip(raw_key: bytes, passphrase: str) -> bytes:
    """Portable backup zip: ciphertext + README. Useless without passphrase."""
    payload = seal_payload(raw_key, passphrase)
    readme = (
        "Oblivio master-key backup\n"
        "===========================\n\n"
        "This zip does NOT contain a readable master key.\n"
        "master.key.sealed is encrypted with the passphrase you chose.\n"
        "Without that passphrase the file is useless to agents, APIs, and\n"
        "anyone who finds the download.\n\n"
        "Restore into the app: place master.key.sealed under data/ and unlock\n"
        "with the same passphrase, or:\n"
        "  python -c \"from app import open_master_key_zip; "
        "open('data/master.key.sealed','wb').write("
        "open_master_key_zip(open('oblivio-master-key.zip','rb').read(),"
        "'YOUR_PASSPHRASE') and b'')\"\n\n"
        "Never put the passphrase in a chat, email, or agent prompt.\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.txt", readme)
        zf.writestr("master.key.sealed", payload)
    return buf.getvalue()


def open_master_key_zip(zip_bytes: bytes, passphrase: str) -> bytes:
    """Inverse of seal_master_key_zip."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        return open_payload(zf.read("master.key.sealed"), passphrase)


def seal_at_rest(passphrase: str) -> None:
    """Write sealed key to disk and remove any legacy plaintext master.key."""
    global SESSION_KEY
    if SESSION_KEY is None:
        raise ValueError("nothing to seal — unlock or create a key first")
    KEY_SEALED_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = seal_payload(SESSION_KEY, passphrase)
    KEY_SEALED_PATH.write_bytes(payload)
    lock_down(KEY_SEALED_PATH)
    if KEY_PATH.is_file():
        try:
            KEY_PATH.unlink()
        except OSError as exc:
            print(f"[oblivio] could not remove plaintext key: {exc}",
                  file=sys.stderr)


def unlock_session(passphrase: str) -> None:
    """Load master key into memory from sealed file (or migrate legacy)."""
    global SESSION_KEY, KEY_JUST_CREATED
    if KEY_SEALED_PATH.is_file():
        try:
            SESSION_KEY = open_payload(KEY_SEALED_PATH.read_bytes(), passphrase)
        except Exception as exc:
            # AES-GCM InvalidTag is the normal "wrong password" path.
            raise ValueError(
                "Wrong passphrase. This keep was sealed earlier with a different "
                "one — you cannot set a new passphrase without unlocking first. "
                "If you forgot it, use Start over (you will lose access to any "
                "memories encrypted under the old key)."
            ) from exc
        return
    if KEY_PATH.is_file():
        # Legacy plaintext: load, seal under this passphrase, delete plaintext.
        SESSION_KEY = KEY_PATH.read_bytes()
        if len(SESSION_KEY) != 32:
            raise ValueError("legacy master.key has unexpected length")
        seal_at_rest(passphrase)
        return
    # First-time setup: mint in memory, seal at rest.
    from oblivio.crypto import generate_master_key
    SESSION_KEY = generate_master_key()
    KEY_JUST_CREATED = True
    seal_at_rest(passphrase)


def reset_local_key_material() -> None:
    """Wipe sealed key + ack so a new passphrase can be chosen.

    Does not delete keep ciphertext; those records become unreadable without
    the old key — that is intentional and stated in the UI.
    """
    global SESSION_KEY, KEY_JUST_CREATED
    SESSION_KEY = None
    KEY_JUST_CREATED = False
    for p in (KEY_SEALED_PATH, KEY_PATH, KEY_ACK_PATH):
        try:
            if p.is_file():
                p.unlink()
        except OSError as exc:
            print(f"[oblivio] could not remove {p.name}: {exc}", file=sys.stderr)


def ensure_session_key() -> bytes:
    """Return the in-memory key, minting once, or refuse if sealed and locked."""
    global SESSION_KEY, KEY_JUST_CREATED
    if SESSION_KEY is not None:
        return SESSION_KEY
    if KEY_SEALED_PATH.is_file():
        raise KeyLocked(
            "master key is sealed on disk — unlock with your passphrase")
    if KEY_PATH.is_file():
        # Legacy: still readable on disk until the next unlock migrates it.
        SESSION_KEY = KEY_PATH.read_bytes()
        return SESSION_KEY
    from oblivio.crypto import generate_master_key
    SESSION_KEY = generate_master_key()
    KEY_JUST_CREATED = True
    return SESSION_KEY


def client(need_key: bool = True):
    from oblivio.client import OblivioClient
    key = b""
    if need_key:
        key = ensure_session_key()
    return OblivioClient(NODE_URL, key, pin_path=str(PIN_PATH))


def _require_session_token(handler: "Handler") -> bool:
    """Key material is never reachable with an agent token — only the page token."""
    tok = handler.headers.get("X-Oblivio-Token") or ""
    if not tok and "?" in handler.path:
        from urllib.parse import parse_qs
        tok = (parse_qs(handler.path.split("?", 1)[1]).get("t") or [""])[0]
    return bool(tok) and len(tok) == len(TOKEN) and secrets.compare_digest(
        tok, TOKEN)


# ------------------------------------------------------------- heartwood ----

def heartwood_modules():
    """Load Heartwood from a discovered install. Not vendored into this tree."""
    hw_dir = resolve_heartwood_dir()
    if hw_dir is None:
        return None, (
            "Heartwood is not installed yet.\n\n"
            "It is the throttle / effort-proof engine for this tab — kept as a "
            "separate repo so the protocol has one source of truth.\n\n"
            "Click Install Heartwood below, or run:\n\n"
            f"    git clone {HEARTWOOD_REPO} {HERE.parent / 'heartwood'}\n\n"
            "Or set HEARTWOOD_DIR to an existing clone.")
    try:
        # Drop any previously imported Heartwood modules so a fresh install
        # in the same process is visible without restarting the app.
        for name in list(sys.modules):
            if name in ("heartwood", "challenges", "endpoint", "endpoints",
                        "providers", "portable") or name.startswith("heartwood."):
                del sys.modules[name]
        path = str(hw_dir)
        if path not in sys.path:
            sys.path.insert(0, path)
        import challenges, endpoint, endpoints, heartwood      # noqa: E402
        return (heartwood, challenges, endpoint, endpoints), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def install_heartwood() -> tuple[bool, str]:
    """Clone the official Heartwood repo next to Oblivio. Fixed URL only."""
    global _HEARTWOOD_CACHED
    existing = resolve_heartwood_dir()
    if existing is not None:
        return True, f"already installed at {existing}"
    dest = HERE.parent / "heartwood"
    if dest.exists() and not (dest / "heartwood.py").is_file():
        return False, f"{dest} exists but is not a Heartwood tree"
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            ["git", "clone", "--depth", "1", HEARTWOOD_REPO, str(dest)],
            capture_output=True, text=True, timeout=180,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except FileNotFoundError:
        return False, "git is not on PATH — install Git, or clone Heartwood manually"
    except subprocess.TimeoutExpired:
        return False, "git clone timed out"
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "clone failed").strip()[:400]
        return False, err
    if not (dest / "heartwood.py").is_file():
        return False, "clone finished but heartwood.py is missing"
    _HEARTWOOD_CACHED = dest
    return True, str(dest)


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
        rc = H.build_receipt(seed, diff, com, beacon, plan, cal, tr, "oblivio-app")
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
        # Empty Host is not trusted: some clients omit it; attackers can too.
        # Only explicit loopback names are accepted.
        host = (self.headers.get("Host") or "").split(":")[0].strip("[]").lower()
        return host in ("127.0.0.1", "localhost", "::1")

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
        tok = self.headers.get("X-Oblivio-Token") or ""
        if not tok and "?" in self.path:
            from urllib.parse import parse_qs
            tok = (parse_qs(self.path.split("?", 1)[1]).get("t") or [""])[0]
        # compare_digest requires equal length; unequal inputs must not 500.
        self.caller = None
        if tok and len(tok) == len(TOKEN) and secrets.compare_digest(tok, TOKEN):
            self.caller = "page"
            return True
        # An agent token, when enabled, reaches memory routes only — never key
        # routes, Heartwood install, or the agent switch itself.
        agent_tok = AGENT.get("token") or ""
        if (AGENT["on"] and agent_tok and tok
                and len(tok) == len(agent_tok)
                and secrets.compare_digest(tok, agent_tok)):
            path = self.path.split("?", 1)[0]
            if path.startswith(("/api/write", "/api/read/", "/api/state")):
                # Which caller this is, decided here and read by the routes.
                # Reaching a route is not the same as being entitled to what it
                # returns: /api/read and /api/state both hand back memory, and
                # the answer must depend on who is asking.
                self.caller = "agent"
                return True
            return False
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
                _, hw_err = heartwood_modules()
                hw_path = resolve_heartwood_dir()
                hw_meta = {
                    "heartwood": hw_err is None,
                    "heartwood_error": hw_err,
                    "heartwood_path": str(hw_path) if hw_path else None,
                }
                if not ok:
                    return self._send(200, {"node": False, "why": how,
                                            "privacy": privacy_snapshot(),
                                            **hw_meta})
                # Head + list are metadata-only; the key is only needed when
                # reading or writing plaintext. Creating it here would mint a
                # secret the moment someone opens the app, before they have
                # anything to protect — wrong moment for the backup modal.
                c = client(need_key=False)
                head = c.head()
                recs = c.list()
                pin_ok = PIN_PATH.is_file()

                m = gate_mod()
                pol = load_policy()
                # Names and classes come from the local catalogue: the node
                # returns none. Anything absent from it was written before
                # classes existed, or by another tool -- unclassified is not
                # public, so it counts as secret, which is what decode_label
                # would say about it too.
                bysens = {s.label: 0 for s in m.Sensitivity}
                cat = {e.get("index"): e for e in load_catalogue()}
                listed = []
                for i, r in enumerate(recs):
                    idx = r.get("index", i)
                    e = cat.get(idx)
                    sname = ((e or {}).get("sensitivity")
                             or m.Sensitivity.SECRET.label)
                    bysens[sname] = bysens.get(sname, 0) + 1
                    listed.append({**r, "index": idx,
                                   "label": (e or {}).get("label") or "",
                                   "sensitivity": sname,
                                   "classified": e is not None})
                granted = m.Tier(AGENT.get("tier", 0))
                reachable = sum(n for s, n in bysens.items()
                                if granted >= m.Tier(pol.get(s,
                                                             int(m.Tier.LOCAL))))
                if getattr(self, "caller", None) == "agent":
                    # A label is a disclosure by itself -- "bank details" tells
                    # you plenty without the record behind it -- so an agent
                    # must not be able to enumerate what it cannot open.
                    listed = [x for x in listed
                              if granted >= m.Tier(pol.get(x["sensitivity"],
                                                           int(m.Tier.LOCAL)))]
                recs = listed
                return self._send(200, {
                    "node": True, "how": how,
                    "records": len(recs),
                    "by_sensitivity": bysens,
                    "agent_reachable": reachable,
                    "tree_size": head.get("tree_size"),
                    "root": head.get("root_hex") or head.get("root_hash")
                            or head.get("root"),
                    "pubkey": head.get("public_key_hex"),
                    "key_exists": key_material_exists(),
                    "key_sealed_at_rest": key_sealed_at_rest(),
                    "unlocked": session_unlocked(),
                    "key_backed_up": key_backed_up(),
                    "key_just_created": KEY_JUST_CREATED and not key_backed_up(),
                    "legacy_plaintext": KEY_PATH.is_file(),
                    "pin_held": pin_ok,
                    "integrity": "verified",
                    "privacy": privacy_snapshot(),
                    **hw_meta,
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
                try:
                    res = client().get(idx)
                except KeyLocked:
                    return self._send(423, {
                        "error": "unlock your master key first",
                        "code": "key_locked"})
                plain = res.pop("plaintext")
                try:
                    text = plain.decode("utf-8")
                except UnicodeDecodeError:
                    text = f"<{len(plain)} bytes of binary>"

                m = gate_mod()
                # The class comes from the DECRYPTED label, never from the
                # catalogue, which is plaintext on disk and therefore editable
                # by anything running as this user. An unreadable or absent
                # class reads as SECRET, so a typo costs recall, not exposure.
                sens, shown = m.decode_label(res.get("label", "") or "")
                res["label"] = shown
                res["sensitivity"] = sens.label

                if getattr(self, "caller", None) == "agent":
                    # Decryption already happened -- it had to, the class lives
                    # inside the ciphertext. The gate governs what is
                    # TRANSMITTED, and the agent is on the far side of this
                    # response.
                    required = m.Tier(load_policy().get(sens.label,
                                                        int(m.Tier.LOCAL)))
                    granted = m.Tier(AGENT.get("tier", 0))
                    if granted < required:
                        return self._send(403, {
                            "error": "withheld by policy",
                            "sensitivity": sens.label,
                            "requires": required.label,
                            "agent_tier": granted.label})
                    AGENT_READS.append({"index": idx, "label": shown,
                                        "sensitivity": sens.label,
                                        "at": int(time.time())})
                    del AGENT_READS[:-READS_LIMIT]
                return self._send(200, {"text": text, "meta": res})
            if path == "/api/key":
                # Metadata only. The raw key and its hex never ride on a GET —
                # that is how a page refresh, a log, or an agent scrapes secrets.
                if not _require_session_token(self):
                    return self._send(403, {"error": "session only — not agent token"})
                return self._send(200, {
                    "path": (str(KEY_SEALED_PATH) if key_sealed_at_rest()
                             else (str(KEY_PATH) if KEY_PATH.is_file()
                                   else "(in memory until sealed)")),
                    "sealed_at_rest": key_sealed_at_rest(),
                    "unlocked": session_unlocked(),
                    "legacy_plaintext": KEY_PATH.is_file(),
                    "backed_up": key_backed_up(),
                    "just_created": KEY_JUST_CREATED,
                    "export": "passphrase-sealed zip only",
                    "hex": None,
                    "raw_download": False,
                })
            if path == "/api/key/download":
                # Plain GET of the raw key is refused. Use POST /api/key/export
                # with a passphrase so the downloaded file is ciphertext.
                return self._send(405, {
                    "error": "raw key download is disabled",
                    "hint": ("POST /api/key/export with a passphrase you choose. "
                             "You get a sealed zip — agents that open the file "
                             "cannot read the key without that passphrase."),
                })
            if path == "/api/agent":
                m = gate_mod()
                return self._send(200, {
                    "enabled": AGENT["on"],
                    "token": AGENT["token"] if AGENT["on"] else None,
                    "url": f"http://127.0.0.1:{PORT}",
                    "tier": AGENT.get("tier", 0),
                    "tier_label": m.Tier(AGENT.get("tier", 0)).label,
                    # The switch is reversible; this is not. It is what the
                    # agent already took, and no switch un-reads it.
                    "reads": AGENT_READS[-50:][::-1],
                    "read_count": len(AGENT_READS)})
            if path == "/api/policy":
                m = gate_mod()
                return self._send(200, {
                    "policy": load_policy(),
                    "agent_tier": AGENT.get("tier", 0),
                    "tiers": [{"value": int(t), "label": t.label} for t in m.Tier],
                    "sensitivities": [{"value": int(s), "label": s.label}
                                      for s in m.Sensitivity]})
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
                force = bool(body.get("i_accept_no_backup"))
                try:
                    # Soft gate: mint in memory if needed, require sealed setup
                    # (or explicit accept) before the first write sticks.
                    if not session_unlocked() and key_sealed_at_rest():
                        return self._send(423, {
                            "error": "unlock your master key first",
                            "code": "key_locked"})
                    c = client()
                    if (not key_sealed_at_rest() or not key_backed_up()) and not force:
                        return self._send(409, {
                            "error": "set a passphrase and download a sealed backup",
                            "code": "key_not_backed_up",
                            "key_just_created": KEY_JUST_CREATED,
                            "needs_setup": not key_sealed_at_rest(),
                            "hint": ("Choose a passphrase: it seals the key on "
                                     "disk (agents cannot read it) and builds a "
                                     "portable zip. Or send i_accept_no_backup "
                                     "if you accept permanent loss.")})
                    # Unspecified matches the engine's own default rather than
                    # the strictest class: a memory nobody classified should
                    # still come back to the person who wrote it.
                    m = gate_mod()
                    raw_sens = body.get("sensitivity")
                    if not isinstance(raw_sens, str) or not raw_sens:
                        raw_sens = "personal"
                    sens = m.Sensitivity.parse(raw_sens)
                    label = (raw_label or "")[:120]
                    res = c.put(text, label=m.encode_label(sens, label))
                    add_to_catalogue([catalogue_entry(res, label, sens.label)])
                    return self._send(200, {"ok": True, "record": res,
                                            "sensitivity": sens.label})
                except KeyLocked:
                    return self._send(423, {
                        "error": "unlock your master key first",
                        "code": "key_locked"})
            if path == "/api/key/unlock":
                # Load sealed key into memory. Migrates legacy plaintext.
                # Never returns key material.
                if not _require_session_token(self):
                    return self._send(403, {"error": "session only — not agent token"})
                pw = body.get("passphrase")
                if not isinstance(pw, str) or not pw:
                    return self._send(400, {"error": "passphrase required"})
                try:
                    unlock_session(pw)
                except ValueError as exc:
                    return self._send(403, {
                        "error": str(exc),
                        "code": "wrong_passphrase",
                        "can_reset": True})
                except Exception as exc:
                    return self._send(403, {
                        "error": "could not unlock — wrong passphrase?",
                        "code": "wrong_passphrase",
                        "detail": type(exc).__name__,
                        "can_reset": True})
                return self._send(200, {
                    "ok": True,
                    "unlocked": True,
                    "sealed_at_rest": key_sealed_at_rest(),
                    "legacy_plaintext": KEY_PATH.is_file(),
                })
            if path == "/api/key/lock":
                # Drop the in-memory key. Disk stays sealed. Useful when walking
                # away — and so a process dump is less interesting after.
                global SESSION_KEY
                if not _require_session_token(self):
                    return self._send(403, {"error": "session only — not agent token"})
                SESSION_KEY = None
                return self._send(200, {"ok": True, "unlocked": False})
            if path == "/api/key/reset":
                # Start over: wipe sealed key material so a NEW passphrase can
                # be chosen. Requires explicit confirmation string.
                if not _require_session_token(self):
                    return self._send(403, {"error": "session only — not agent token"})
                confirm = (body.get("confirm") or "").strip().lower()
                if confirm not in ("erase sealed key", "start over"):
                    return self._send(400, {
                        "error": 'type confirm: "start over" to erase the sealed key',
                        "code": "confirm_required"})
                reset_local_key_material()
                return self._send(200, {
                    "ok": True,
                    "reset": True,
                    "hint": "Sealed key removed. Choose a new passphrase to seal again. "
                            "Old keep records cannot be decrypted without the old key."})
            if path == "/api/key/setup":
                # First-run: mint (if needed), seal at rest, export zip, ack.
                # One passphrase — on disk and in the download — so agents that
                # read the project folder or Downloads get ciphertext only.
                if not _require_session_token(self):
                    return self._send(403, {"error": "session only — not agent token"})
                pw = body.get("passphrase")
                pw2 = body.get("passphrase_confirm")
                if not isinstance(pw, str) or not isinstance(pw2, str):
                    return self._send(400, {"error": "passphrase required"})
                if pw != pw2:
                    return self._send(400, {"error": "passphrases do not match — type the same passphrase twice"})
                if len(pw) < _MIN_BACKUP_PASSPHRASE:
                    return self._send(400, {
                        "error": (f"passphrase must be at least "
                                  f"{_MIN_BACKUP_PASSPHRASE} characters")})
                try:
                    if key_sealed_at_rest() and not session_unlocked():
                        # Already sealed: this is unlock+export, not a new passphrase.
                        unlock_session(pw)
                    elif not session_unlocked():
                        ensure_session_key()
                        seal_at_rest(pw)
                    else:
                        if not key_sealed_at_rest() or KEY_PATH.is_file():
                            seal_at_rest(pw)
                    blob = seal_master_key_zip(SESSION_KEY, pw)
                except ValueError as exc:
                    return self._send(403, {
                        "error": str(exc),
                        "code": "wrong_passphrase",
                        "can_reset": True})
                except Exception as exc:
                    return self._send(400, {
                        "error": f"setup failed ({type(exc).__name__})",
                        "detail": type(exc).__name__})
                KEY_ACK_PATH.parent.mkdir(parents=True, exist_ok=True)
                KEY_ACK_PATH.write_text(
                    json.dumps({"acked_at": int(time.time()),
                                "path": str(KEY_SEALED_PATH),
                                "format": "passphrase-sealed-at-rest+zip",
                                "via": "setup"}, indent=2),
                    encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="oblivio-master-key.zip"')
                self.send_header("Content-Length", str(len(blob)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(blob)
                return
            if path == "/api/key/ack":
                if not _require_session_token(self):
                    return self._send(403, {"error": "session only — not agent token"})
                KEY_ACK_PATH.parent.mkdir(parents=True, exist_ok=True)
                KEY_ACK_PATH.write_text(
                    json.dumps({"acked_at": int(time.time()),
                                "path": str(KEY_SEALED_PATH if key_sealed_at_rest()
                                            else KEY_PATH),
                                "format": "passphrase-sealed-zip"}, indent=2),
                    encoding="utf-8")
                return self._send(200, {"ok": True, "backed_up": True})
            if path == "/api/key/export":
                # Portable sealed zip. Requires unlocked session. Never hex.
                if not _require_session_token(self):
                    return self._send(403, {"error": "session only — not agent token"})
                pw = body.get("passphrase")
                pw2 = body.get("passphrase_confirm")
                if not isinstance(pw, str) or not isinstance(pw2, str):
                    return self._send(400, {"error": "passphrase required"})
                if pw != pw2:
                    return self._send(400, {"error": "passphrases do not match"})
                if len(pw) < _MIN_BACKUP_PASSPHRASE:
                    return self._send(400, {
                        "error": (f"passphrase must be at least "
                                  f"{_MIN_BACKUP_PASSPHRASE} characters")})
                try:
                    if not session_unlocked():
                        if key_sealed_at_rest():
                            return self._send(423, {
                                "error": "unlock first", "code": "key_locked"})
                        ensure_session_key()
                    if not key_sealed_at_rest() or KEY_PATH.is_file():
                        seal_at_rest(pw)
                    blob = seal_master_key_zip(SESSION_KEY, pw)
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
                KEY_ACK_PATH.parent.mkdir(parents=True, exist_ok=True)
                KEY_ACK_PATH.write_text(
                    json.dumps({"acked_at": int(time.time()),
                                "path": str(KEY_SEALED_PATH),
                                "format": "passphrase-sealed-zip",
                                "via": "export"}, indent=2),
                    encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="oblivio-master-key.zip"')
                self.send_header("Content-Length", str(len(blob)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(blob)
                return
            if path == "/api/frontier-chat":
                # Historic stack entry: content gate + optional account-decoupled
                # gateway (client holds no provider API key; blind token only).
                if not _require_session_token(self):
                    return self._send(403, {
                        "error": "session only — frontier path is human-gated"})
                from oblivio.frontier_private import (
                    FrontierPrivateError,
                    default_api_key,
                    frontier_chat,
                    make_cloud_remote,
                    make_ollama_local,
                )
                text = (body.get("text") or "").strip()
                if not text:
                    return self._send(400, {"error": "nothing to ask"})
                if not body.get("enable_frontier") or not body.get(
                        "accept_residual_risks"):
                    return self._send(400, {
                        "error": "both enable_frontier and "
                                 "accept_residual_risks are required",
                        "hint": "content is gated; identity only with gateway"})
                model = (body.get("model") or "").strip()
                gateway_url = (body.get("gateway_url") or "").strip()
                # OHTTP: the client posts opaque bytes to the RELAY, which
                # forwards them to the gateway. The relay sees an IP and no
                # plaintext; the gateway sees plaintext and no IP.
                relay_url = (body.get("relay_url") or "").strip()
                # The gateway's key config is supplied, never fetched from the
                # gateway here: asking it for its own key would open exactly
                # the direct connection OHTTP exists to avoid. Read it from
                # GET /v1/params out of band, as the CLI does.
                ohttp_config = (body.get("ohttp_config") or "").strip()
                token_blob = body.get("token")  # {token_hex, signature_hex}
                local_model = (body.get("local_model") or "llama3.2").strip()
                ollama_base = (body.get("ollama_base")
                               or "http://127.0.0.1:11434").strip()
                if not model:
                    return self._send(400, {"error": "model is required"})
                if relay_url and not gateway_url:
                    return self._send(400, {
                        "error": "relay_url needs gateway_url — a relay "
                                 "forwards to a gateway"})
                if relay_url and not ohttp_config:
                    return self._send(400, {
                        "error": "relay_url needs ohttp_config",
                        "hint": "GET /v1/params on the gateway gives "
                                "ohttp_key_config_b64; pass it here"})
                account_decoupled = False
                context: list = []
                if body.get("with_keep"):
                    try:
                        c = client()
                        for rec in c.list()[-6:]:
                            try:
                                opened = c.get(int(rec["index"]))
                                pt = opened.get("plaintext") or b""
                                if isinstance(pt, bytes):
                                    pt = pt.decode("utf-8", "replace")
                                if pt:
                                    context.append(pt)
                            except Exception:
                                continue
                    except KeyLocked:
                        return self._send(423, {
                            "error": "unlock your master key first",
                            "code": "key_locked"})
                try:
                    local = make_ollama_local(ollama_base, local_model)
                    if gateway_url:
                        from oblivio.anon_token import Token
                        from oblivio.frontier_gateway import make_gateway_remote
                        if not isinstance(token_blob, dict):
                            return self._send(400, {
                                "error": "gateway path needs token object "
                                         "{token_hex, signature_hex}"})
                        tok = Token(
                            value_hex=str(token_blob.get("token_hex") or ""),
                            signature_hex=str(
                                token_blob.get("signature_hex") or ""))
                        remote = make_gateway_remote(
                            gateway_url, tok, model=model,
                            use_ohttp=bool(relay_url),
                            ohttp_key_config_b64=ohttp_config or None,
                            relay_url=relay_url or None)
                        account_decoupled = True
                    else:
                        api_base = (body.get("api_base") or "").strip()
                        api_key = (body.get("api_key") or default_api_key()
                                   or "").strip()
                        if not api_base:
                            return self._send(400, {
                                "error": "api_base required, or set gateway_url"})
                        if not api_key:
                            return self._send(400, {
                                "error": "api_key required (or use gateway + token)"})
                        remote = make_cloud_remote(
                            api_base=api_base, api_key=api_key, model=model,
                            dialect=body.get("dialect") or None)
                    # Ask the completer what it sends over, rather than
                    # restating the request body. These disagree exactly when
                    # the receipt would otherwise be wrong.
                    from oblivio.frontier_gateway import transport_of
                    receipt = frontier_chat(
                        text,
                        local=local,
                        remote=remote,
                        context=context,
                        enable_frontier=True,
                        accept_residual_risks=True,
                        max_specificity=int(body.get("max_specificity") or 24),
                        ohttp_independent_operators=(
                            True if body.get("ohttp_independent") else None),
                        account_decoupled=account_decoupled,
                        transport=transport_of(remote),
                        gateway_url=gateway_url or None,
                        relay_url=relay_url or None,
                    )
                except FrontierPrivateError as exc:
                    return self._send(409, {"error": str(exc),
                                            "code": "frontier_refused"})
                except Exception as exc:
                    return self._send(500, safe_error(exc))
                return self._send(200, {"ok": True, **receipt.as_dict()})
            if path == "/api/prove":
                # Zero-knowledge membership: prove a record is in this keep
                # without putting the index in the proof. The cool thing the
                # CLI already does — now on the surface a stranger can reach.
                raw_idx = body.get("index")
                if not isinstance(raw_idx, int) and not (isinstance(raw_idx, str)
                                                         and str(raw_idx).isdigit()):
                    return self._send(400, {"error": "index must be a number"})
                idx = int(raw_idx)
                if idx < 0:
                    return self._send(400, {"error": "index out of range"})
                from oblivio.zk_keep import (keep_leaves, prove_in_keep,
                                               verify_in_keep)
                try:
                    c = client()
                except KeyLocked:
                    return self._send(423, {
                        "error": "unlock your master key first",
                        "code": "key_locked"})
                head = c.head()
                size = int(head.get("tree_size") or 0)
                if idx >= size:
                    return self._send(400, {"error": "no record at that index",
                                            "tree_size": size})
                bundle = prove_in_keep(c, index=idx, head=head)
                leaves = keep_leaves(c)
                ok = verify_in_keep(bundle, leaves, head) is True
                # Never echo the index in the proof blob the user can share.
                return self._send(200, {
                    "ok": ok,
                    "statement": (f"The prover holds one of the {size} records "
                                  f"in this keep. Which one is not revealed."),
                    "tree_size": size,
                    "root": head.get("root_hex"),
                    "proof_has_index": "index" in bundle,
                    "branches": len((bundle.get("proof") or {}).get("t_hex") or []),
                    "bundle": bundle if ok else None,
                })
            if path == "/api/agent":
                # Only the page's own token may flip this. An agent holding an
                # agent token must not be able to keep itself enabled.
                supplied = self.headers.get("X-Oblivio-Token") or ""
                if not secrets.compare_digest(supplied, TOKEN):
                    return self._send(403, {"error": "only the app can change this"})
                AGENT["on"] = bool(body.get("enabled"))
                AGENT["token"] = secrets.token_urlsafe(24) if AGENT["on"] else None
                return self._send(200, {"enabled": AGENT["on"],
                                        "token": AGENT["token"],
                                        "url": f"http://127.0.0.1:{PORT}"})
            if path == "/api/policy":
                # Page token only. An agent able to widen its own clearance
                # would walk straight through the gate it is standing behind,
                # which would make the whole policy decorative.
                if not _require_session_token(self):
                    return self._send(403, {"error": "session only — not agent token"})
                m = gate_mod()
                load_policy()
                changed = body.get("policy")
                if isinstance(changed, dict):
                    for k, v in changed.items():
                        if k == "secret" or k not in POLICY:
                            continue          # SECRET is pinned, see load_policy
                        if isinstance(v, int) and 0 <= v <= int(max(m.Tier)):
                            POLICY[k] = v
                tier = body.get("agent_tier")
                if isinstance(tier, int) and 0 <= tier <= int(max(m.Tier)):
                    AGENT["tier"] = tier
                _write_json_locked(POLICY_PATH, POLICY)
                return self._send(200, {"policy": load_policy(),
                                        "agent_tier": AGENT.get("tier", 0)})
            if path == "/api/hw/install":
                # Session only — never agent. Fixed upstream URL only.
                if not _require_session_token(self):
                    return self._send(403, {"error": "session only"})
                ok, msg = install_heartwood()
                if not ok:
                    return self._send(500, {"error": msg, "ok": False})
                mods, err = heartwood_modules()
                return self._send(200, {
                    "ok": True, "path": msg,
                    "ready": mods is not None,
                    "detail": err,
                })
            if path == "/api/hw/run":
                if not _require_session_token(self):
                    return self._send(403, {
                        "error": "session only — Heartwood is not agent-reachable"})
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
                print(f"[oblivio] read failed: {type(exc).__name__}: {exc}",
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
<title>Oblivio</title><style>
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
.okbox{border-left:3px solid var(--good);padding:.2rem 0 .2rem .9rem;
color:var(--muted);font-size:.86rem;margin-top:.9rem}
.rail{display:flex;flex-wrap:wrap;gap:.45rem;margin-top:1.15rem}
.pill{font-family:var(--mono);font-size:.72rem;letter-spacing:.02em;
padding:.28rem .6rem;border-radius:999px;border:1px solid var(--line);
color:var(--muted);background:rgba(0,0,0,.22)}
.pill.on{color:var(--cyan);border-color:rgba(79,208,224,.35);
background:rgba(79,208,224,.08)}
.pill.warn{color:var(--gold);border-color:rgba(227,179,65,.4);
background:rgba(227,179,65,.08)}
.pill.bad{color:var(--bad);border-color:rgba(248,81,73,.35);
background:rgba(248,81,73,.08)}
.pill.good{color:var(--good);border-color:rgba(63,185,80,.35);
background:rgba(63,185,80,.08)}
.welcome{display:grid;gap:.75rem;grid-template-columns:repeat(auto-fit,minmax(12rem,1fr));
margin-top:1rem}
.stepc{background:rgba(0,0,0,.28);border:1px solid var(--line);border-radius:.6rem;
padding:.9rem 1rem}
.stepc b{display:block;color:var(--cyan);font-family:var(--mono);font-size:.78rem;
margin-bottom:.35rem}
.stepc span{font-size:.86rem;color:var(--muted)}
.searchrow{display:flex;gap:.6rem;margin-top:.8rem;align-items:center}
.searchrow input{flex:1;margin:0}
.actions{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:.7rem}
.rec .acts{display:flex;gap:.35rem;align-items:center}
.rec button.mini{padding:.2rem .5rem;font-size:.72rem;border-radius:.3rem;
border:1px solid var(--line);background:transparent;color:var(--muted);
font-family:var(--mono);cursor:pointer}
.rec button.mini:hover{color:var(--accent);border-color:var(--accent)}
.modal{position:fixed;inset:0;z-index:40;display:none;place-items:center;
background:rgba(4,8,14,.72);backdrop-filter:blur(6px);padding:1.2rem}
.modal.show{display:grid}
.modal .sheet{width:min(34rem,100%);background:var(--panel2);border:1px solid var(--line);
border-radius:.9rem;padding:1.4rem 1.5rem;box-shadow:0 20px 60px rgba(0,0,0,.55);
background-image:linear-gradient(180deg,rgba(227,179,65,.07),transparent 50%)}
.modal h2{margin:0 0 .4rem;font-size:1.2rem;color:var(--gold)}
.modal .hex{margin-top:.8rem;padding:.7rem .8rem;border:1px solid var(--line);
border-radius:.45rem;background:rgba(0,0,0,.4);color:var(--gold);
font-family:var(--mono);font-size:.78rem;word-break:break-all;max-height:6.5rem;
overflow:auto;user-select:all}
.modal .rowbtns{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:1rem}
.eye{opacity:.55;font-size:.78rem;margin-left:.25rem}

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

<!-- Passphrase: seals key at rest + portable zip. Never raw key/hex in the page. -->
<div class=modal id=keymodal role=dialog aria-modal=true aria-labelledby=keymodaltitle>
  <div class=sheet>
    <h2 id=keymodaltitle>Seal your master key</h2>
    <p class=note id=keymodalhelp>Choose a passphrase (at least 10 characters),
    type it twice, then click Seal. There is no email reset — remember it.
    You will download a sealed zip backup.</p>
    <label for=keypw id=keypwlab>Passphrase (min 10 characters)</label>
    <input id=keypw type=password autocomplete=new-password
           placeholder="e.g. four-words-you-will-remember">
    <label for=keypw2 id=keypw2lab>Type it again</label>
    <input id=keypw2 type=password autocomplete=new-password
           placeholder="same passphrase again">
    <div id=keymodalerr class=warnbox style="display:none;margin-top:.7rem"></div>
    <div class=okbox id=keymodalok style="margin-top:.8rem">You get
    <b style="color:var(--ink)">oblivio-master-key.zip</b> plus
    <span class=mono>data/master.key.sealed</span> — both ciphertext.
    Never put the passphrase in a chat or agent prompt.</div>
    <div class=rowbtns>
      <button class=go id=keymodalsave>Seal on disk + download zip</button>
      <button class=ghost id=keymodallater>Not now</button>
      <button class=ghost id=keymodalreset style="display:none;color:var(--bad);
        border-color:rgba(248,81,73,.4)">Start over</button>
    </div>
    <p class=note id=keymodalfoot style="margin-top:.9rem;font-size:.8rem">If
    this keep was sealed before (e.g. during testing), you must unlock with that
    passphrase — or Start over to choose a new one (old memories stay encrypted
    under the lost key).</p>
  </div>
</div>

<div class=wrap>
<header>
  <div class=brand>
    <svg viewBox="0 0 96 96" aria-hidden="true">
      <path d="M48 8 L80 19 v28 c0 19-13 32-32 40 C29 79 16 66 16 47 V19 Z"
            fill="none" stroke="#F4B728" stroke-width="4" stroke-linejoin="round"/>
      <path fill-rule="evenodd" fill="#F4B728"
            d="M33 44 h6 v-7 h6 v7 h6 v-7 h6 v7 h6 v26 H33 Z M44 57 h8 v13 h-8 Z"/>
    </svg>
    <div><h1>Oblivio</h1>
    <div class=tag id=tag>encrypted memory · the node cannot read it</div></div>
  </div>
  <div class=rail id=rail aria-label="Privacy posture"></div>
  <div class=tabs role=tablist>
    <button class=tab id=t-keep role=tab aria-selected=true aria-controls=p-keep>Your keep</button>
    <button class=tab id=t-write role=tab aria-selected=false aria-controls=p-write>Remember</button>
    <button class=tab id=t-sec role=tab aria-selected=false aria-controls=p-sec>Security</button>
    <button class=tab id=t-hw role=tab aria-selected=false aria-controls=p-hw>Heartwood</button>
    <button class=tab id=t-proof role=tab aria-selected=false aria-controls=p-proof>Proof</button>
    <button class=tab id=t-truth role=tab aria-selected=false aria-controls=p-truth>Privacy truth</button>
    <button class=tab id=t-how role=tab aria-selected=false aria-controls=p-how>How it works</button>
  </div>
</header>

<section class=page id=p-keep role=tabpanel aria-labelledby=t-keep>
  <div class=card>
    <h2>Your keep</h2>
    <div class=stats id=stats></div>
    <p class=note id=keepnote></p>
    <div id=welcome class=welcome style="display:none">
      <div class=stepc><b>1 · Remember</b><span>Write something only you should see. It is encrypted on this machine before the node ever gets a blob.</span></div>
      <div class=stepc><b>2 · Save your key</b><span>One file decrypts everything. Back it up once — there is no reset. We will ask you, not nag forever.</span></div>
      <div class=stepc><b>3 · Prove, don't disclose</b><span>Show that you hold a record in this keep without saying which one. That is the zero-knowledge part.</span></div>
    </div>
  </div>
  <div class=card>
    <h2>Memories <span class=eye title="Labels stay inside the ciphertext. The node never sees them.">· private labels</span></h2>
    <p class=note>Stored encrypted. Open one to decrypt it here — the node
    only ever held ciphertext. Filter stays on this page; nothing is searched on the node.</p>
    <div class=searchrow>
      <input id=rfilter type=search placeholder="Filter by name (local only)…" autocomplete=off>
    </div>
    <div id=recs style="margin-top:.8rem">…</div>
    <div id=reader style="display:none;margin-top:1rem;border-top:1px solid var(--line);
         padding-top:1rem">
      <div class=mono id=readermeta></div>
      <pre id=readertext style="white-space:pre-wrap;font-size:.9rem;margin:.6rem 0 0"></pre>
      <div class=actions>
        <button class=ghost id=rprove>Prove I hold this · without naming which</button>
        <button class=ghost id=rhide>Hide</button>
      </div>
      <div id=proveres style="margin-top:.8rem"></div>
    </div>
  </div>
</section>

<section class=page id=p-sec role=tabpanel aria-labelledby=t-sec hidden>
  <div class=card>
    <h2>Security — plain English</h2>
    <p class=note>This is the page for everyone, not just cryptographers. What
    Oblivio does to keep you safer, what it does <b style="color:var(--ink)">not</b>
    do, and what you should do with your key. Live status updates as you use the app.</p>
    <div class=stats id=secstats style="margin-top:1rem"></div>
    <div id=secposture style="margin-top:1rem"></div>
  </div>

  <div class=card>
    <h2>What is protected</h2>
    <ul class=plain>
      <li><b>Your memories stay encrypted.</b> Text is sealed on this machine
      before the storage node ever sees a blob. The node has no key — so it
      cannot read what you stored.</li>
      <li><b>History cannot be silently rewritten.</b> Every save appends to a
      signed log. If something is dropped or changed, your client refuses it.</li>
      <li><b>Your master key is sealed on disk.</b> After setup it is
      passphrase-wrapped (<span class=mono>master.key.sealed</span>). Backups
      are a sealed zip — not a raw key file agents can open.</li>
      <li><b>This app does not phone home.</b> It binds to localhost only. No
      Oblivio cloud account. No analytics upload of your keep.</li>
      <li><b>You can prove you hold a record without naming which.</b> That is
      the zero-knowledge membership feature on the Proof tab.</li>
    </ul>
  </div>

  <div class=card>
    <h2>What you must do</h2>
    <ol class=steps>
      <li><b>Set a passphrase and save the sealed zip</b> when prompted — before
      you store anything you would mind losing. There is no password reset.</li>
      <li><b>Never put the passphrase in a chat or AI agent.</b> That hands over
      the only secret that opens your keep.</li>
      <li><b>Lock when you walk away</b> if others can use this computer
      (Proof tab / unlock flow). Unlocked means the key is in memory.</li>
      <li><b>Treat cloud AI as a different risk.</b> Sending a question to a
      frontier model is not the same as storing a memory here. Use
      <b>Privacy truth</b> and the frontier stack only if you understand the receipt.</li>
    </ol>
  </div>

  <div class=card>
    <h2>What is not protected</h2>
    <ul class=plain>
      <li><b>Malware on your PC while unlocked</b> can still read process memory.
      Sealed-at-rest stops cold disk scrapes, not a live infection.</li>
      <li><b>A normal cloud chat with your API key</b> still identifies your
      account to the provider. That is not “anonymous ChatGPT.”</li>
      <li><b>Heartwood</b> checks whether a provider did the work you paid for
      — it is an effort audit, not a privacy tool. It may call the provider.</li>
      <li><b>If someone has your passphrase and sealed zip,</b> they can open
      the keep. Guard both like a password manager vault.</li>
    </ul>
    <div class=warnbox>If a product promises “frontier AI with zero metadata and
    zero identity for free,” treat that as a claim to verify — not as what this
    app silently guarantees.</div>
  </div>

  <div class=card>
    <h2>Where to go next</h2>
    <div class=welcome>
      <div class=stepc><b>Proof</b><span>Key backup, sealed zip, zero-knowledge membership, agent access switch.</span></div>
      <div class=stepc><b>Heartwood</b><span>Check if your AI is being throttled — install engine if needed, then run a check.</span></div>
      <div class=stepc><b>Privacy truth</b><span>Deep threat model, frontier stack, and residual risks with full receipts.</span></div>
      <div class=stepc><b>How it works</b><span>Step-by-step: encrypt → append → verify → decrypt.</span></div>
    </div>
    <p class=note style="margin-top:1rem">Technical write-up for reviewers:
    <span class=mono>SECURITY.md</span> and <span class=mono>STACK.md</span>
    in the GitHub repo — not required to use the app.</p>
  </div>
</section>

<section class=page id=p-write role=tabpanel aria-labelledby=t-write hidden>
  <div class=card>
    <h2>Remember something</h2>
    <p class=note>Encrypted on this machine before it leaves. The node stores
    a blob it cannot open, and cannot tell one memory from another.</p>
    <div id=writewarn class=warnbox style="display:none">No sealed zip backup
    yet. You will be asked to download a passphrase-sealed backup before this
    is kept — or you can accept permanent loss if the key disappears.</div>
    <label for=wlabel>A name for it (optional · stays encrypted)</label>
    <input id=wlabel placeholder="e.g. bank details, notes on the grant" autocomplete=off>
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
    <label>Current root <span class=eye>(public commitment · not secret)</span></label>
    <div class=mono id=root>…</div>
    <label style="margin-top:.8rem">Integrity</label>
    <div id=integrity class=okbox>Checking…</div>
  </div>

  <div class=card>
    <h2>Your master key</h2>
    <p class=note>On disk the key is <span class=mono>data/master.key.sealed</span>
    (passphrase-wrapped). In process it lives in memory only while unlocked.
    Portable backups are a <b style="color:var(--ink)">sealed zip</b> — never
    raw bytes, never hex in the page.</p>
    <div id=keystatus class=warnbox>Not sealed yet.</div>
    <label>Sealed key path (local only · not for sharing)</label>
    <div class=mono id=keypath>data/master.key.sealed</div>
    <div class=actions>
      <button class=go id=keyprompt style="margin-top:0">Download sealed backup zip</button>
    </div>
    <div class=warnbox>Do not put the passphrase in a chat or agent prompt.
    The zip is safe to park in Downloads; the passphrase is not.</div>
  </div>

  <div class=card>
    <h2>Zero-knowledge membership</h2>
    <p class=note>Prove you hold <b style="color:var(--ink)">one</b> of the
    records in this keep without saying which. The proof carries no index;
    every record produces the same shape. Bound to the signed tree head, so it
    fails if the keep grows or is swapped.</p>
    <label for=proveidx>Record number to prove (kept private in the proof)</label>
    <input id=proveidx type=number min=0 step=1 placeholder="e.g. 0" style="max-width:12rem">
    <div class=actions>
      <button class=go id=provego style="margin-top:0">Build proof</button>
      <button class=ghost id=provedl style="display:none">Download proof JSON</button>
    </div>
    <div id=proveout style="margin-top:.9rem"></div>
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
    <p class=note style="margin-top:.7rem">Oblivio refuses the trade. The
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
    up before you store anything you would miss.</b> The app exports a
    passphrase-sealed zip only — never the raw key in the page.</p>
  </div>

  <div class=card>
    <h2>Limits (summary)</h2>
    <p class=note>Full honesty lives on the
    <b style="color:var(--ink)">Privacy truth</b> tab — what the keep protects,
    what frontier models still see, and what this app will not claim.</p>
  </div>
</section>

<section class=page id=p-truth role=tabpanel aria-labelledby=t-truth hidden>
  <div class=card>
    <h2>Privacy truth</h2>
    <p class=note>This tab is the security / threat-model surface — what is
    real today, what is not, and where people get sold fiction. Read it before
    you put anything in the keep you would mind losing or leaking.</p>
    <div class=stats id=truthstats style="margin-top:1rem"></div>
  </div>

  <div class=card>
    <h2>What this app protects (storage)</h2>
    <ul class=plain>
      <li><b>The node cannot read your memories.</b> Encryption happens on this
      machine; storage only ever gets ciphertext.</li>
      <li><b>The node cannot rewrite history unnoticed.</b> Append-only Merkle
      log + signed head; your client pins and checks on every read.</li>
      <li><b>The raw master key is not shown and not downloaded as plaintext.</b>
      On disk it is passphrase-sealed; in process it lives in memory only after
      unlock. Agents that open the zip or <span class=mono>.sealed</span> file
      still need your passphrase.</li>
      <li><b>This app does not phone home</b> and does not send your keep to any
      frontier model by itself.</li>
    </ul>
    <div class=okbox>That is real privacy for <b style="color:var(--ink)">stored
    memory against an untrusted storage operator</b>. It is not the same as
    “chat anonymously with GPT.”</div>
  </div>

  <div class=card>
    <h2>Frontier models and “who you are”</h2>
    <p class=note><b style="color:var(--ink)">No — not by default, and not
    completely.</b> Keeping a storage node blind is a different problem from
    talking to Claude, GPT, Grok, or any hosted model without them learning
    who you are.</p>
    <ul class=plain>
      <li><b>API key = account identity.</b> A normal cloud call authenticates
      as you (or your org). The provider already knows the customer.</li>
      <li><b>The prompt is data.</b> Names, places, rare facts re-identify you
      even if you strip obvious labels.</li>
      <li><b>Metadata still exists.</b> Timing, size, IP, model choice, and
      billing all leak signals on a direct cloud path.</li>
      <li><b>The hard path is partial.</b> Local abstraction + blind tokens +
      constant-rate traffic + OHTTP can reduce linkability. It needs extra
      setup, honest operators, and still does not erase that a frontier model
      saw a question at all.</li>
    </ul>
    <div class=warnbox>If someone promises “frontier models with zero metadata
    and zero identity,” treat that as a claim to verify — not as what Oblivio
    ships in this app today.</div>
  </div>

  <div class=card>
    <h2>What can still go wrong</h2>
    <ul class=plain>
      <li><b>Unlocked session on a compromised machine.</b> Malware running as
      you can read process memory. Sealed-at-rest stops cold disk scrapes — not
      a live dump while unlocked.</li>
      <li><b>Passphrase in a chat or agent prompt.</b> That hands over the only
      secret that opens the sealed key and the zip.</li>
      <li><b>Which record you read</b> can leak access patterns unless you pay
      for full-keep private read (trivial PIR).</li>
      <li><b>Direct cloud chat</b> is labelled not private in the CLI and is
      not offered as a silent default here.</li>
    </ul>
  </div>

  <div class=card>
    <h2>The hard path (CLI · not one-click)</h2>
    <p class=note>If you need a capable hosted model with less linkability,
    four layers each remove a different leak. No single trick removes them all:</p>
    <ol class=steps>
      <li><b>Content</b> — local model rewrites a generic question; private
      context never leaves.</li>
      <li><b>Authorisation</b> — blind-signed token (Privacy Pass shape), not
      your name on the spend.</li>
      <li><b>Rhythm</b> — constant-rate, uniform-size traffic.</li>
      <li><b>Address</b> — OHTTP: relay sees IP not question; gateway sees
      question not IP. Both operators must be independent or anonymity is
      void.</li>
    </ol>
    <div class=warnbox><b style="color:var(--ink)">Honest catch.</b> That stack
    is in the library/CLI, not a button in this app. Finding independent relay
    and gateway operators is still the bottleneck no amount of local code
    substitutes for.</div>
  </div>

  <div class=card>
    <h2>Historic frontier stack</h2>
    <p class=note><b style="color:var(--ink)">Content gated</b> (local abstract +
    LeakGate) · <b style="color:var(--ink)">account decoupled</b> when you use a
    gateway + blind token (you never paste a provider API key here) ·
    re-specialise on this machine. See <span class=mono>STACK.md</span>.</p>
    <label for=ft-text>Your private question</label>
    <textarea id=ft-text placeholder="Include real names/details — they should stay on this machine."></textarea>
    <div class=grid2 style="margin-top:.6rem">
      <div><label for=ft-mode>Path</label>
        <select id=ft-mode>
          <option value=gateway selected>Gateway + blind token (no client API key)</option>
          <option value=direct>Direct API key (content only — account still yours)</option>
        </select></div>
      <div><label for=ft-model>Frontier model id</label>
        <input id=ft-model placeholder="grok-3 / gpt-4o / …" autocomplete=off></div>
      <div id=ft-gw-wrap><label for=ft-gw>Gateway URL</label>
        <input id=ft-gw value="http://127.0.0.1:8751" autocomplete=off></div>
      <div id=ft-tok-wrap><label for=ft-token>Token JSON (from token issue)</label>
        <textarea id=ft-token style="min-height:4rem" placeholder='{"token_hex":"…","signature_hex":"…"}'></textarea></div>
      <div id=ft-base-wrap style="display:none"><label for=ft-base>API base</label>
        <input id=ft-base placeholder="https://api.x.ai" autocomplete=off></div>
      <div id=ft-key-wrap style="display:none"><label for=ft-key>API key</label>
        <input id=ft-key type=password autocomplete=off placeholder="not stored"></div>
      <div id=ft-relay-wrap><label for=ft-relay>OHTTP relay URL (optional)</label>
        <input id=ft-relay placeholder="http://relay.example:8750 — leave blank for a direct send" autocomplete=off></div>
      <div id=ft-ohttp-wrap><label for=ft-ohttp>Gateway ohttp_key_config_b64</label>
        <input id=ft-ohttp placeholder="from GET /v1/params on the gateway" autocomplete=off></div>
      <div><label for=ft-local>Local Ollama model</label>
        <input id=ft-local value="llama3.2" autocomplete=off></div>
    </div>
    <p class=note id=ft-relay-note style="margin-top:.5rem">
      A relay splits the roles: it sees your IP and never your request; the
      gateway sees your request and never your IP. It only buys you anything
      when <b>a different person</b> runs each one — two on your own machine is
      a direct send with extra steps, and the receipt will say so.</p>
    <label style="margin-top:.8rem;display:flex;gap:.5rem;align-items:flex-start;color:var(--muted);font-size:.86rem">
      <input type=checkbox id=ft-enable style="width:auto;margin-top:.2rem">
      Enable frontier path</label>
    <label style="display:flex;gap:.5rem;align-items:flex-start;color:var(--muted);font-size:.86rem">
      <input type=checkbox id=ft-accept style="width:auto;margin-top:.2rem">
      I accept residual risks listed in the receipt (not zero-metadata magic)</label>
    <label style="display:flex;gap:.5rem;align-items:flex-start;color:var(--muted);font-size:.86rem">
      <input type=checkbox id=ft-keep style="width:auto;margin-top:.2rem">
      Use recent keep memories as private context (never sent raw)</label>
    <button class=go id=ft-go>Run historic stack</button>
    <div id=ft-out style="margin-top:1rem"></div>
  </div>

  <div class=card>
    <h2>Heartwood is a different question</h2>
    <p class=note>The <b style="color:var(--ink)">Heartwood</b> tab asks whether
    a provider did the compute you paid for — not whether they can read your
    keep. Same posture toward an unauditable company; different object.</p>
  </div>
</section>

<section class=page id=p-hw role=tabpanel aria-labelledby=t-hw hidden>
  <div class=card>
    <h2>Heartwood — is your AI throttling you?</h2>
    <p class=note>A provider can serve the model you paid for while quietly
    spending less compute. Answers still look fine; the bill does not change.
    <b style="color:var(--ink)">Heartwood</b> asks questions that cannot be
    answered without doing the work, binds challenge selection to public
    randomness, and issues a transferable receipt.
    <b style="color:var(--ink)">This is not privacy</b> — that is the rest of
    Oblivio. This checks whether the work was done.</p>
    <div id=hwstatus class=okbox style="display:none;margin-top:.8rem"></div>
    <div id=hwmissing style="display:none;margin-top:1rem;border:1px solid var(--line);
         border-radius:.6rem;padding:1rem 1.15rem;background:rgba(0,0,0,.25)">
      <div style="font-weight:650;font-size:.95rem;margin-bottom:.4rem">
        Heartwood engine not found</div>
      <pre class=mono id=hwmissingtext style="white-space:pre-wrap;font-size:.8rem;
        color:var(--muted);margin:0"></pre>
      <div class=actions style="margin-top:.9rem">
        <button class=go id=hwinstall style="margin-top:0">Install Heartwood</button>
        <a class=ghost href="https://github.com/zcashsensei/heartwood" target=_blank
           rel=noopener style="display:inline-block;padding:.5rem 1rem;
           text-decoration:none;border:1px solid var(--line);border-radius:.45rem;
           color:var(--ink);font-size:.88rem">View on GitHub</a>
      </div>
      <p class=note style="margin-top:.7rem;font-size:.8rem">Install clones the
      official repo next to Oblivio (fixed URL only). Requires <span class=mono>git</span>.</p>
    </div>
    <div class=grid2 id=hwform style="margin-top:1.1rem">
      <div><label for=hw-target>Which AI are you checking?</label>
        <select id=hw-target>
          <option value=haiku>Claude Haiku 4.5 — fast and cheap</option>
          <option value=sonnet>Claude Sonnet 5</option>
          <option value=opus>Claude Opus 5 — top tier</option>
          <option value=gpt5>OpenAI GPT-5</option>
          <option value=local>A model on this machine (Ollama)</option>
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
    <div class=warnbox id=hwwarn style="display:none">This calls the provider
    under check. It is an audit of effort, not a private path. API keys are
    read from your environment by Heartwood (not stored in Oblivio).</div>
    <button class=go id=hwgo>Run Heartwood check</button>
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
const api = (p,o={}) => fetch(p,{...o,headers:{'X-Oblivio-Token':TOKEN,
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

let STATE = null;
let LAST_PROOF = null;
let OPEN_IDX = null;
let MODAL_DISMISSED = false;   // "Not now" this session only
// Labels live inside ciphertext; the list endpoint cannot show them. Cache
// what we decrypt in this session so the filter can use real names.
const LABEL_CACHE = {};

function paintRail(s){
  const p = s.privacy || {};
  const pills = [
    ['on','localhost only'],
    ['on','encrypted on this device'],
    [p.key_sealed_at_rest ? 'good' : 'warn',
      p.key_sealed_at_rest ? 'key sealed at rest' : 'key not sealed on disk'],
    [p.unlocked ? 'good' : (p.key_sealed_at_rest ? 'warn' : 'on'),
      p.unlocked ? 'unlocked this session' : (p.key_sealed_at_rest ? 'locked' : 'no key yet')],
    [p.sends_data_out ? 'bad' : 'on', p.sends_data_out ? 'phones home' : 'does not phone home'],
    [p.agent_access ? 'warn' : 'good', p.agent_access ? 'agent access ON' : 'agent access off'],
    ['warn','frontier chat ≠ private by default'],
  ];
  $('rail').innerHTML = pills.map(([k,t])=>`<span class="pill ${k}">${esc(t)}</span>`).join('');
}

function paintStats(s){
  const html =
    `<div class=stat><b>${s.records??0}</b><span>memories kept</span></div>
     <div class=stat><b>${s.tree_size??'—'}</b><span>entries in the log</span></div>
     <div class=stat><b>${s.integrity==='verified'?'verified':'—'}</b><span>log integrity</span></div>
     <div class=stat><b>${s.pin_held?'held':'—'}</b><span>local pin</span></div>`;
  $('stats').innerHTML = html;
  $('proofstats').innerHTML = html;
  if($('truthstats')){
    const p = s.privacy || {};
    $('truthstats').innerHTML =
      `<div class=stat><b>${p.key_sealed_at_rest?'yes':'no'}</b><span>key sealed at rest</span></div>
       <div class=stat><b>${p.unlocked?'yes':'no'}</b><span>unlocked this session</span></div>
       <div class=stat><b>${p.sends_data_out?'yes':'no'}</b><span>phones home</span></div>
       <div class=stat><b>no</b><span>frontier private by default</span></div>`;
  }
  if($('secstats')){
    const p = s.privacy || {};
    $('secstats').innerHTML =
      `<div class=stat><b>${s.node?'up':'down'}</b><span>local node</span></div>
       <div class=stat><b>${p.key_sealed_at_rest?'yes':'no'}</b><span>key sealed on disk</span></div>
       <div class=stat><b>${p.unlocked?'unlocked':'locked'}</b><span>this session</span></div>
       <div class=stat><b>${s.heartwood?'ready':'install'}</b><span>Heartwood</span></div>
       <div class=stat><b>${p.sends_data_out?'yes':'no'}</b><span>phones home</span></div>
       <div class=stat><b>127.0.0.1</b><span>bind address</span></div>`;
    const bits = [];
    if(p.key_sealed_at_rest) bits.push('<span class="pill good">disk key sealed</span>');
    else bits.push('<span class="pill warn">set a passphrase soon</span>');
    if(p.unlocked) bits.push('<span class="pill on">session unlocked</span>');
    else if(p.key_sealed_at_rest) bits.push('<span class="pill warn">locked — unlock to read/write</span>');
    if(s.heartwood) bits.push('<span class="pill good">Heartwood ready</span>');
    else bits.push('<span class="pill on">Heartwood optional</span>');
    if(!p.sends_data_out) bits.push('<span class="pill good">does not phone home</span>');
    if(p.agent_access) bits.push('<span class="pill warn">agent access ON</span>');
    else bits.push('<span class="pill good">agent access off</span>');
    bits.push('<span class="pill warn">frontier chat ≠ private by default</span>');
    $('secposture').innerHTML = '<div class=rail style="margin:0">'+bits.join('')+'</div>';
  }
}

function paintList(s){
  const q = ($('rfilter').value||'').trim().toLowerCase();
  const rows = (s.list||[]).filter(r=>{
    if(!q) return true;
    const lab = LABEL_CACHE[r.index] || r.label || '';
    return String(lab).toLowerCase().includes(q)
        || String(r.index??'').includes(q);
  });
  $('welcome').style.display = s.records ? 'none' : 'grid';
  $('keepnote').textContent = s.records
    ? 'Everything below was encrypted here before the node saw it. Click to decrypt locally.'
    : 'Nothing kept yet. Open Remember and write your first memory — you will be asked to save your master key first.';
  if(!rows.length){
    $('recs').innerHTML = s.list && s.list.length
      ? '<span class=note>no memories match that filter</span>'
      : '<span class=note>nothing yet</span>';
    return;
  }
  $('recs').innerHTML = rows.slice().reverse().map(r=>{
    const i = r.index;
    // Labels from list are empty by design (node never stores them). After you
    // open a record here, its name is cached for this session only.
    const title = LABEL_CACHE[i] || r.label || ('record #'+i);
    return `<div class=rec data-i="${i}">
      <span>${esc(title)}</span>
      <span class=acts>
        <button class=mini data-act=open data-i="${i}">open</button>
        <button class=mini data-act=prove data-i="${i}">prove</button>
        <span class=i>#${i}</span>
      </span></div>`;
  }).join('');
  document.querySelectorAll('.rec').forEach(el=>{
    el.onclick = e=>{
      const btn = e.target.closest('button.mini');
      const i = el.dataset.i;
      if(btn && btn.dataset.act==='prove'){ e.stopPropagation(); doProve(i, true); return; }
      openRecord(i);
    };
  });
}

async function openRecord(i){
  OPEN_IDX = i;
  $('reader').style.display='block';
  $('proveres').innerHTML='';
  $('readertext').textContent='decrypting…';
  $('readermeta').textContent = 'record #'+i;
  const r = await (await api('/api/read/'+i)).json();
  if(r.error){ $('readertext').textContent='could not open: '+r.error; return; }
  const lab = (r.meta&&r.meta.label) ? r.meta.label : '';
  if(lab) LABEL_CACHE[i] = lab;
  $('readermeta').textContent =
    (lab?lab+' · ':'')+'record #'+i+' · decrypted here, not on the node · inclusion verified';
  $('readertext').textContent = r.text;
  $('proveidx').value = i;
  if(STATE) paintList(STATE);
}

async function refresh(){
  let s;
  try { s = await (await api('/api/state')).json(); }
  catch(e){ $('tag').textContent='could not reach the app'; return; }
  STATE = s;
  if(!s.node){ $('tag').textContent='node did not start: '+(s.why||'');
    paintRail(s); return; }
  $('tag').textContent = 'encrypted memory · the node cannot read it';
  paintRail(s);
  paintStats(s);
  paintList(s);
  $('root').textContent = s.root || '—';
  $('integrity').className = 'okbox';
  $('integrity').innerHTML = s.pin_held
    ? '<b style="color:var(--good)">Verified.</b> Signed head checked; append-only pin held on this machine. A rewrite would be refused.'
    : '<b style="color:var(--good)">Verified.</b> Signed head checked this session. A pin will be written on the first read or write.';
  if(s.key_sealed_at_rest && s.unlocked){
    $('keystatus').className='okbox';
    $('keystatus').innerHTML='Unlocked. Working key is in memory only; on disk it is passphrase-sealed. Export another zip anytime.';
  } else if(s.key_sealed_at_rest && !s.unlocked){
    $('keystatus').className='warnbox';
    $('keystatus').innerHTML='Sealed on disk — <b style="color:var(--ink)">locked this session</b>. Enter your passphrase to open the keep.';
  } else if(s.legacy_plaintext){
    $('keystatus').className='warnbox';
    $('keystatus').innerHTML='Legacy plaintext key on disk. Unlock with a passphrase to seal it and remove the readable file.';
  } else {
    $('keystatus').className='warnbox';
    $('keystatus').textContent='No sealed key yet. Set a passphrase before storing anything you would miss.';
  }
  $('writewarn').style.display = (s.key_backed_up && s.key_sealed_at_rest) ? 'none' : 'block';
  // Locked → unlock. No sealed key yet → setup (first visit, not only after write).
  if(s.key_sealed_at_rest && !s.unlocked && !MODAL_DISMISSED){
    openKeyModal('unlock');
  } else if(!s.key_sealed_at_rest && !MODAL_DISMISSED){
    openKeyModal('setup');
  }
  // Heartwood tab readiness
  if(s.heartwood){
    $('hwform').style.display=''; $('hwgo').style.display='';
    $('hwmissing').style.display='none';
    $('hwwarn').style.display='block';
    $('hwstatus').style.display='block';
    $('hwstatus').innerHTML = 'Heartwood ready'
      +(s.heartwood_path ? ' · <span class=mono>'+esc(s.heartwood_path)+'</span>' : '');
  } else {
    $('hwform').style.display='none'; $('hwgo').style.display='none';
    $('hwwarn').style.display='none';
    $('hwstatus').style.display='none';
    $('hwmissing').style.display='block';
    $('hwmissingtext').textContent = s.heartwood_error || 'not available';
  }
}
if($('hwinstall')) $('hwinstall').onclick = async ()=>{
  $('hwinstall').disabled = true;
  $('hwinstall').textContent = 'Installing…';
  try{
    const r = await (await api('/api/hw/install',{method:'POST',body:'{}'})).json();
    if(!r.ok){ $('hwmissingtext').textContent = r.error || 'install failed'; return; }
    await refresh();
  }catch(e){ $('hwmissingtext').textContent = String(e); }
  finally{ $('hwinstall').disabled = false; $('hwinstall').textContent = 'Install Heartwood'; }
};
refresh();
$('rfilter').oninput = ()=>{ if(STATE) paintList(STATE); };
$('rhide').onclick = ()=>{ $('reader').style.display='none'; OPEN_IDX=null; };

let KEY_MODAL_MODE = 'setup'; // setup | unlock | export

async function openKeyModal(mode){
  KEY_MODAL_MODE = mode || 'setup';
  $('keymodal').classList.add('show');
  const unlock = KEY_MODAL_MODE === 'unlock';
  const exp = KEY_MODAL_MODE === 'export';
  $('keymodaltitle').textContent = unlock
    ? 'Unlock your keep'
    : (exp ? 'Download sealed backup zip' : 'Create your passphrase');
  $('keymodalhelp').textContent = unlock
    ? 'This keep is already sealed. Enter the passphrase you chose before — this is not a “new password” screen. Wrong passphrase will fail. Use Start over only if you accept losing the old key.'
    : (exp
      ? 'Enter your current passphrase twice to download a fresh sealed zip backup.'
      : 'Choose a passphrase (at least 10 characters), type it twice, then Seal. You will get a sealed zip. There is no email reset.');
  $('keypw').value = '';
  $('keypw2').value = '';
  $('keypw2').style.display = unlock ? 'none' : 'block';
  $('keypw2lab').style.display = unlock ? 'none' : 'block';
  $('keypw').autocomplete = unlock ? 'current-password' : 'new-password';
  $('keymodalsave').textContent = unlock ? 'Unlock' : (exp ? 'Download sealed zip' : 'Seal + download backup');
  $('keymodalok').style.display = unlock ? 'none' : 'block';
  $('keymodalreset').style.display = unlock ? 'inline-block' : 'none';
  $('keymodalerr').style.display = 'none';
  try{
    const r = await (await api('/api/key')).json();
    if(r.path) $('keypath').textContent = r.path;
  }catch(e){ /* ok */ }
  setTimeout(()=>$('keypw').focus(), 50);
}
function closeKeyModal(){ $('keymodal').classList.remove('show'); }
function keyModalErr(msg){
  const el = $('keymodalerr');
  el.style.display = 'block';
  el.textContent = msg;
}

$('keymodallater').onclick = ()=>{ MODAL_DISMISSED=true; closeKeyModal(); };
if($('keymodalreset')) $('keymodalreset').onclick = async ()=>{
  if(!confirm('Start over?\n\nThis deletes the sealed key on this machine so you can choose a NEW passphrase.\n\nAny memories already stored cannot be opened without the OLD passphrase. Continue?')) return;
  const confirmWord = prompt('Type start over to confirm:');
  if((confirmWord||'').trim().toLowerCase() !== 'start over'){
    keyModalErr('Reset cancelled — type exactly: start over');
    return;
  }
  try{
    const res = await api('/api/key/reset',{method:'POST',
      body:JSON.stringify({confirm:'start over'})});
    const r = await res.json();
    if(!res.ok){ keyModalErr(r.error||'reset failed'); return; }
    MODAL_DISMISSED = false;
    closeKeyModal();
    await refresh();
    openKeyModal('setup');
  }catch(e){ keyModalErr('could not reset: '+e); }
};
$('keymodalsave').onclick = async ()=>{
  const pw = $('keypw').value;
  const pw2 = $('keypw2').value;
  if(KEY_MODAL_MODE === 'unlock'){
    if(!pw){ keyModalErr('Enter your passphrase.'); return; }
    $('keymodalsave').disabled = true;
    $('keymodalsave').textContent = 'Unlocking…';
    try{
      const res = await api('/api/key/unlock',{method:'POST',
        body:JSON.stringify({passphrase:pw})});
      const body = await res.json().catch(()=>({}));
      if(!res.ok){
        keyModalErr(body.error || 'Wrong passphrase. Use Start over only if you forgot it.');
        $('keymodalreset').style.display = 'inline-block';
        return;
      }
      $('keypw').value = '';
      closeKeyModal();
      MODAL_DISMISSED = false;
      await refresh();
    }catch(e){ keyModalErr('could not unlock — is the app still running?'); }
    finally{ $('keymodalsave').disabled = false; $('keymodalsave').textContent = 'Unlock'; }
    return;
  }
  if(pw.length < 10){ keyModalErr('Passphrase must be at least 10 characters.'); return; }
  if(pw !== pw2){ keyModalErr('Passphrases do not match — type the same one twice.'); return; }
  $('keymodalsave').disabled = true;
  $('keymodalsave').textContent = 'Sealing (a few seconds)…';
  try{
    const path = KEY_MODAL_MODE === 'export' ? '/api/key/export' : '/api/key/setup';
    const res = await api(path,{method:'POST',
      body:JSON.stringify({passphrase:pw, passphrase_confirm:pw2})});
    if(!res.ok){
      const err = await res.json().catch(()=>({}));
      keyModalErr(err.error || 'failed');
      if(err.can_reset) $('keymodalreset').style.display = 'inline-block';
      return;
    }
    const blob = await res.blob();
    if(blob.size < 50){ keyModalErr('Backup download was empty — try again.'); return; }
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'oblivio-master-key.zip';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);
    $('keypw').value = '';
    $('keypw2').value = '';
    closeKeyModal();
    MODAL_DISMISSED = false;
    await refresh();
  }catch(e){
    keyModalErr('could not seal / export: '+(e.message||e));
  }finally{
    $('keymodalsave').disabled = false;
    $('keymodalsave').textContent = KEY_MODAL_MODE==='export' ? 'Download sealed zip' : 'Seal + download backup';
  }
};

async function writeMemory(force){
  const text=$('wtext').value.trim(); if(!text) return;
  $('wgo').disabled=true;
  const body={text,label:$('wlabel').value};
  if(force) body.i_accept_no_backup = true;
  const res = await api('/api/write',{method:'POST',body:JSON.stringify(body)});
  const r = await res.json();
  $('wgo').disabled=false;
  if(r.code==='key_locked'){
    $('wres').innerHTML =
      `<div class=res style="border-color:var(--gold)">
        <b style="color:var(--gold)">Unlock first.</b>
        <p class=note style="margin-top:.4rem">Your key is sealed on disk for this session.</p></div>`;
    openKeyModal('unlock');
    return;
  }
  if(r.code==='key_not_backed_up'){
    $('wres').innerHTML =
      `<div class=res style="border-color:var(--gold)">
        <b style="color:var(--gold)">Seal your master key first.</b>
        <p class=note style="margin-top:.4rem">${esc(r.hint||'')}</p>
        <div class=actions>
          <button class=go id=wbackup style="margin-top:0">Set passphrase + download zip</button>
          <button class=ghost id=wforce>Save memory anyway (I accept permanent loss)</button>
        </div></div>`;
    $('wbackup').onclick = ()=>openKeyModal(r.needs_setup ? 'setup' : 'export');
    $('wforce').onclick = ()=>writeMemory(true);
    openKeyModal(r.needs_setup ? 'setup' : 'export');
    await refresh();
    return;
  }
  $('wres').innerHTML = r.ok
    ? `<div class=res style="border-color:var(--good)"><b style="color:var(--good)">Kept.</b>
       <div class=mono style="margin-top:.4rem">encrypted here · the node stored a blob it cannot read
       · log head verified</div></div>`
    : `<div class=res style="border-color:var(--bad)"><b style="color:var(--bad)">Failed.</b>
       <div class=mono>${esc(r.error||'')}</div></div>`;
  if(r.ok){ $('wtext').value=''; $('wlabel').value=''; refresh(); }
}
$('wgo').onclick=()=>writeMemory(false);

$('keyprompt').onclick=()=>{
  MODAL_DISMISSED=false;
  const s = STATE || {};
  if(s.key_sealed_at_rest && !s.unlocked) openKeyModal('unlock');
  else if(!s.key_sealed_at_rest) openKeyModal('setup');
  else openKeyModal('export');
};

async function doProve(idx, stay){
  $('proveout').innerHTML = '<span class=note>building zero-knowledge proof…</span>';
  $('proveres').innerHTML = '<span class=note>building zero-knowledge proof…</span>';
  const res = await api('/api/prove',{method:'POST',body:JSON.stringify({index:Number(idx)})});
  const r = await res.json();
  LAST_PROOF = r.bundle || null;
  const box = r.ok
    ? `<div class=res style="border-color:var(--good)">
        <b style="color:var(--good)">VERIFIED</b>
        <p class=note style="margin-top:.4rem">${esc(r.statement||'')}</p>
        <div class=mono style="margin-top:.5rem">branches ${r.branches} · tree size ${r.tree_size}
        · index not in proof: ${r.proof_has_index?'NO — bug':'yes'}
        · root ${esc((r.root||'').slice(0,16))}…</div></div>`
    : `<div class=res style="border-color:var(--bad)"><b style="color:var(--bad)">Failed.</b>
        <div class=mono>${esc(r.error||'proof did not verify')}</div></div>`;
  $('proveout').innerHTML = box;
  $('proveres').innerHTML = box;
  $('provedl').style.display = LAST_PROOF ? 'inline-block' : 'none';
  if(!stay){
    tabs.forEach(o=>{const on=o.id==='t-proof';
      o.setAttribute('aria-selected',on); $(o.getAttribute('aria-controls')).hidden=!on;});
  }
}
$('provego').onclick=()=>{
  const i=$('proveidx').value;
  if(i===''||i==null){ $('proveout').innerHTML='<span class=note>pick a record number</span>'; return; }
  doProve(i, false);
};
$('rprove').onclick=()=>{ if(OPEN_IDX!=null) doProve(OPEN_IDX, true); };
$('provedl').onclick=()=>{
  if(!LAST_PROOF) return;
  const blob = new Blob([JSON.stringify(LAST_PROOF,null,2)],{type:'application/json'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob); a.download='oblivio-membership-proof.json';
  a.click(); URL.revokeObjectURL(a.href);
};

async function agentPaint(a){
  const on=a.enabled;
  $('agenttoggle').textContent = on ? 'Turn off agent access' : 'Turn on agent access';
  $('agentbox').style.display = on ? 'block' : 'none';
  if(STATE){ STATE.privacy = STATE.privacy||{}; STATE.privacy.agent_access=on; paintRail(STATE); }
  if(!on) return;
  $('agenturl').textContent = a.url;
  $('agenttok').textContent = a.token;
  $('agentex').textContent =
`# save a memory
curl -s ${a.url}/api/write \\
  -H "X-Oblivio-Token: ${a.token}" \\
  -H "Content-Type: application/json" \\
  -d '{"text":"remember this","label":"note","i_accept_no_backup":true}'

# read memory #0 back
curl -s "${a.url}/api/read/0" -H "X-Oblivio-Token: ${a.token}"`;
}
$('agenttoggle').onclick=async()=>{
  const cur=$('agentbox').style.display==='block';
  const a=await (await api('/api/agent',{method:'POST',
    body:JSON.stringify({enabled:!cur})})).json();
  agentPaint(a);
};
api('/api/agent').then(r=>r.json()).then(agentPaint).catch(()=>{});

function ftModePaint(){
  const gw = ($('ft-mode').value==='gateway');
  $('ft-gw-wrap').style.display = gw?'block':'none';
  $('ft-tok-wrap').style.display = gw?'block':'none';
  // OHTTP splits the gateway's roles, so it only exists on the gateway path.
  $('ft-relay-wrap').style.display = gw?'block':'none';
  $('ft-ohttp-wrap').style.display = gw?'block':'none';
  $('ft-relay-note').style.display = gw?'block':'none';
  $('ft-base-wrap').style.display = gw?'none':'block';
  $('ft-key-wrap').style.display = gw?'none':'block';
}
$('ft-mode').onchange = ftModePaint; ftModePaint();

$('ft-go').onclick = async ()=>{
  const text = ($('ft-text').value||'').trim();
  if(!text){ $('ft-out').innerHTML='<span class=note>type a question</span>'; return; }
  if(!$('ft-enable').checked || !$('ft-accept').checked){
    $('ft-out').innerHTML='<div class=warnbox>Both acknowledgements are required.</div>';
    return;
  }
  const useGw = $('ft-mode').value==='gateway';
  const body = {
    text,
    model: $('ft-model').value.trim(),
    local_model: $('ft-local').value.trim()||'llama3.2',
    enable_frontier: true,
    accept_residual_risks: true,
    with_keep: $('ft-keep').checked,
  };
  if(useGw){
    body.gateway_url = $('ft-gw').value.trim();
    try { body.token = JSON.parse($('ft-token').value||'{}'); }
    catch(e){ $('ft-out').innerHTML='<div class=warnbox>Token JSON is invalid.</div>'; return; }
    const relay = $('ft-relay').value.trim();
    const cfg = $('ft-ohttp').value.trim();
    if(relay && !cfg){
      $('ft-out').innerHTML='<div class=warnbox>A relay needs the gateway\'s '
        +'ohttp_key_config_b64 (GET /v1/params). Without it there is no OHTTP '
        +'send, and this refuses rather than quietly going direct.</div>';
      return;
    }
    if(relay){ body.relay_url = relay; body.ohttp_config = cfg; }
  } else {
    body.api_base = $('ft-base').value.trim();
    body.api_key = $('ft-key').value;
  }
  $('ft-go').disabled = true;
  $('ft-go').textContent = 'Running stack…';
  $('ft-out').innerHTML = '<span class=note>abstract · LeakGate · '
    +(useGw?'blind token · gateway':'API key')+' …</span>';
  try{
    const res = await api('/api/frontier-chat',{method:'POST',body:JSON.stringify(body)});
    const r = await res.json();
    if(!res.ok || r.error){
      $('ft-out').innerHTML = `<div class=res style="border-color:var(--bad)">
        <b style="color:var(--bad)">Refused — nothing private was sent.</b>
        <p class=note style="margin-top:.4rem">${esc(r.error||'failed')}</p></div>`;
      return;
    }
    const claims = (r.claims||[]).map(c=>`<li>${esc(c)}</li>`).join('');
    const residual = (r.residual||[]).map(c=>`<li>${esc(c)}</li>`).join('');
    const idOk = r.identity_private ? 'var(--good)' : 'var(--warn)';
    const mdOk = r.metadata_private ? 'var(--good)' : 'var(--warn)';
    // Why metadata privacy was or was not granted. Shown always: the refusal
    // reason is the part a reader needs, and it used to be invisible.
    const mdWhy = (r.metadata_reasons||[]).map(c=>`<li>${esc(c)}</li>`).join('');
    $('ft-out').innerHTML = `
      <div class=res style="border-color:var(--good)">
        <b style="color:var(--good)">Reply</b>
        <pre style="white-space:pre-wrap;font-size:.9rem;margin:.5rem 0 0">${esc(r.reply||'')}</pre>
      </div>
      <div class=card style="margin-top:.8rem">
        <h2 style="font-size:.95rem">Receipt</h2>
        <p class=note>${esc(r.notice||'')}</p>
        <label>Mode</label><div class=mono>${esc(r.mode)} · attempts ${esc(r.attempts)} ·
          account_decoupled=${esc(r.account_decoupled)}</div>
        <label>Transport that actually carried it</label>
        <div class=mono>${esc(r.transport||'direct')}${
          r.transport==='ohttp'?' — client → relay → gateway':' — client → gateway'}</div>
        <div class="${r.metadata_private?'okbox':'warnbox'}" style="margin-top:.7rem">
          <b>Network metadata${r.metadata_private?'' : ' — not private'}</b>
          <ul class=plain>${mdWhy}</ul></div>
        <label>Exactly what left toward the provider / gateway</label>
        <pre class=mono style="white-space:pre-wrap;font-size:.78rem;background:rgba(0,0,0,.3);
          border:1px solid var(--line);border-radius:.45rem;padding:.7rem">${esc(r.sent||'')}</pre>
        <div class=okbox style="margin-top:.7rem"><b>Claims</b><ul class=plain>${claims}</ul></div>
        <div class=warnbox style="margin-top:.7rem"><b>Residual — not claimed</b><ul class=plain>${residual}</ul></div>
        <p class=note style="margin-top:.6rem">
          <span style="color:${idOk}">identity_private=${esc(r.identity_private)}</span> ·
          <span style="color:${mdOk}">metadata_private=${esc(r.metadata_private)}</span> ·
          content_private=${esc(r.content_private)}</p>
      </div>`;
  }catch(e){
    $('ft-out').innerHTML = `<div class=res style="border-color:var(--bad)"><b style="color:var(--bad)">Error</b>
      <p class=note>${esc(e.message||e)}</p></div>`;
  }finally{
    $('ft-go').disabled = false;
    $('ft-go').textContent = 'Run historic stack';
  }
};

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
        from oblivio._console import use_utf8_stdout
        use_utf8_stdout()
    except Exception:
        pass

    ok, how = ensure_node()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    url = f"http://127.0.0.1:{PORT}"
    print(f"Oblivio -> {url}")
    print(f"  node: {'up (' + how + ')' if ok else 'FAILED: ' + how}")
    print("  bound to localhost only. Ctrl-C to stop.")
    # Interactive launches only (2026-08-13). Opening unconditionally meant every restart
    # — including a supervised one — stole focus with a new tab. `launch.pyw` is the
    # deliberate "open the app" entry point and still opens a browser; this path is the
    # server, and a server should not. `--open` forces, `--no-open` always wins.
    _interactive = bool(getattr(sys.stdout, "isatty", lambda: False)())
    if "--no-open" not in sys.argv and ("--open" in sys.argv or _interactive):
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
