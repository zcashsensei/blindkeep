"""One-shot smoke of the local app UI endpoints. Not part of the suite."""
import io
import json
import re
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

BASE = "http://127.0.0.1:8743"
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> int:
    html = urllib.request.urlopen(BASE + "/").read().decode()
    m = re.search(r'const TOKEN = "([^"]+)"', html)
    assert m, "no token in page"
    token = m.group(1)
    print("token ok", len(token))
    for needle in ("keymodal", "Seal on disk", "Privacy posture",
                   "Truth: frontier models", "sealed"):
        assert needle in html, f"missing UI marker: {needle}"
    assert "Copy hex" not in html
    print("ui markers ok")

    def req(path, data=None, raw=False):
        body = None if data is None else json.dumps(data).encode()
        r = urllib.request.Request(
            BASE + path, data=body,
            method="POST" if body is not None else "GET",
            headers={
                "X-Oblivio-Token": token,
                "Content-Type": "application/json",
                "Host": "127.0.0.1:8743",
            },
        )
        try:
            with urllib.request.urlopen(r) as resp:
                raw_body = resp.read()
                if raw:
                    return resp.status, raw_body, resp.headers
                return resp.status, json.loads(raw_body.decode())
        except urllib.error.HTTPError as e:
            raw_body = e.read()
            try:
                parsed = json.loads(raw_body.decode())
            except Exception:
                parsed = raw_body
            if raw:
                return e.code, parsed, e.headers
            return e.code, parsed

    code, st = req("/api/state")
    print("state", code, st.get("unlocked"), st.get("key_sealed_at_rest"))
    assert st["privacy"]["frontier_private_by_default"] is False
    assert st["privacy"]["sends_data_out"] is False

    code, w = req("/api/write", {"text": "secret note", "label": "test"})
    print("write gated", code, w.get("code"))
    assert code in (409, 423), w

    pw = "correct-horse-test-passphrase"
    code, blob, headers = req(
        "/api/key/setup",
        {"passphrase": pw, "passphrase_confirm": pw},
        raw=True,
    )
    print("setup", code, "zip", isinstance(blob, (bytes, bytearray)), len(blob) if isinstance(blob, (bytes, bytearray)) else blob)
    assert code == 200 and isinstance(blob, (bytes, bytearray)) and blob[:2] == b"PK"
    assert (ROOT / "data" / "master.key.sealed").is_file(), "sealed at rest missing"
    assert not (ROOT / "data" / "master.key").is_file(), "plaintext key must be gone"

    import app as appmod
    raw = appmod.open_master_key_zip(bytes(blob), pw)
    assert len(raw) == 32
    assert appmod.open_payload(
        (ROOT / "data" / "master.key.sealed").read_bytes(), pw) == raw
    print("seal round-trip ok")

    code, st = req("/api/state")
    assert st["unlocked"] and st["key_sealed_at_rest"] and st["key_backed_up"]

    code, w = req("/api/write", {"text": "secret note", "label": "test"})
    print("write after setup", code, w.get("ok"))
    assert w.get("ok")

    # Lock session in the running server, then unlock again
    code, locked = req("/api/key/lock", {})
    assert locked.get("ok")
    code, st = req("/api/state")
    assert st["key_sealed_at_rest"] and not st["unlocked"]
    code, w = req("/api/write", {"text": "again", "label": "x"})
    assert code == 423 and w.get("code") == "key_locked"
    code, u = req("/api/key/unlock", {"passphrase": pw})
    print("unlock", code, u)
    assert u.get("ok")
    code, w = req("/api/write", {"text": "after unlock", "label": "x"})
    assert w.get("ok")

    print("ALL SMOKE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
