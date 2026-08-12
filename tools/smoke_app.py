"""One-shot smoke of the local app UI endpoints. Not part of the suite."""
import io
import json
import re
import urllib.error
import urllib.request
import zipfile

BASE = "http://127.0.0.1:8743"


def main() -> int:
    html = urllib.request.urlopen(BASE + "/").read().decode()
    m = re.search(r'const TOKEN = "([^"]+)"', html)
    assert m, "no token in page"
    token = m.group(1)
    print("token ok", len(token))
    for needle in ("keymodal", "sealed zip", "Privacy posture",
                   "Prove I hold", "localhost only", "Download sealed zip"):
        assert needle in html, f"missing UI marker: {needle}"
    assert "keymodalhex" not in html, "raw hex UI must not ship"
    assert "Copy hex" not in html, "copy-hex must not ship"
    print("ui markers ok")

    def req(path, data=None, raw=False):
        body = None if data is None else json.dumps(data).encode()
        r = urllib.request.Request(
            BASE + path, data=body,
            method="POST" if body is not None else "GET",
            headers={
                "X-Blindkeep-Token": token,
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
                return e.code, json.loads(raw_body.decode())
            except Exception:
                return e.code, raw_body

    code, st = req("/api/state")
    print("state", code, "records", st.get("records"),
          "key", st.get("key_exists"), "backed", st.get("key_backed_up"))
    assert st["privacy"]["bound"] == "loopback"
    assert st["privacy"]["backup_format"] == "passphrase-sealed zip"

    code, w = req("/api/write", {"text": "secret note", "label": "test"})
    print("write no backup", code, w.get("code"))
    assert code == 409 and w.get("code") == "key_not_backed_up"

    code, k = req("/api/key")
    print("key meta", code, k)
    assert code == 200 and k.get("hex") is None
    assert k.get("raw_download") is False

    # Raw GET download must be refused
    code, refused = req("/api/key/download")
    print("raw download", code, refused.get("error") if isinstance(refused, dict) else refused)
    assert code == 405

    # Sealed export
    pw = "correct-horse-test-passphrase"
    code, blob, headers = req(
        "/api/key/export",
        {"passphrase": pw, "passphrase_confirm": pw},
        raw=True,
    )
    print("export", code, "bytes", len(blob) if isinstance(blob, (bytes, bytearray)) else type(blob))
    assert code == 200 and isinstance(blob, (bytes, bytearray))
    assert b"PK" == blob[:2]  # zip magic
    assert "zip" in (headers.get("Content-Type") or "")
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        names = set(zf.namelist())
        assert "master.key.sealed" in names and "README.txt" in names
        sealed = zf.read("master.key.sealed")
        assert sealed.startswith(b"BK1\0")
        # sealed payload must not be the raw 32-byte key
        assert len(sealed) > 32

    # Round-trip open
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import app as appmod
    raw = appmod.open_master_key_zip(bytes(blob), pw)
    assert len(raw) == 32
    print("seal round-trip ok")

    code, st = req("/api/state")
    assert st["key_backed_up"], "export should auto-ack backup"

    code, w = req("/api/write", {"text": "secret note", "label": "test"})
    print("write after export", code, w.get("ok"), (w.get("record") or {}).get("index"))
    assert w.get("ok")

    code, p = req("/api/prove", {"index": int((w.get("record") or {}).get("index", 0))})
    print("prove", code, p.get("ok"), "has_idx", p.get("proof_has_index"))
    assert p.get("ok") and p.get("proof_has_index") is False

    print("ALL SMOKE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
