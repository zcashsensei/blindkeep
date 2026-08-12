"""One-shot smoke of the local app UI endpoints. Not part of the suite."""
import json
import re
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8743"


def main() -> int:
    html = urllib.request.urlopen(BASE + "/").read().decode()
    m = re.search(r'const TOKEN = "([^"]+)"', html)
    assert m, "no token in page"
    token = m.group(1)
    print("token ok", len(token))
    for needle in ("keymodal", "Save your master key", "Privacy posture",
                   "Prove I hold", "localhost only"):
        assert needle in html, f"missing UI marker: {needle}"
    print("ui markers ok")

    def req(path, data=None):
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
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    code, st = req("/api/state")
    print("state", code, "records", st.get("records"),
          "key", st.get("key_exists"), "backed", st.get("key_backed_up"))
    assert st["privacy"]["bound"] == "loopback"
    assert st["privacy"]["sends_data_out"] is False

    code, w = req("/api/write", {"text": "secret note", "label": "test"})
    print("write no backup", code, w.get("code"))
    assert code == 409 and w.get("code") == "key_not_backed_up"

    code, k = req("/api/key")
    print("key", code, "bytes", k.get("bytes"))
    assert code == 200 and k["bytes"] == 32

    code, a = req("/api/key/ack", {})
    print("ack", code, a)
    assert a.get("ok")

    code, w = req("/api/write", {"text": "secret note", "label": "test"})
    print("write after ack", code, w.get("ok"), (w.get("record") or {}).get("index"))
    assert w.get("ok")

    code, st = req("/api/state")
    print("after", st["records"], st["key_backed_up"], (st.get("root") or "")[:16])
    assert st["key_backed_up"] and st["records"] >= 1

    code, p = req("/api/prove", {"index": int((w.get("record") or {}).get("index", 0))})
    print("prove", code, p.get("ok"), (p.get("statement") or "")[:70],
          "has_idx", p.get("proof_has_index"))
    assert p.get("ok") and p.get("proof_has_index") is False

    # download should return raw bytes
    r = urllib.request.Request(
        BASE + "/api/key/download?t=" + token,
        headers={"Host": "127.0.0.1:8743"},
    )
    with urllib.request.urlopen(r) as resp:
        raw = resp.read()
        assert len(raw) == 32, len(raw)
        assert "attachment" in resp.headers.get("Content-Disposition", "")
    print("download ok")
    print("ALL SMOKE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
