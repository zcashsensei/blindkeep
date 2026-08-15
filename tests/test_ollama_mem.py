"""Local model memory tests.

A fake model server stands in for Ollama, so the suite runs anywhere and does
not require a model to be installed. The tests that matter most are the ones
asserting where data does NOT go.
"""

import json
import os
import shutil
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oblivio.client import OblivioClient
from oblivio.crypto import generate_master_key
from oblivio.node import _Handler
from oblivio.ollama_mem import (
    NotLocalError,
    OllamaMemory,
    OllamaUnavailable,
    _assert_local,
)
from oblivio.store import MemoryStore

SERVERS = []
TMPDIRS = []
SEEN_REQUESTS = []


def tmpdir():
    d = tempfile.mkdtemp(prefix="oblivio-ollama-")
    TMPDIRS.append(d)
    return d


def oblivio_node():
    d = tmpdir()
    store = MemoryStore(os.path.join(d, "node"))
    h = type("H", (_Handler,), {"store": store, "log_message": lambda *a, **k: None})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), h)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    client = OblivioClient(f"http://127.0.0.1:{httpd.server_address[1]}",
                             generate_master_key(),
                             pin_path=os.path.join(d, "pin.json"))
    return client, store, d


def fake_ollama(reply="I remember."):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def _json(self, obj):
            body = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._json({"models": [{"name": "llama3.2"}]})

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(n) or b"{}")
            SEEN_REQUESTS.append(payload)
            self._json({"message": {"role": "assistant", "content": reply}})

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    return f"http://127.0.0.1:{httpd.server_address[1]}"


def memory(reply="I remember."):
    client, store, d = oblivio_node()
    m = OllamaMemory(client, ollama_base=fake_ollama(reply),
                     index_path=os.path.join(d, "index.json"))
    return m, store, d


# --- the privacy boundary ---------------------------------------------------

def test_remote_model_endpoints_are_refused():
    """Prompts must not leave the machine by accident."""
    for bad in ("http://api.openai.com", "http://192.168.1.50:11434",
                "https://example.com", "http://8.8.8.8:11434"):
        try:
            _assert_local(bad)
        except NotLocalError:
            continue
        raise AssertionError(f"accepted non-local endpoint {bad}")


def test_loopback_endpoints_are_accepted():
    for good in ("http://127.0.0.1:11434", "http://localhost:11434",
                 "http://[::1]:11434"):
        assert _assert_local(good)


def test_remote_requires_explicit_opt_in():
    client, _, d = oblivio_node()
    try:
        OllamaMemory(client, ollama_base="http://10.0.0.5:11434",
                     index_path=os.path.join(d, "i.json"))
    except NotLocalError:
        pass
    else:
        raise AssertionError("remote endpoint accepted without opt-in")

    m = OllamaMemory(client, ollama_base="http://10.0.0.5:11434",
                     index_path=os.path.join(d, "i.json"), allow_remote=True)
    assert m.base == "http://10.0.0.5:11434"


def test_no_third_party_endpoints_in_the_module():
    """No code path here can reach a hosted provider."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(root, "oblivio", "ollama_mem.py"),
               encoding="utf-8").read().lower()
    for host in ("api." + "openai.com", "api." + "anthropic.com",
                 "generativelanguage", "api.cohere"):
        assert host not in src, f"module references {host}"


# --- memory round trip ------------------------------------------------------

def test_remember_and_recall():
    m, _, _ = memory()
    res = m.remember("prefers concise answers", label="prefs")
    assert m.recall(record_id=res["record_id"]) == "prefers concise answers"


def test_memories_are_encrypted_on_the_node():
    m, store, _ = memory()
    m.remember("my private diagnosis")
    found = False
    for root, _, files in os.walk(store.data_dir):
        for fn in files:
            with open(os.path.join(root, fn), "rb") as fh:
                if b"my private diagnosis" in fh.read():
                    found = True
    assert not found, "plaintext reached the node"


def test_index_persists_across_instances():
    client, _, d = oblivio_node()
    path = os.path.join(d, "index.json")
    base = fake_ollama()
    m1 = OllamaMemory(client, ollama_base=base, index_path=path)
    m1.remember("first thing")
    m2 = OllamaMemory(client, ollama_base=base, index_path=path)
    assert m2.recent(5) == ["first thing"]


def test_recent_returns_newest_last():
    m, _, _ = memory()
    for t in ("one", "two", "three"):
        m.remember(t)
    assert m.recent(3) == ["one", "two", "three"]


# --- the chat loop ----------------------------------------------------------

def test_chat_returns_the_reply_and_stores_both_turns():
    SEEN_REQUESTS.clear()
    m, _, _ = memory(reply="Noted.")
    out = m.chat("remember I prefer short answers")
    assert out == "Noted."
    stored = m.recent(2)
    assert "remember I prefer short answers" in stored
    assert "Noted." in stored


def test_chat_injects_prior_memories_into_context():
    """This is the whole feature: the model is told what it stored before."""
    SEEN_REQUESTS.clear()
    m, _, _ = memory()
    m.remember("the user is allergic to penicillin", label="prefs")
    m.chat("what should my doctor know?", remember=False)

    system = SEEN_REQUESTS[-1]["messages"][0]["content"]
    assert "allergic to penicillin" in system, system[:300]


def test_chat_can_skip_storing():
    m, _, _ = memory()
    before = len(m.recent(50))
    m.chat("do not store this", remember=False)
    assert len(m.recent(50)) == before


def test_missing_model_server_gives_an_actionable_error():
    client, _, d = oblivio_node()
    m = OllamaMemory(client, ollama_base="http://127.0.0.1:9",
                     index_path=os.path.join(d, "i.json"), timeout=2)
    assert not m.available()
    try:
        m.chat("hello")
    except OllamaUnavailable as exc:
        assert "ollama" in str(exc).lower() or "model server" in str(exc).lower()
        return
    raise AssertionError("a dead model server did not raise clearly")


def test_recall_degrades_when_a_node_is_down():
    """A stored memory that cannot be fetched must not break the chat loop."""
    m, _, _ = memory()
    m.remember("something")
    for h in SERVERS:
        try:
            h.shutdown()
        except Exception:
            pass
    assert m.recent(5) == []      # no exception


def run():
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed, failed = [], []
    for name, fn in tests:
        try:
            fn()
            passed.append(name)
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failed.append(name)
            print(f"  FAIL  {name}\n          {exc}")
        except Exception as exc:
            failed.append(name)
            print(f"  ERROR {name}\n          {type(exc).__name__}: {exc}")
    for h in SERVERS:
        try:
            h.shutdown()
            h.server_close()
        except Exception:
            pass
    for d in TMPDIRS:
        shutil.rmtree(d, ignore_errors=True)
    print(f"\n{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())
