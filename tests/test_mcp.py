"""The MCP bridge: what an MCP host is told, and what it is never told.

The server under test is the real thing — `py -3 -m oblivio mcp` as a
subprocess, spoken to over its actual stdin/stdout — because the protocol
layer IS the surface a host touches, and a suite that imports the functions
would pass while the stream framing, the UTF-8 guard, or the argv wiring was
broken. The app behind it is a fake with the same three agent routes, so the
suite asserts the bridge's half of every conversation: what it sends (the
token header, the sensitivity, never a backup bypass) and how it translates
each refusal (policy withhold, dead token, locked key) into words a model
acts on without acting around the gate.

Four processes, one per configuration that must behave differently: a good
token, a wrong token, no token, and no app at all.
"""

import json
import os
import queue
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

FAKE_TOKEN = "test-agent-token-abc"

WRITES: list = []          # every body the fake's /api/write received
SERVERS: list = []
PROCS: list = []

STATE_RESPONSE = {
    "node": True, "records": 2,
    "by_sensitivity": {"personal": 2, "secret": 2},
    "agent_reachable": 2,
    "tree_size": 4, "root": "ab" * 32,
    "key_sealed_at_rest": True, "unlocked": True,
    "list": [
        {"index": 0, "label": "greeting", "sensitivity": "personal"},
        {"index": 3, "label": "favourite colour", "sensitivity": "personal"},
    ],
}


class FakeApp(BaseHTTPRequestHandler):
    """app.py's three agent routes, with each refusal reachable on demand."""

    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self) -> bool:
        return self.headers.get("X-Oblivio-Token") == FAKE_TOKEN

    def do_GET(self):
        if not self._authed():
            return self._send(403, {"error": "forbidden"})
        path = self.path.split("?", 1)[0]
        if path == "/api/state":
            return self._send(200, STATE_RESPONSE)
        if path.startswith("/api/read/"):
            idx = int(path.rsplit("/", 1)[-1])
            if idx == 0:
                return self._send(200, {
                    "text": "the user prefers green tea · verified",
                    "meta": {"index": 0, "label": "greeting",
                             "sensitivity": "personal"}})
            if idx == 1:
                return self._send(403, {
                    "error": "withheld by policy", "sensitivity": "secret",
                    "requires": "local", "agent_tier": "open"})
            if idx == 2:
                return self._send(423, {"error": "unlock your master key",
                                        "code": "key_locked"})
            return self._send(400, {"error": "no such record"})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authed():
            return self._send(403, {"error": "forbidden"})
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n).decode("utf-8")) if n else {}
        if self.path.split("?", 1)[0] == "/api/write":
            WRITES.append(body)
            if "LOCKME" in (body.get("text") or ""):
                return self._send(423, {"error": "unlock your master key",
                                        "code": "key_locked"})
            if "NOBACKUP" in (body.get("text") or ""):
                return self._send(409, {
                    "error": "set a passphrase first",
                    "code": "key_not_backed_up"})
            # The real route's shape exactly (app.py /api/write): the put
            # result rides under "record", never at the top level.
            return self._send(200, {
                "ok": True,
                "record": {"record_id": "r" * 16, "index": 4,
                           "leaf_hex": "cd" * 32, "tree_size": 5,
                           "root_hex": "ef" * 32},
                "sensitivity": body.get("sensitivity") or "personal"})
        return self._send(404, {"error": "not found"})

    def log_message(self, *a):            # keep the suite's output readable
        pass


class McpProc:
    """One `oblivio mcp` subprocess with a line-timeout reader."""

    def __init__(self, url: str, token):
        env = dict(os.environ)
        env["OBLIVIO_APP_URL"] = url
        env.pop("OBLIVIO_AGENT_TOKEN", None)
        if token is not None:
            env["OBLIVIO_AGENT_TOKEN"] = token
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "oblivio", "mcp"],
            cwd=ROOT, env=env, text=True, encoding="utf-8",
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        PROCS.append(self.proc)
        self._q: "queue.Queue[str]" = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()
        self._id = 0

    def _pump(self):
        for line in self.proc.stdout:
            self._q.put(line)

    def send(self, method: str, params=None, notification=False):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notification:
            self._id += 1
            msg["id"] = self._id
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def send_raw(self, line: str):
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def read(self, timeout: float = 15.0) -> dict:
        # A timeout, not a blocking readline: a bridge that hangs must FAIL
        # the suite, not wedge it.
        return json.loads(self._q.get(timeout=timeout))

    def rpc(self, method: str, params=None) -> dict:
        self.send(method, params)
        reply = self.read()
        assert reply.get("id") == self._id, \
            f"reply id {reply.get('id')} for request {self._id}"
        return reply

    def call(self, tool: str, args=None) -> dict:
        reply = self.rpc("tools/call", {"name": tool,
                                        "arguments": args or {}})
        assert "result" in reply, f"expected a tool RESULT, got {reply}"
        return reply["result"]


MAIN: McpProc = None
NO_TOKEN: McpProc = None
BAD_TOKEN: McpProc = None
DEAD_APP: McpProc = None


def _boot():
    global MAIN, NO_TOKEN, BAD_TOKEN, DEAD_APP
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeApp)
    SERVERS.append(srv)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"

    MAIN = McpProc(url, FAKE_TOKEN)
    NO_TOKEN = McpProc(url, None)
    BAD_TOKEN = McpProc(url, "stale-token-from-before-restart")
    # A port with nothing on it. Binding then closing reserves one that is
    # very unlikely to be re-taken within the suite's lifetime.
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead_port = s.getsockname()[1]
    s.close()
    DEAD_APP = McpProc(f"http://127.0.0.1:{dead_port}", FAKE_TOKEN)

    for p in (MAIN, NO_TOKEN, BAD_TOKEN, DEAD_APP):
        init = p.rpc("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}})
        assert "result" in init, init
        p.send("notifications/initialized", notification=True)


# ---- protocol ---------------------------------------------------------------


def test_initialize_negotiates_and_instructs():
    reply = MAIN.rpc("initialize", {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"}})
    res = reply["result"]
    assert res["protocolVersion"] == "2025-06-18"
    assert res["serverInfo"]["name"] == "oblivio"
    assert "tools" in res["capabilities"]
    # The two facts a model must hold from message one: classes gate
    # release, and a refusal is the user's decision.
    assert "policy" in res["instructions"]
    assert "not an error" in res["instructions"]


def test_unknown_protocol_version_gets_latest():
    res = MAIN.rpc("initialize", {"protocolVersion": "1999-01-01",
                                  "capabilities": {},
                                  "clientInfo": {"name": "t", "version": "0"}}
                   )["result"]
    assert res["protocolVersion"] == "2025-06-18"


def test_tools_list_names_the_four_tools():
    res = MAIN.rpc("tools/list")["result"]
    names = {t["name"] for t in res["tools"]}
    assert names == {"save_memory", "list_memories", "read_memory",
                     "keep_status"}, names
    for t in res["tools"]:
        assert t["inputSchema"]["type"] == "object", t["name"]
        assert t["description"], t["name"]
    ro = {t["name"]: t["annotations"]["readOnlyHint"] for t in res["tools"]}
    assert ro == {"save_memory": False, "list_memories": True,
                  "read_memory": True, "keep_status": True}


def test_unknown_tool_is_a_protocol_error():
    reply = MAIN.rpc("tools/call", {"name": "drop_table", "arguments": {}})
    assert reply["error"]["code"] == -32602


def test_unknown_method_is_method_not_found():
    reply = MAIN.rpc("resources/list")
    assert reply["error"]["code"] == -32601


def test_notifications_get_no_reply():
    MAIN.send("notifications/cancelled", {"requestId": 999},
              notification=True)
    reply = MAIN.rpc("ping")            # the NEXT reply must answer the ping
    assert reply["result"] == {}


def test_garbage_line_is_a_parse_error():
    MAIN.send_raw("this is not json")
    reply = MAIN.read()
    assert reply["error"]["code"] == -32700
    assert reply["id"] is None


# ---- the bridge, token in hand ----------------------------------------------


def test_save_memory_passes_class_and_label():
    before = len(WRITES)
    res = MAIN.call("save_memory", {"text": "likes green tea",
                                    "sensitivity": "sensitive",
                                    "label": "preferences"})
    assert not res.get("isError"), res
    assert "Kept as record #4" in res["content"][0]["text"]
    assert "tree size 5" in res["content"][0]["text"]
    body = WRITES[before]
    assert body["text"] == "likes green tea"
    assert body["sensitivity"] == "sensitive"
    assert body["label"] == "preferences"


def test_save_never_volunteers_the_backup_bypass():
    """`i_accept_no_backup` accepts permanent loss. Only a person may."""
    assert WRITES, "run after a write test"
    for body in WRITES:
        assert "i_accept_no_backup" not in body, body


def test_save_refuses_empty_text_without_calling_the_app():
    before = len(WRITES)
    res = MAIN.call("save_memory", {"text": "   "})
    assert res.get("isError"), res
    assert len(WRITES) == before


def test_save_rejects_unknown_sensitivity():
    res = MAIN.call("save_memory", {"text": "x", "sensitivity": "ultra"})
    assert res.get("isError"), res
    assert "public" in res["content"][0]["text"]


def test_locked_key_says_unlock_not_error():
    res = MAIN.call("save_memory", {"text": "LOCKME please"})
    assert res.get("isError")
    assert "unlock" in res["content"][0]["text"].lower()


def test_unbacked_key_refusal_is_not_bypassed():
    res = MAIN.call("save_memory", {"text": "NOBACKUP please"})
    assert res.get("isError")
    text = res["content"][0]["text"]
    assert "backup" in text.lower()
    assert "Do not bypass" in text
    assert "i_accept_no_backup" not in WRITES[-1]


def test_list_memories_counts_the_withheld():
    res = MAIN.call("list_memories")
    assert not res.get("isError"), res
    text = res["content"][0]["text"]
    assert "4 records" in text                 # 2 personal + 2 secret
    assert "2 cleared" in text
    assert "withheld" in text
    assert "greeting" in text and "favourite colour" in text
    # What the fake withheld it also never listed; nothing to assert on
    # labels here beyond presence — the withholding is the app's job and
    # test_agent_gate.py's subject. The bridge must only not invent rows.
    assert text.count("#") == 2


def test_read_memory_returns_verified_text():
    res = MAIN.call("read_memory", {"index": 0})
    assert not res.get("isError"), res
    text = res["content"][0]["text"]
    assert "green tea" in text
    assert "integrity verified" in text
    assert "·" in text        # UTF-8 survived the pipe on any codepage


def test_read_withheld_names_the_policy_not_a_fault():
    res = MAIN.call("read_memory", {"index": 1})
    assert res.get("isError")
    text = res["content"][0]["text"]
    assert "Withheld" in text
    assert "'secret'" in text and "'local'" in text and "'open'" in text
    assert "user's decision" in text
    assert "Do not try" in text


def test_read_rejects_a_non_index():
    for bad in ({"index": -1}, {"index": "0"}, {"index": True}, {}):
        res = MAIN.call("read_memory", bad)
        assert res.get("isError"), bad


def test_keep_status_reports_the_verified_log():
    res = MAIN.call("keep_status")
    assert not res.get("isError"), res
    text = res["content"][0]["text"]
    assert "tree size 4" in text
    assert "4 records" in text
    assert "2 cleared" in text


# ---- the three broken configurations ----------------------------------------


def test_no_token_is_the_users_decision_spelled_out():
    for tool in ("save_memory", "list_memories", "read_memory"):
        res = NO_TOKEN.call(tool, {"text": "x", "index": 0})
        assert res.get("isError"), tool
        text = res["content"][0]["text"]
        assert "OBLIVIO_AGENT_TOKEN" in text, tool
        assert "Agent access" in text, tool


def test_no_token_status_still_diagnoses():
    res = NO_TOKEN.call("keep_status")
    assert res.get("isError")
    text = res["content"][0]["text"]
    assert "running" in text and "no agent token" in text


def test_stale_token_says_how_to_refresh():
    res = BAD_TOKEN.call("list_memories")
    assert res.get("isError")
    text = res["content"][0]["text"]
    assert "OBLIVIO_AGENT_TOKEN" in text
    assert "switched off" in text or "restarted" in text


def test_dead_app_says_start_it():
    res = DEAD_APP.call("keep_status")
    assert res.get("isError")
    assert "not reachable" in res["content"][0]["text"]


def run():
    _boot()
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("test_")]
    passed, failed = [], []
    try:
        for name, fn in tests:
            try:
                fn()
                passed.append(name)
                print(f"  PASS  {name}")
            except AssertionError as exc:
                failed.append(name)
                print(f"  FAIL  {name}")
                print(f"          {exc}")
            except Exception as exc:
                failed.append(name)
                print(f"  ERROR {name}")
                print(f"          {type(exc).__name__}: {exc}")
    finally:
        for p in PROCS:
            try:
                p.stdin.close()
            except OSError:
                pass
        deadline = time.time() + 5
        for p in PROCS:
            try:
                p.wait(timeout=max(0.1, deadline - time.time()))
            except subprocess.TimeoutExpired:
                p.kill()
        for s in SERVERS:
            s.shutdown()
    print()
    print(f"{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())
