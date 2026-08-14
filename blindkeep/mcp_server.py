"""Blindkeep as an MCP server: any MCP host becomes an AI with a keep.

Model Context Protocol is how Claude Desktop, Claude Code and a growing list
of hosts hand tools to a model. This module speaks it over stdio, so a user
adds one line of config and their assistant can remember things — with every
read and write passing through the app's release gate, never around it.

**This is a bridge, not a second gate.** The app (`app.py`) already decides
what an agent may be handed: sensitivity comes from the decrypted label, the
policy maps it to a required tier, the agent's tier is a declaration the user
made, and every read lands in an irreversible ledger. Re-implementing any of
that here would create two enforcement points that drift — the exact defect
`test_agent_gate.py` exists to prevent. So this module holds no key, opens no
ciphertext, and makes no release decision. It forwards to the app's three
agent routes (`/api/write`, `/api/read/<n>`, `/api/state`) with the agent
token, and translates refusals into words a model acts on correctly.

**The token is the consent.** Nothing here can mint one: only the app's own
page can enable agent access, and turning it off invalidates the token
mid-session. A missing or dead token is therefore not an error state to route
around but the user's decision, and the tool results say exactly how the user
— not the model — can change it.

**A refusal is the product working.** "Withheld by policy" means the gate did
its job; the model is told so, told what class the record is, and told that
the user's app is the place to change policy. It is never phrased as a
failure, because a model that treats refusals as errors will retry, rephrase,
and social-engineer its way toward the very disclosure the gate refused.

Runs on stdlib only, like every other module: JSON-RPC 2.0, one message per
line, UTF-8 regardless of the parent's codepage — a Windows host launches
children under the ANSI codepage, and a protocol stream is exactly the child
stdout the UTF-8 rule exists for.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Optional

from . import __version__

DEFAULT_APP_URL = "http://127.0.0.1:8743"
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

# One instruction block, sent at initialize. This is what the model knows
# about the keep before it ever calls a tool, so the two facts that shape
# correct behaviour go here: classes decide release, and refusal is policy.
INSTRUCTIONS = (
    "Blindkeep is this user's encrypted memory. Records carry a sensitivity "
    "class (public, personal, sensitive, secret) sealed inside the "
    "ciphertext, and the user's release policy decides which classes you may "
    "be handed. A record 'withheld by policy' is not an error and not an "
    "obstacle to work around: it is the user's decision, changeable only by "
    "the user in the Blindkeep app. Save memories at the honest class — "
    "'secret' is write-only for you: you can store it, and only the user "
    "will ever read it back."
)

HOW_TO_CONNECT = (
    "The Blindkeep app is not reachable. Ask the user to start it "
    "(py -3 app.py in the Blindkeep folder, or the desktop launcher) — "
    "the app runs the keep this server bridges to."
)

HOW_TO_ENABLE = (
    "No agent token is configured, so Blindkeep has not been told to trust "
    "this connection. Ask the user to: open the Blindkeep app "
    "(http://127.0.0.1:8743), switch on Agent access, copy the token it "
    "mints, and set it as BLINDKEEP_AGENT_TOKEN in this MCP server's "
    "environment. Handing an agent memory access is the user's decision; "
    "nothing on this side can grant it."
)

HOW_TO_REFRESH = (
    "Blindkeep refused the agent token. Either agent access was switched "
    "off, or the app restarted and minted a new token. Ask the user to open "
    "the Blindkeep app, check Agent access is on, and update "
    "BLINDKEEP_AGENT_TOKEN in this MCP server's config to the current token."
)


# ---- the bridge -------------------------------------------------------------


class AppUnreachable(Exception):
    """The app did not answer at all — distinct from the app refusing."""


class BlindkeepBridge:
    """Talks to the app's agent routes. Holds a token, never a key."""

    def __init__(self, url: Optional[str] = None, token: Optional[str] = None,
                 timeout: float = 30.0):
        self.url = (url or os.environ.get("BLINDKEEP_APP_URL")
                    or DEFAULT_APP_URL).rstrip("/")
        self._token = token
        self.timeout = timeout

    @property
    def token(self) -> str:
        # Read at call time so a flag wins over the environment but the
        # environment still works alone — same precedence as the CLI's keys.
        return self._token or os.environ.get("BLINDKEEP_AGENT_TOKEN") or ""

    def request(self, method: str, path: str,
                body: Optional[dict] = None) -> tuple[int, dict]:
        data = None
        headers = {"Accept": "application/json",
                   "X-Blindkeep-Token": self.token}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.url + path, data=data,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            # The app's refusals arrive as HTTP errors with a JSON body that
            # names the reason. That body IS the answer — losing it would
            # collapse "withheld by policy" and "bad token" into one blur.
            try:
                detail = json.loads(e.read().decode("utf-8"))
            except Exception:
                detail = {"error": f"HTTP {e.code}"}
            return e.code, detail
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise AppUnreachable(str(e)) from e


# ---- tools ------------------------------------------------------------------

SENSITIVITIES = ("public", "personal", "sensitive", "secret")

TOOLS: list[dict[str, Any]] = [
    {
        "name": "save_memory",
        "description": (
            "Save something worth remembering to the user's encrypted keep. "
            "It is encrypted on this machine before storage; the storage node "
            "never sees plaintext. Choose the honest sensitivity class: "
            "public (fine for anyone), personal (about the user; the "
            "default), sensitive (would embarrass or expose), secret "
            "(write-only for you — you will not be able to read it back; "
            "only the user can, in their app)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string",
                         "description": "What to remember, as plain text."},
                "sensitivity": {
                    "type": "string", "enum": list(SENSITIVITIES),
                    "description": "Honest class of this memory. "
                                   "Default: personal."},
                "label": {"type": "string",
                          "description": "Short name for the record "
                                         "(shown in the user's app)."},
            },
            "required": ["text"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False,
                        "idempotentHint": False, "openWorldHint": False},
    },
    {
        "name": "list_memories",
        "description": (
            "List the stored memories this connection is cleared to read: "
            "record number, label, and sensitivity class. Records above your "
            "granted tier are counted but not listed — a label alone can "
            "disclose ('bank details' tells plenty), so what you cannot open "
            "you also cannot enumerate."
        ),
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "read_memory",
        "description": (
            "Read one memory by its record number (from list_memories). The "
            "app decrypts it locally, verifies its inclusion proof against "
            "the signed log head, and hands it over only if the user's "
            "release policy clears its sensitivity class for you. Every read "
            "is recorded in the user's agent-reads ledger."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "index": {"type": "integer", "minimum": 0,
                          "description": "The record number."},
            },
            "required": ["index"],
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "keep_status",
        "description": (
            "Health and integrity of the user's keep: whether the node is "
            "up, how many records it holds, how many you are cleared to "
            "read, and the verified state of the append-only log (tree size "
            "and signed root). Use this first if other tools fail."
        ),
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
]


def _text(msg: str, is_error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": msg}], "isError": is_error}


def _no_token() -> dict:
    return _text(HOW_TO_ENABLE, is_error=True)


def _refused(status: int, detail: dict) -> dict:
    """An app refusal, translated. Which refusal matters more than that one
    happened: a policy withhold is the gate working, a 403 'forbidden' is a
    dead token, a 423 is a locked key. Each gets words the model can act on
    without acting AROUND the gate."""
    err = str(detail.get("error") or f"HTTP {status}")
    if status == 403 and "withheld" in err:
        return _text(
            f"Withheld by the user's release policy: this record is "
            f"'{detail.get('sensitivity', '?')}' and requires the "
            f"'{detail.get('requires', '?')}' tier; this connection is "
            f"treated as '{detail.get('agent_tier', '?')}'. This is the "
            f"user's decision, not a fault. Do not try to obtain the "
            f"content another way; the user can change policy in their "
            f"Blindkeep app.", is_error=True)
    if status == 403:
        return _text(HOW_TO_REFRESH, is_error=True)
    if status == 423:
        return _text(
            "The master key is sealed for this session. Ask the user to "
            "unlock their key in the Blindkeep app, then try again.",
            is_error=True)
    if status == 409 and detail.get("code") == "key_not_backed_up":
        return _text(
            "The keep refuses writes until the master key is protected: "
            "the user has not set a passphrase or downloaded a sealed "
            "backup, so anything saved now could be permanently lost. Ask "
            "the user to finish key setup in the Blindkeep app. Do not "
            "bypass this.", is_error=True)
    return _text(f"Blindkeep refused: {err}", is_error=True)


def call_tool(bridge: BlindkeepBridge, name: str, args: dict) -> dict:
    if name == "save_memory":
        if not bridge.token:
            return _no_token()
        text = args.get("text")
        if not isinstance(text, str) or not text.strip():
            return _text("Nothing to save: 'text' must be non-empty text.",
                         is_error=True)
        sens = args.get("sensitivity") or "personal"
        if sens not in SENSITIVITIES:
            return _text(f"Unknown sensitivity {sens!r}. One of: "
                         f"{', '.join(SENSITIVITIES)}.", is_error=True)
        body = {"text": text, "sensitivity": sens,
                "label": str(args.get("label") or "")[:120]}
        status, resp = bridge.request("POST", "/api/write", body)
        if status != 200:
            return _refused(status, resp)
        rec = resp.get("record") or {}
        return _text(
            f"Kept as record #{rec.get('index', '?')}. Encrypted locally as "
            f"'{sens}', committed to the append-only log (tree size "
            f"{rec.get('tree_size', '?')}). The storage node holds only "
            f"ciphertext it cannot read.")

    if name == "list_memories":
        if not bridge.token:
            return _no_token()
        status, resp = bridge.request("GET", "/api/state")
        if status != 200:
            return _refused(status, resp)
        if not resp.get("node"):
            return _text(f"The keep's node is not running: "
                         f"{resp.get('why', 'unknown reason')}.",
                         is_error=True)
        by_sens = resp.get("by_sensitivity") or {}
        total = sum(by_sens.values()) if by_sens else resp.get("records", 0)
        reachable = resp.get("agent_reachable", 0)
        rows = resp.get("list") or []
        lines = [f"#{r.get('index')}  [{r.get('sensitivity', '?')}]  "
                 f"{r.get('label') or '(no label)'}" for r in rows]
        held = total - reachable
        summary = (f"{total} records in the keep; {reachable} cleared for "
                   f"you" + (f", {held} withheld by the user's release "
                             f"policy (not listed)" if held > 0 else "") + ".")
        if lines:
            summary += "\n" + "\n".join(lines)
            if len(rows) < reachable:
                summary += f"\n(showing the most recent {len(rows)})"
        return _text(summary)

    if name == "read_memory":
        if not bridge.token:
            return _no_token()
        idx = args.get("index")
        if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0:
            return _text("'index' must be a record number (a non-negative "
                         "integer from list_memories).", is_error=True)
        status, resp = bridge.request("GET", f"/api/read/{idx}")
        if status != 200:
            return _refused(status, resp)
        meta = resp.get("meta") or {}
        return _text(
            f"Record #{idx} [{meta.get('sensitivity', '?')}] "
            f"{meta.get('label') or '(no label)'} — integrity verified "
            f"against the signed log head:\n{resp.get('text', '')}")

    if name == "keep_status":
        # Status works without a token so a half-configured install can
        # still be diagnosed — but it then reports reachability only, since
        # the app rightly refuses memory metadata to the tokenless.
        if not bridge.token:
            try:
                bridge.request("GET", "/api/state")
            except AppUnreachable:
                return _text(HOW_TO_CONNECT, is_error=True)
            return _text("The Blindkeep app is running at " + bridge.url
                         + ", but no agent token is configured. "
                         + HOW_TO_ENABLE, is_error=True)
        status, resp = bridge.request("GET", "/api/state")
        if status != 200:
            return _refused(status, resp)
        if not resp.get("node"):
            return _text(f"App up, node DOWN: "
                         f"{resp.get('why', 'unknown reason')}.",
                         is_error=True)
        by_sens = resp.get("by_sensitivity") or {}
        total = sum(by_sens.values()) if by_sens else resp.get("records", 0)
        classes = ", ".join(f"{k} {v}" for k, v in sorted(by_sens.items()))
        return _text(
            f"Keep healthy. Node up; append-only log verified "
            f"(tree size {resp.get('tree_size')}, signed root "
            f"{str(resp.get('root') or '')[:16]}…). {total} records"
            + (f" ({classes})" if classes else "")
            + f"; {resp.get('agent_reachable', 0)} cleared for this "
            f"connection. Key sealed at rest: "
            f"{bool(resp.get('key_sealed_at_rest'))}; unlocked: "
            f"{bool(resp.get('unlocked'))}.")

    raise KeyError(name)


# ---- the wire ---------------------------------------------------------------


def _handle(bridge: BlindkeepBridge, msg: dict) -> Optional[dict]:
    """One request in, one response out; None for notifications."""
    method = msg.get("method")
    msg_id = msg.get("id")

    def result(payload: dict) -> dict:
        return {"jsonrpc": "2.0", "id": msg_id, "result": payload}

    def error(code: int, text: str) -> dict:
        return {"jsonrpc": "2.0", "id": msg_id,
                "error": {"code": code, "message": text}}

    if method == "initialize":
        asked = (msg.get("params") or {}).get("protocolVersion")
        version = asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
        return result({
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "blindkeep", "title": "Blindkeep",
                           "version": __version__},
            "instructions": INSTRUCTIONS,
        })
    if method == "ping":
        return result({})
    if method == "tools/list":
        return result({"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        if name not in {t["name"] for t in TOOLS}:
            return error(-32602, f"unknown tool: {name!r}")
        try:
            out = call_tool(bridge, name, params.get("arguments") or {})
        except AppUnreachable:
            out = _text(HOW_TO_CONNECT, is_error=True)
        except Exception as exc:
            # A tool failure is a RESULT, not a protocol error: the model
            # should read it and adapt, not watch the connection die.
            out = _text(f"blindkeep bridge error: "
                        f"{type(exc).__name__}: {exc}", is_error=True)
        return result(out)

    if msg_id is None:
        return None                      # a notification we do not act on
    return error(-32601, f"method not found: {method!r}")


def serve_stdio(url: Optional[str] = None, token: Optional[str] = None) -> int:
    """Speak MCP on stdin/stdout until the host hangs up.

    stdout carries protocol and nothing else; anything a person should see
    goes to stderr, because one stray print corrupts the stream.
    """
    # UTF-8 both ways, whatever codepage the host launched us under, and
    # bare-\n line endings so no client has to strip \r from JSON.
    for stream, kwargs in ((sys.stdin, {}), (sys.stdout, {"newline": "\n"})):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace", **kwargs)
        except (AttributeError, OSError):
            pass

    bridge = BlindkeepBridge(url=url, token=token)
    print(f"blindkeep mcp: bridging to {bridge.url} "
          f"(token {'set' if bridge.token else 'NOT SET'})", file=sys.stderr)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            reply: Optional[dict] = {
                "jsonrpc": "2.0", "id": None,
                "error": {"code": -32700, "message": "parse error"}}
        else:
            reply = _handle(bridge, msg)
        if reply is not None:
            sys.stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0
