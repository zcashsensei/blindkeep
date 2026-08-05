"""Local model memory.

The point of the project stated as a working loop: an assistant that remembers
you, where the memory lives encrypted on storage you do not have to trust, and
the model runs on your own machine so the conversation never leaves it.

Nobody adopts a memory layer. They adopt an assistant that does not forget.

**Local only, enforced rather than assumed.** The model endpoint must resolve to
a loopback address. Pointing this at a remote host requires passing
`allow_remote=True` explicitly, and even then the payload still never includes a
third-party API key, because there is no code path here that adds one. If a
gateway to a hosted model is ever wanted, that is `cloud_gate.py`, which is
opt-in and labelled not private.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse

from .client import BlindkeepClient

DEFAULT_BASE = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.2"
MAX_REPLY_BYTES = 8 * 1024 * 1024
DEFAULT_RECALL = 6


class OllamaUnavailable(Exception):
    """The local model server is not reachable."""


class NotLocalError(Exception):
    """The configured endpoint is not on this machine."""


def _assert_local(base_url: str) -> str:
    """Refuse a non-loopback model endpoint unless explicitly permitted."""
    parsed = urlparse(base_url)
    host = parsed.hostname
    if not host:
        raise NotLocalError(f"no host in {base_url!r}")
    if host == "localhost":
        return base_url.rstrip("/")
    try:
        if ipaddress.ip_address(host).is_loopback:
            return base_url.rstrip("/")
    except ValueError:
        pass
    raise NotLocalError(
        f"{host} is not a loopback address. Prompts would leave this machine. "
        f"Pass allow_remote=True only if that is genuinely what you want.")


@dataclass
class Turn:
    role: str
    content: str
    record_id: Optional[str] = None


class OllamaMemory:
    """A local chat loop whose history is stored through Blindkeep."""

    def __init__(self,
                 client: BlindkeepClient,
                 ollama_base: str = DEFAULT_BASE,
                 model: str = DEFAULT_MODEL,
                 index_path: Optional[str] = None,
                 allow_remote: bool = False,
                 timeout: float = 120.0):
        self.client = client
        self.base = ollama_base.rstrip("/") if allow_remote else _assert_local(ollama_base)
        self.model = model
        self.timeout = timeout
        self.index_path = index_path or os.path.join("data", "client",
                                                     "ollama_index.json")
        self._index: list[dict[str, Any]] = self._load_index()

    # ---- the local record of what was stored --------------------------------
    #
    # Record identifiers are not secret, but they are the only handle to a
    # memory. Losing them means the data is still safe and still unreadable —
    # and also unfindable. The index is that handle, kept beside the key.

    def _load_index(self) -> list[dict[str, Any]]:
        try:
            with open(self.index_path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def _save_index(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.index_path)) or ".",
                    exist_ok=True)
        tmp = self.index_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._index[-500:], f, indent=2)
        os.replace(tmp, self.index_path)

    # ---- memory -------------------------------------------------------------

    def remember(self, text: str, label: str = "chat") -> dict[str, Any]:
        """Encrypt and store one piece of text."""
        result = self.client.put(text.encode("utf-8"), label=label)
        self._index.append({"record_id": result["record_id"],
                            "index": result["index"], "label": label})
        self._save_index()
        return result

    def recall(self, record_id: Optional[str] = None,
               index: Optional[int] = None) -> str:
        """Fetch and decrypt one memory."""
        if record_id is not None:
            return self.client.get_by_id(record_id)["plaintext"].decode("utf-8")
        if index is not None:
            return self.client.get(index)["plaintext"].decode("utf-8")
        raise ValueError("pass record_id or index")

    def recent(self, n: int = DEFAULT_RECALL) -> list[str]:
        """The last n memories, newest last, skipping any that fail to verify."""
        out: list[str] = []
        for entry in self._index[-n:]:
            try:
                out.append(self.recall(record_id=entry["record_id"]))
            except Exception:
                continue          # a node may be down; degrade, do not crash
        return out

    # ---- the model ----------------------------------------------------------

    def _post(self, path: str, payload: dict) -> dict:
        req = urllib.request.Request(
            self.base + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read(MAX_REPLY_BYTES).decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise OllamaUnavailable(
                f"model server returned HTTP {exc.code}: "
                f"{exc.read(2048).decode('utf-8', 'replace')}") from exc
        except (urllib.error.URLError, OSError, socket.timeout) as exc:
            raise OllamaUnavailable(
                f"no local model server at {self.base} ({exc}). "
                f"Start Ollama, or pass a different --ollama-base.") from exc

    def chat(self, user_message: str, system: Optional[str] = None,
             remember: bool = True, recall: int = DEFAULT_RECALL) -> str:
        """One exchange: recall context, ask the local model, store both turns."""
        messages: list[dict[str, str]] = []

        context = self.recent(recall) if recall else []
        base_system = system or (
            "You are a helpful assistant with persistent memory of this user.")
        if context:
            joined = "\n".join(f"- {c}" for c in context)
            base_system += (
                "\n\nPreviously stored memories about this user:\n" + joined)
        messages.append({"role": "system", "content": base_system})
        messages.append({"role": "user", "content": user_message})

        data = self._post("/api/chat", {
            "model": self.model, "messages": messages, "stream": False,
        })
        reply = (data.get("message") or {}).get("content", "")
        if not reply:
            raise OllamaUnavailable(
                f"model returned no content (keys: {sorted(data)})")

        if remember:
            self.remember(user_message, label="user")
            self.remember(reply, label="assistant")
        return reply

    def available(self) -> bool:
        """True when a local model server answers."""
        try:
            req = urllib.request.Request(self.base + "/api/tags")
            with urllib.request.urlopen(req, timeout=3) as resp:
                resp.read(65536)
            return True
        except Exception:
            return False
