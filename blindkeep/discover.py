"""Peer discovery.

A client needs a list of node URLs before `ReplicatedClient` can do anything.
Hard-coding them in source does not survive contact with a real network, so the
list comes from a file, optionally topped up from a bootstrap endpoint.

Security notes, because a peer list is an attractive thing to poison:

* **A bootstrap list is not trusted.** It supplies candidate addresses and
  nothing else. Every node is still verified independently on use — signatures,
  inclusion proofs, consistency against a pinned head. A malicious bootstrap can
  waste a client's time; it cannot make the client accept a bad record.

* **URLs are validated before use.** Only http and https, no credentials in the
  URL, and cloud metadata addresses are refused outright: a bootstrap server
  that can point a client at 169.254.169.254 turns every client into a probe
  against its own infrastructure.

* **Redirects are not followed** when probing, for the same reason.

* **Pinned keys survive discovery.** If a peer entry carries `pubkey_hex`, that
  pin is preserved and handed to the client, so discovery can add nodes but
  never silently substitute one.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

DEFAULT_TIMEOUT = 2.0
MAX_PEERS = 256
MAX_BOOTSTRAP_BYTES = 1 * 1024 * 1024

# Link-local ranges used by cloud instance-metadata services. A peer list that
# can name these can make a client read its own host's credentials endpoint.
_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "100.100.100.200"}

# The same services as addresses, for checking what a NAME resolves to. Blocking the
# literal and the well-known hostname is not enough on its own: an attacker controls
# their own DNS, so `peer.attacker.example` answering 169.254.169.254 walked straight
# past a check that only ever looked at the spelling of the host.
_METADATA_ADDRS = frozenset({
    "169.254.169.254",          # AWS, Azure, GCP, DigitalOcean, Oracle
    "100.100.100.200",          # Alibaba Cloud
    "fd00:ec2::254",            # AWS IMDS over IPv6
})


class DiscoveryError(Exception):
    """The peer list could not be loaded, or contained nothing usable."""


@dataclass
class Peer:
    url: str
    pubkey_hex: Optional[str] = None
    live: bool = False
    tree_size: Optional[int] = None
    error: str = ""
    meta: dict = field(default_factory=dict)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DiscoveryError(f"peer attempted to redirect to {newurl!r}")


_OPENER = urllib.request.build_opener(_NoRedirect())


def _refuse_if_metadata(addr: str, shown_as: str) -> None:
    """Raise if an address is a link-local or instance-metadata endpoint."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return
    # ipv4_mapped exists only on IPv6Address, so ask for it rather than assume it. An
    # IPv6-mapped form (::ffff:169.254.169.254) is the same endpoint by another spelling.
    mapped = getattr(ip, "ipv4_mapped", None)
    if str(ip) in _METADATA_ADDRS or (mapped is not None and str(mapped) in _METADATA_ADDRS):
        raise DiscoveryError(
            f"refusing cloud metadata address {addr} (via {shown_as})"
            if addr != shown_as else f"refusing cloud metadata address {addr}")
    if ip.is_link_local:
        raise DiscoveryError(
            f"refusing link-local address {addr} (via {shown_as})"
            if addr != shown_as else f"refusing link-local address {addr}")


def normalise_url(url: str, resolve: bool = True) -> str:
    """Validate and canonicalise a peer URL, or raise.

    Loopback and private addresses are deliberately allowed: the default node listens on
    127.0.0.1 and LAN peers are a supported deployment, so blocking them would break the
    normal case to defend against nothing. What is refused is link-local and the cloud
    instance-metadata endpoints, which exist only to be read by the host itself.

    `resolve` controls whether hostnames are looked up and their answers checked. Set it
    False only where no lookup is wanted (offline validation, tests); the literal checks
    still run either way.
    """
    if not isinstance(url, str) or not url.strip():
        raise DiscoveryError("peer url must be a non-empty string")
    u = url.strip().rstrip("/")
    parsed = urlparse(u)
    if parsed.scheme not in ("http", "https"):
        raise DiscoveryError(f"unsupported scheme in {url!r} (http/https only)")
    if not parsed.hostname:
        raise DiscoveryError(f"no host in {url!r}")
    if parsed.username or parsed.password:
        raise DiscoveryError("credentials in a peer url are not accepted")
    host = parsed.hostname.lower()
    if host in _METADATA_HOSTS:
        raise DiscoveryError(f"refusing cloud metadata address {host}")
    _refuse_if_metadata(host, host)

    # A name is only as trustworthy as what it answers with, and the attacker owns the
    # zone for their own name. Check every address the host resolves to, not the string.
    #
    # This does not defeat DNS rebinding: a name that answers honestly here and with a
    # metadata address at connect time still wins, because validation and connection are
    # two separate lookups. Closing that needs the check at socket level, which is a
    # larger change than this function. Stated rather than implied — see SECURITY.md.
    if resolve:
        try:
            infos = socket.getaddrinfo(host, parsed.port or 80, proto=socket.IPPROTO_TCP)
        except (socket.gaierror, UnicodeError, ValueError):
            infos = []      # unresolvable: the connection will fail on its own merits
        for info in infos:
            _refuse_if_metadata(info[4][0], host)
    return u


def load_peers(path: str | Path) -> list[Peer]:
    """Read a peer list from disk."""
    p = Path(path)
    if not p.is_file():
        raise DiscoveryError(f"peer file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DiscoveryError(f"{p} is not valid JSON: {exc}") from exc

    entries = data.get("nodes") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise DiscoveryError(f"{p} must contain a list of nodes")

    peers: list[Peer] = []
    for entry in entries[:MAX_PEERS]:
        if isinstance(entry, str):
            peers.append(Peer(url=normalise_url(entry)))
        elif isinstance(entry, dict):
            peers.append(Peer(url=normalise_url(entry.get("url", "")),
                              pubkey_hex=entry.get("pubkey_hex") or None))
        else:
            raise DiscoveryError(f"unrecognised peer entry: {entry!r}")
    return peers


def fetch_bootstrap(url: str, timeout: float = DEFAULT_TIMEOUT) -> list[Peer]:
    """Fetch candidate peers from a bootstrap endpoint.

    The response is untrusted input: it is size-bounded, URL-validated, and
    every node it names is still verified independently on use.
    """
    url = normalise_url(url)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_BOOTSTRAP_BYTES + 1)
    except (urllib.error.URLError, OSError, socket.timeout) as exc:
        raise DiscoveryError(f"bootstrap {url} unreachable: {exc}") from exc
    if len(raw) > MAX_BOOTSTRAP_BYTES:
        raise DiscoveryError("bootstrap response is too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DiscoveryError(f"bootstrap {url} returned invalid JSON: {exc}") from exc

    entries = data.get("nodes") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise DiscoveryError("bootstrap response must contain a list of nodes")

    peers: list[Peer] = []
    for entry in entries[:MAX_PEERS]:
        try:
            if isinstance(entry, str):
                peers.append(Peer(url=normalise_url(entry)))
            elif isinstance(entry, dict):
                peers.append(Peer(url=normalise_url(entry.get("url", "")),
                                  pubkey_hex=entry.get("pubkey_hex") or None))
        except DiscoveryError:
            continue      # skip a bad entry rather than losing the whole list
    return peers


def probe_peer(peer: Peer, timeout: float = DEFAULT_TIMEOUT) -> Peer:
    """Check a peer is answering, and record what it reports."""
    try:
        req = urllib.request.Request(peer.url + "/health",
                                     headers={"Accept": "application/json"})
        with _OPENER.open(req, timeout=timeout) as resp:
            body = json.loads(resp.read(65536).decode("utf-8"))
        peer.live = bool(body.get("ok", True))
        peer.tree_size = body.get("size")
        peer.meta = body if isinstance(body, dict) else {}
        peer.error = "" if peer.live else "node reported not ok"
    except Exception as exc:
        peer.live = False
        peer.error = f"{type(exc).__name__}: {exc}"
    return peer


def filter_live(peers: list[Peer], timeout: float = DEFAULT_TIMEOUT) -> list[Peer]:
    """Probe every peer concurrently and keep the ones answering."""
    import concurrent.futures

    if not peers:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(peers))) as pool:
        probed = list(pool.map(lambda p: probe_peer(p, timeout), peers))
    return [p for p in probed if p.live]


def discover(path: str | Path | None = None,
             bootstrap_url: str | None = None,
             require_live: bool = True,
             timeout: float = DEFAULT_TIMEOUT) -> list[Peer]:
    """Build a peer list from a file, a bootstrap endpoint, or both."""
    peers: list[Peer] = []
    if path:
        peers.extend(load_peers(path))
    if bootstrap_url:
        peers.extend(fetch_bootstrap(bootstrap_url, timeout))
    if not peers:
        raise DiscoveryError(
            "no peers configured — pass a peer file or a bootstrap url")

    # First entry for a url wins, so a bootstrap cannot displace a locally
    # pinned public key with one of its own choosing.
    seen: dict[str, Peer] = {}
    for p in peers:
        if p.url in seen:
            if seen[p.url].pubkey_hex is None and p.pubkey_hex:
                seen[p.url].pubkey_hex = p.pubkey_hex
        else:
            seen[p.url] = p
    unique = list(seen.values())

    if not require_live:
        return unique
    live = filter_live(unique, timeout)
    if not live:
        raise DiscoveryError(
            f"none of the {len(unique)} configured peer(s) responded")
    return live


def urls(peers: list[Peer]) -> list[str]:
    """The plain URL list `ReplicatedClient` expects."""
    return [p.url for p in peers]


def as_dicts(peers: list[Peer]) -> list[dict[str, Any]]:
    return [{"url": p.url, "live": p.live, "tree_size": p.tree_size,
             "pubkey_hex": p.pubkey_hex, "error": p.error} for p in peers]
