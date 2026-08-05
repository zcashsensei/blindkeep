"""Blindkeep CLI — run a node, put/get encrypted memory, verify the log."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# The dashboard and progress board are local working tools, not part of the
# published project. Their subcommands are registered only when the files are
# actually present, so a clone never advertises a command it cannot run.
_ROOT = Path(__file__).resolve().parent.parent
_HAS_DASHBOARD = (_ROOT / "dashboard.py").is_file()
_HAS_PROGRESS = (Path(__file__).resolve().parent / "progress.py").is_file()


def _client_from_args(args):
    from .client import BlindkeepClient

    key_path = args.key
    if not os.path.exists(key_path):
        print(f"creating new master key at {key_path}", file=sys.stderr)
        BlindkeepClient.create_keys(key_path)
    key = BlindkeepClient.load_master_key(key_path)
    pin = getattr(args, "pin", None) or os.path.join(os.path.dirname(key_path) or ".", "pin.json")
    return BlindkeepClient(args.url, key, pin_path=pin,
                          expected_pubkey_hex=getattr(args, "pubkey", None) or None)


def cmd_node(args) -> int:
    from .node import serve
    serve(args.data_dir, host=args.host, port=args.port)
    return 0


def cmd_progress(args) -> int:
    """Scan repo and auto-mark finished todos in data/plan.json."""
    from .progress import main as progress_main

    argv = []
    if getattr(args, "dry_run", False):
        argv.append("--dry-run")
    if getattr(args, "json", False):
        argv.append("--json")
    return progress_main(argv)


def cmd_dash(args) -> int:
    import runpy
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    dash = root / "dashboard.py"
    if not dash.is_file():
        print(f"error: dashboard not found at {dash}", file=sys.stderr)
        return 1
    os.chdir(root)
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    # sync board before UI
    try:
        from .progress import sync_progress
        sync_progress(write=True)
    except Exception as e:
        print(f"progress sync skipped: {e}", file=sys.stderr)
    argv = ["dashboard.py", "--host", args.host, "--port", str(args.port)]
    if args.no_open:
        argv.append("--no-open")
    sys.argv = argv
    runpy.run_path(str(dash), run_name="__main__")
    return 0


def cmd_peers(args) -> int:
    from .discover import as_dicts, discover

    peers = discover(args.file if args.file and os.path.exists(args.file) else None,
                     bootstrap_url=args.bootstrap,
                     require_live=not args.all,
                     timeout=args.timeout)
    if args.json:
        print(json.dumps(as_dicts(peers), indent=2))
    else:
        for p in peers:
            state = "live" if p.live else "unprobed"
            size = f"  size={p.tree_size}" if p.tree_size is not None else ""
            pin = "  pinned" if p.pubkey_hex else ""
            print(f"  {p.url}  {state}{size}{pin}")
        print(f"\n{len(peers)} peer(s)")
    return 0


def cmd_audit(args) -> int:
    from .audit import audit_peers, rank
    from .client import BlindkeepClient
    from .discover import discover, urls

    key = BlindkeepClient.load_master_key(args.key)
    if args.url:
        targets = [args.url]
    else:
        targets = urls(discover(args.file, timeout=args.timeout))

    results = rank(audit_peers(targets, key, pin_dir=args.pin_dir,
                               sample_size=args.sample))
    if args.json:
        print(json.dumps([r.as_dict() for r in results], indent=2))
    else:
        for r in results:
            print("  " + r.summary())
    # A dishonest node is a failure exit; an offline one is not.
    return 1 if any(r.security_failures for r in results) else 0


def cmd_chat(args) -> int:
    from .client import BlindkeepClient
    from .ollama_mem import OllamaMemory

    key = BlindkeepClient.load_master_key(args.key)
    client = BlindkeepClient(args.url, key, pin_path=args.pin)
    mem = OllamaMemory(client, ollama_base=args.ollama_base, model=args.model,
                       allow_remote=args.allow_remote)
    reply = mem.chat(args.text, system=args.system,
                     remember=not args.no_remember, recall=args.recall)
    print(reply)
    return 0


def cmd_cloud_chat(args) -> int:
    """Opt-in path to a hosted model. NOT PRIVATE."""
    from .cloud_gate import cloud_complete

    api_key = args.api_key or os.environ.get("BLINDKEEP_CLOUD_KEY", "")
    result = cloud_complete(
        args.text, api_base=args.api_base, api_key=api_key, model=args.model,
        enable_cloud=args.enable_cloud,
        accept_not_private=args.i_accept_not_private,
        system=args.system, apply_redaction=args.redact)
    print(f"[{result['notice']}]", file=sys.stderr)
    if result["redacted"]:
        print(f"[redacted before sending: {', '.join(result['redacted'])}]",
              file=sys.stderr)
    print(result["reply"])
    return 0


def _read_passphrase(args, confirm: bool = False) -> str:
    """Take a passphrase from a flag, a file, or an interactive prompt.

    Prefer the prompt: a passphrase passed as an argument is recorded in shell
    history and visible in the process list.
    """
    import getpass

    if getattr(args, "passphrase_file", None):
        with open(args.passphrase_file, "r", encoding="utf-8") as f:
            return f.read().strip()
    if getattr(args, "passphrase", None):
        return args.passphrase
    first = getpass.getpass("Passphrase: ")
    if confirm and first != getpass.getpass("Confirm passphrase: "):
        raise ValueError("passphrases did not match")
    return first


def cmd_recover(args) -> int:
    from .client import BlindkeepClient
    from . import recovery

    action = args.action

    if action == "export":
        key = BlindkeepClient.load_master_key(args.key)
        print("Write this down and keep it somewhere safe. Anyone holding it")
        print("can read every record you have stored.\n")
        print("  " + recovery.to_recovery_code(key) + "\n")
        return 0

    if action == "restore":
        key = recovery.from_recovery_code(args.code)
        if os.path.exists(args.key) and not args.force:
            print(f"refusing to overwrite {args.key} (pass --force)", file=sys.stderr)
            return 1
        BlindkeepClient.save_master_key(args.key, key)
        print(f"key restored -> {args.key}")
        return 0

    if action == "backup":
        key = BlindkeepClient.load_master_key(args.key)
        blob = recovery.wrap_key(key, _read_passphrase(args, confirm=True))
        with open(args.out, "wb") as f:
            f.write(blob)
        print(f"wrote passphrase-protected backup -> {args.out}")
        print("This file is safe to store anywhere. Its strength is your passphrase.")
        return 0

    if action == "unbackup":
        with open(args.file, "rb") as f:
            blob = f.read()
        key = recovery.unwrap_key(blob, _read_passphrase(args))
        if os.path.exists(args.key) and not args.force:
            print(f"refusing to overwrite {args.key} (pass --force)", file=sys.stderr)
            return 1
        BlindkeepClient.save_master_key(args.key, key)
        print(f"key restored -> {args.key}")
        return 0

    if action == "split":
        key = BlindkeepClient.load_master_key(args.key)
        shares = recovery.split_key(key, threshold=args.threshold, shares=args.shares)
        print(f"Any {args.threshold} of these {args.shares} shares restore the key.")
        print(f"Fewer than {args.threshold} reveal nothing at all.")
        print("Store them in separate places or with different people.\n")
        for s in shares:
            print(f"  share {s.index}:  {s.encode()}")
        print()
        return 0

    if action == "combine":
        shares = [recovery.Share.decode(s) for s in args.share]
        key = recovery.combine_shares(shares)
        if os.path.exists(args.key) and not args.force:
            print(f"refusing to overwrite {args.key} (pass --force)", file=sys.stderr)
            return 1
        BlindkeepClient.save_master_key(args.key, key)
        print(f"key reconstructed from {len(shares)} shares -> {args.key}")
        return 0

    print(f"unknown action: {action}", file=sys.stderr)
    return 1


def cmd_keygen(args) -> int:
    from .client import BlindkeepClient
    if os.path.exists(args.key) and not args.force:
        print(f"refusing to overwrite {args.key} (pass --force)", file=sys.stderr)
        return 1
    BlindkeepClient.create_keys(args.key)
    print(f"wrote 32-byte master key -> {args.key}")
    print("keep this file secret; without it ciphertext is unreadable")
    return 0


def cmd_put(args) -> int:
    client = _client_from_args(args)
    if args.file:
        with open(args.file, "rb") as f:
            data = f.read()
    else:
        data = args.text.encode("utf-8") if args.text is not None else sys.stdin.buffer.read()
    result = client.put(data, label=args.label or "")
    print(json.dumps(result, indent=2))
    return 0


def cmd_get(args) -> int:
    client = _client_from_args(args)
    # None (not "") means "use the label the record was stored with".
    label = args.label or None
    if args.record_id:
        result = client.get_by_id(args.record_id, label=label)
    else:
        result = client.get(int(args.index), label=label)
    plain = result.pop("plaintext")
    if args.raw:
        sys.stdout.buffer.write(plain)
    else:
        meta = {k: v for k, v in result.items()}
        print(json.dumps(meta, indent=2), file=sys.stderr)
        try:
            sys.stdout.write(plain.decode("utf-8"))
            if not plain.endswith(b"\n"):
                sys.stdout.write("\n")
        except UnicodeDecodeError:
            sys.stdout.buffer.write(plain)
    return 0


def cmd_head(args) -> int:
    client = _client_from_args(args)
    head = client.head()
    print(json.dumps(head, indent=2))
    return 0


def cmd_list(args) -> int:
    client = _client_from_args(args)
    # list is metadata only (no ciphertexts); still refresh pin via head
    client.head()
    records = client.list()
    print(json.dumps(records, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blindkeep",
        description="Blindkeep — verifiable encrypted memory for local AI",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    n = sub.add_parser("node", help="run a local memory node")
    n.add_argument("--data-dir", default="data/node")
    n.add_argument("--host", default="127.0.0.1")
    n.add_argument("--port", type=int, default=8741)
    n.set_defaults(func=cmd_node)

    if _HAS_PROGRESS:
        prog = sub.add_parser("progress", help="auto-mark done todos from repo evidence")
        prog.add_argument("--dry-run", action="store_true")
        prog.add_argument("--json", action="store_true")
        prog.set_defaults(func=cmd_progress)

    if _HAS_DASHBOARD:
        d = sub.add_parser("dash", help="open the local project dashboard (syncs progress first)")
        d.add_argument("--host", default="127.0.0.1")
        d.add_argument("--port", type=int, default=8742)
        d.add_argument("--no-open", action="store_true")
        d.set_defaults(func=cmd_dash)

    k = sub.add_parser("keygen", help="create a client master key")
    k.add_argument("--key", default="data/client/master.key")
    k.add_argument("--force", action="store_true")
    k.set_defaults(func=cmd_keygen)

    r = sub.add_parser("recover", help="back up or restore the master key")
    rsub = r.add_subparsers(dest="action", required=True)
    _KEY = ("--key", {"default": "data/client/master.key"})

    r_exp = rsub.add_parser("export", help="print a written recovery code")
    r_exp.add_argument(_KEY[0], **_KEY[1])

    r_res = rsub.add_parser("restore", help="restore the key from a recovery code")
    r_res.add_argument("--code", required=True)
    r_res.add_argument(_KEY[0], **_KEY[1])
    r_res.add_argument("--force", action="store_true")

    r_bak = rsub.add_parser("backup", help="write a passphrase-protected key file")
    r_bak.add_argument(_KEY[0], **_KEY[1])
    r_bak.add_argument("--out", default="data/client/master.key.backup")
    r_bak.add_argument("--passphrase", default=None,
                       help="prefer the interactive prompt; a flag is visible in shell history")
    r_bak.add_argument("--passphrase-file", default=None)

    r_unb = rsub.add_parser("unbackup", help="restore the key from a backup file")
    r_unb.add_argument("--file", required=True)
    r_unb.add_argument(_KEY[0], **_KEY[1])
    r_unb.add_argument("--force", action="store_true")
    r_unb.add_argument("--passphrase", default=None)
    r_unb.add_argument("--passphrase-file", default=None)

    r_spl = rsub.add_parser("split", help="split the key into k-of-n shares")
    r_spl.add_argument(_KEY[0], **_KEY[1])
    r_spl.add_argument("--threshold", type=int, default=3, help="shares needed to restore")
    r_spl.add_argument("--shares", type=int, default=5, help="shares to produce")

    r_cmb = rsub.add_parser("combine", help="reconstruct the key from shares")
    r_cmb.add_argument("--share", action="append", required=True,
                       help="repeat once per share")
    r_cmb.add_argument(_KEY[0], **_KEY[1])
    r_cmb.add_argument("--force", action="store_true")

    r.set_defaults(func=cmd_recover)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--url", default="http://127.0.0.1:8741")
    common.add_argument("--key", default="data/client/master.key")
    common.add_argument("--pin", default="data/client/pin.json")
    common.add_argument("--pubkey", default=None, help="optional pinned node pubkey hex")

    put = sub.add_parser("put", parents=[common], help="encrypt + store a memory")
    put.add_argument("--text", default=None, help="plaintext string")
    put.add_argument("--file", default=None, help="read plaintext from file")
    put.add_argument("--label", default="", help="optional non-secret label (also AAD)")
    put.set_defaults(func=cmd_put)

    get = sub.add_parser("get", parents=[common], help="fetch + verify + decrypt")
    get.add_argument("--index", default=None)
    get.add_argument("--record-id", default=None)
    get.add_argument("--label", default="")
    get.add_argument("--raw", action="store_true", help="write raw bytes to stdout")
    get.set_defaults(func=cmd_get)

    head = sub.add_parser("head", parents=[common], help="fetch + verify signed tree head")
    head.set_defaults(func=cmd_head)

    lst = sub.add_parser("list", parents=[common], help="list record metadata")
    lst.set_defaults(func=cmd_list)

    pe = sub.add_parser("peers", help="discover and probe storage nodes")
    pe.add_argument("--file", default="data/peers.json")
    pe.add_argument("--bootstrap", default=None, help="url returning a peer list")
    pe.add_argument("--all", action="store_true", help="include unreachable peers")
    pe.add_argument("--timeout", type=float, default=2.0)
    pe.add_argument("--json", action="store_true")
    pe.set_defaults(func=cmd_peers)

    au = sub.add_parser("audit", help="challenge nodes to serve records they hold")
    au.add_argument("--url", default=None, help="audit one node instead of a peer file")
    au.add_argument("--file", default="data/peers.json")
    au.add_argument("--key", default="data/client/master.key")
    au.add_argument("--pin-dir", default="data/pins")
    au.add_argument("--sample", type=int, default=5)
    au.add_argument("--timeout", type=float, default=2.0)
    au.add_argument("--json", action="store_true")
    au.set_defaults(func=cmd_audit)

    ch = sub.add_parser("chat", help="chat with a LOCAL model, with memory")
    ch.add_argument("--text", required=True)
    ch.add_argument("--url", default="http://127.0.0.1:8741")
    ch.add_argument("--key", default="data/client/master.key")
    ch.add_argument("--pin", default="data/client/pin.json")
    ch.add_argument("--ollama-base", default="http://127.0.0.1:11434")
    ch.add_argument("--model", default="llama3.2")
    ch.add_argument("--system", default=None)
    ch.add_argument("--recall", type=int, default=6)
    ch.add_argument("--no-remember", action="store_true")
    ch.add_argument("--allow-remote", action="store_true",
                    help="permit a non-loopback model endpoint (prompts leave this machine)")
    ch.set_defaults(func=cmd_chat)

    cc = sub.add_parser("cloud-chat",
                        help="send a prompt to a hosted model — NOT PRIVATE")
    cc.add_argument("--text", required=True)
    cc.add_argument("--api-base", default="https://api.openai.com")
    cc.add_argument("--api-key", default=None,
                    help="or set BLINDKEEP_CLOUD_KEY; a flag is visible in shell history")
    cc.add_argument("--model", default="gpt-4o-mini")
    cc.add_argument("--system", default=None)
    cc.add_argument("--redact", action="store_true",
                    help="best-effort secret removal; NOT a privacy guarantee")
    cc.add_argument("--enable-cloud", action="store_true")
    cc.add_argument("--i-accept-not-private", action="store_true")
    cc.set_defaults(func=cmd_cloud_chat)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
