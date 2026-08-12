"""Blindkeep CLI — run a node, put/get encrypted memory, verify the log."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import dialects
from ._console import use_utf8_stdout

# The dashboard and progress board are local working tools, not part of the
# published project. Their subcommands are registered only when the files are
# actually present, so a clone never advertises a command it cannot run.
_ROOT = Path(__file__).resolve().parent.parent
_HAS_DASHBOARD = (_ROOT / "dashboard.py").is_file()
_HAS_PROGRESS = (Path(__file__).resolve().parent / "progress.py").is_file()


class CliError(Exception):
    """A usage problem stated in the user's terms, not a traceback."""


def _load_key(key_path: str) -> bytes:
    """Load an existing master key, or explain how to make one.

    Creating key material must never be a side effect of another command.
    It previously was, and the consequences were worse than the untidiness
    suggests: a mistyped ``--key`` silently minted a *new* 32-byte secret, so
    ``put`` would encrypt under a key the user did not mean and their real key
    could never read it back. Read-only commands scattered secrets through
    whatever directory they happened to run in, and even commands that went on
    to fail left one behind. `keygen` and `recover` create keys — deliberately,
    and with an overwrite guard. Nothing else does.
    """
    from .client import BlindkeepClient

    if not os.path.exists(key_path):
        raise CliError(
            f"no master key at {key_path}\n"
            f"  create one:  blindkeep keygen --key {key_path}\n"
            f"  or restore:  blindkeep recover restore --code ... --key {key_path}")
    return BlindkeepClient.load_master_key(key_path)


def _client_from_args(args, need_key: bool = True):
    from .client import BlindkeepClient

    key_path = args.key
    # `head` and `list` are metadata-only: neither touches master_key. Asking
    # for a key to read a signed tree head would be a lie about what is needed.
    key = _load_key(key_path) if need_key else b""
    pin = getattr(args, "pin", None) or os.path.join(os.path.dirname(key_path) or ".", "pin.json")
    return BlindkeepClient(args.url, key, pin_path=pin,
                          expected_pubkey_hex=getattr(args, "pubkey", None) or None)


def cmd_node(args) -> int:
    from .node import ExposureRefused, serve
    try:
        serve(args.data_dir, host=args.host, port=args.port,
              accept_no_auth=getattr(args, "accept_no_auth", False))
    except ExposureRefused as exc:
        raise CliError(str(exc))
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


def cmd_status(args) -> int:
    """Report what the repository contains, counted rather than claimed."""
    from .status import main as status_main

    return status_main(["--json"] if args.json else [])


def cmd_prove(args) -> int:
    """Prove a value is within a range, disclosing nothing about it."""
    from .zk import ProofError, commit, prove_range

    try:
        _, blinding = commit(args.value)
        commitment, proof = prove_range(
            args.value, blinding, bits=args.bits,
            context=(args.context or "").encode("utf-8"))
    except ProofError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    out = {"commitment_hex": commitment.value_hex, "bits": args.bits,
           "context": args.context or "", "proof": proof.as_dict()}
    text = json.dumps(out, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"proof written to {args.out}", file=sys.stderr)
        print(f"commitment: {commitment.value_hex}")
    else:
        print(text)
    # The blinding factor is the secret half. Printing it to stdout beside the
    # proof would put it in the same place the proof is about to be shared.
    print(f"[keep this secret to prove anything further about the same value: "
          f"blinding={blinding:x}]", file=sys.stderr)
    return 0


def cmd_verify_proof(args) -> int:
    """Verify a range proof. Exit 0 only if it holds for THIS statement."""
    from .zk import Commitment, Proof, verify_range

    with open(args.proof, "r", encoding="utf-8") as f:
        blob = json.load(f)

    commitment = Commitment(args.commitment or blob["commitment_hex"])
    bits = args.bits if args.bits is not None else int(blob["bits"])
    context = (args.context if args.context is not None
               else blob.get("context", "")) or ""

    ok = verify_range(commitment, Proof.from_dict(blob["proof"]), bits=bits,
                      context=context.encode("utf-8"))
    if ok:
        print(f"VERIFIED: the committed value is in [0, 2^{bits}) "
              f"for context {context!r}")
        return 0
    print("REFUSED: the proof does not hold for this statement", file=sys.stderr)
    return 1


def cmd_prove_in_keep(args) -> int:
    """Prove you hold a record in this keep, without revealing which one."""
    from .client import BlindkeepClient
    from .zk_keep import prove_in_keep

    key = _load_key(args.key)
    client = BlindkeepClient(args.url, key, pin_path=args.pin)
    bundle = prove_in_keep(client, args.index)

    text = json.dumps(bundle, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"proof written to {args.out}", file=sys.stderr)
    else:
        print(text)
    print(f"[proves membership among {bundle['keep_size']} records at root "
          f"{bundle['head']['root_hex'][:16]}… — the index is not in the proof]",
          file=sys.stderr)
    return 0


def cmd_verify_in_keep(args) -> int:
    """Verify against a keep the verifier looks up itself. Exit 0 only if it holds."""
    from .client import BlindkeepClient
    from .zk_keep import keep_leaves, verify_in_keep

    key = _load_key(args.key)
    client = BlindkeepClient(args.url, key, pin_path=args.pin)
    with open(args.proof, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    head = client.head()
    if verify_in_keep(bundle, keep_leaves(client), head):
        print(f"VERIFIED: the prover holds one of the {head['tree_size']} records "
              f"in this keep. Which one is not revealed.")
        return 0
    print("REFUSED: the proof does not hold for this keep at this head",
          file=sys.stderr)
    return 1


def cmd_zk_witness(args) -> int:
    """Export everything a halo2 prover needs for a membership proof over this keep."""
    from .client import BlindkeepClient
    from .zk_tree import export_for_circuit, write_witness

    key = _load_key(args.key)
    client = BlindkeepClient(args.url, key, pin_path=args.pin)
    bundle = export_for_circuit(client, args.index)

    if args.out:
        write_witness(bundle, args.out)
        print(f"witness written to {args.out}", file=sys.stderr)
    else:
        print(json.dumps(bundle, indent=2))
    print(f"[depth {bundle['depth']} · poseidon root {bundle['public']['root'][:16]}… "
          f"· anchored to signed head {bundle['anchor']['sha256_root_hex'][:16]}…]",
          file=sys.stderr)
    print("[the leaf and path are PRIVATE inputs; only the root is public]", file=sys.stderr)
    return 0


def _find_prover(explicit=None):
    """Locate blindkeep-prove: an explicit path, an env var, or PATH.

    Returned as a path rather than invoked, so a missing prover is a message about installing one
    binary and not a traceback from a failed subprocess.
    """
    import shutil

    for candidate in (explicit, os.environ.get("BLINDKEEP_PROVER")):
        if candidate:
            if os.path.isfile(candidate):
                return candidate
            raise CliError(f"no prover at {candidate}")
    found = shutil.which("blindkeep-prove") or shutil.which("blindkeep-prove.exe")
    if found:
        return found
    raise CliError(
        "blindkeep-prove was not found.\n"
        "  It is a single binary that turns a witness into a SNARK proof. Either:\n"
        "    put it on PATH, pass --prover /path/to/it, or set BLINDKEEP_PROVER\n"
        "  Build it from https://github.com/zcashsensei/zk-encrypted-intelligence:\n"
        "    cargo build --release --bin blindkeep-prove\n"
        "  Or skip proving and export the witness alone:  blindkeep zk-witness")


def cmd_zk_prove(args) -> int:
    """Witness and proof in one step: export, prove, done."""
    import subprocess
    import tempfile

    from .client import BlindkeepClient
    from .zk_tree import export_for_circuit, write_witness

    prover = _find_prover(args.prover)

    key = _load_key(args.key)
    client = BlindkeepClient(args.url, key, pin_path=args.pin)
    bundle = export_for_circuit(client, args.index)

    # The witness holds the leaf and the full path — the private half. It goes to a temporary file
    # and is removed, so the one artefact left behind is the proof, which reveals nothing.
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    tmp.close()
    try:
        write_witness(bundle, tmp.name)
        cmd = [prover, "prove", "--witness", tmp.name, "--out", args.out]
        # encoding is not optional: the prover emits UTF-8, and decoding it with the system
        # codepage turns "·" into "Â·" and "…" into "â€¦". Same class as the console guard —
        # a child's output is UTF-8 whatever the parent's locale happens to be.
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
        if proc.returncode != 0:
            print(proc.stderr.strip() or "the prover failed", file=sys.stderr)
            return 1
        for line in proc.stderr.strip().splitlines():
            print(f"[{line}]", file=sys.stderr)
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

    print(f"[witness discarded — the proof reveals neither the record nor its position]",
          file=sys.stderr)
    print(args.out)
    return 0


def cmd_token(args) -> int:
    """Issue or verify an anonymous entitlement.

    Both sides live here because a single-machine demonstration is the only way to show the
    property without standing up a service: the issuer signs a blinded value, and the token that
    comes back shares nothing with what it signed.
    """
    from .anon_token import Client, Issuer, Token, TokenError

    if args.action == "issue":
        # Prefer the gateway's issuer so tokens redeem on frontier-gateway.
        issuer_path = getattr(args, "issuer_key", None) or "data/gateway_issuer.pem"
        if os.path.exists(issuer_path):
            from .frontier_gateway import load_issuer, save_issuer
            issuer = load_issuer(issuer_path)
        else:
            issuer = Issuer()
            if getattr(args, "issuer_key", None) or True:
                try:
                    from .frontier_gateway import save_issuer
                    save_issuer(issuer, issuer_path)
                    print(f"issuer key written to {issuer_path}", file=sys.stderr)
                except Exception:
                    pass
        # A persisted gateway issuer is exactly what a client should be pinning: one key, one
        # crowd. Both ends are ours here, so this demonstrates the refusal rather than defending
        # against it — a real client learns this id from somewhere the gateway does not control.
        client = Client(*issuer.public, expected_key_id=issuer.key_id)
        print(f"[issuer key {issuer.key_id[:16]}… — a client blinding under any other key is "
              f"in a crowd of one]", file=sys.stderr)
        blinded = client.blind()
        token = client.unblind(issuer.sign_blinded(blinded))
        if os.path.exists(issuer_path):
            try:
                from .frontier_gateway import save_issuer
                save_issuer(issuer, issuer_path)
            except Exception:
                pass

        out = token.as_dict()
        text = json.dumps(out, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"token written to {args.out}", file=sys.stderr)
        else:
            print(text)
        print(f"[the issuer signed {f'{blinded:x}'[:16]}… and will later see "
              f"{token.value_hex[:16]}… — it cannot connect them]", file=sys.stderr)
        print("[single use: an issuer that does not remember has issued an "
              "unlimited pass]", file=sys.stderr)
        return 0

    with open(args.token, "r", encoding="utf-8") as f:
        blob = json.load(f)
    tok = Token(value_hex=blob["token_hex"], signature_hex=blob["signature_hex"],
                key_id_hex=blob.get("key_id", ""))
    if tok.key_id_hex:
        print(f"[issued under key {tok.key_id_hex[:16]}… — a verifier holding a different key "
              f"refuses this by name]", file=sys.stderr)
    print(f"token {tok.value_hex[:16]}… — verification needs the issuer's key, "
          f"which this command does not have.", file=sys.stderr)
    print("A real deployment verifies at the provider. This checks shape only.")
    return 0 if len(tok.value) == 32 and tok.signature_hex else 1


def cmd_read_private(args) -> int:
    """Read one record without telling the node which. Costs the whole keep."""
    from .client import BlindkeepClient
    from .private_read import RetrievalError, read_private, visibility

    key = _load_key(args.key)
    client = BlindkeepClient(args.url, key, pin_path=args.pin)
    try:
        r = read_private(client, args.index, max_records=args.max_records)
    except RetrievalError as exc:
        raise CliError(str(exc))

    print(f"[{r.cost()}]", file=sys.stderr)
    if args.show_visibility:
        for k, v in visibility(client).items():
            print(f"[  {k}: {v}]", file=sys.stderr)
    if args.raw:
        sys.stdout.buffer.write(r.plaintext)
    else:
        print(r.plaintext.decode("utf-8", errors="replace"))
    return 0


def cmd_gossip(args) -> int:
    """Compare signed heads with another client. Catches a node telling two stories."""
    from .client import BlindkeepClient
    from .witness import EquivocationError, HeadLog, SignedHead, gossip

    key = _load_key(args.key)
    client = BlindkeepClient(args.url, key, pin_path=args.pin)
    head = client.head()

    log = (HeadLog.load(args.log) if args.log and os.path.exists(args.log)
           else HeadLog(public_key_hex=head["public_key_hex"]))
    try:
        log.observe(SignedHead.from_dict(head))
        added = 0
        if args.theirs:
            with open(args.theirs, "r", encoding="utf-8") as f:
                theirs = json.load(f)
            added = gossip(log, theirs.get("heads", theirs))
    except EquivocationError as exc:
        # The one outcome worth shouting about: two of the node's own signatures on
        # contradictory claims. Written out so it survives this process.
        print(f"EQUIVOCATION DETECTED: {exc}", file=sys.stderr)
        out = args.proof or "equivocation_proof.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(exc.proof.as_dict(), f, indent=2)
        print(f"proof written to {out} — it verifies without this node and "
              f"without trusting you", file=sys.stderr)
        return 1

    if args.log:
        log.save(args.log)
    print(f"{len(log.heads)} head(s) known for this node, {added} new from gossip")
    print("no contradiction found — which is not proof of honesty, only that "
          "nobody comparing has seen one yet")
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
    from .discover import discover, urls

    key = _load_key(args.key)
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

    key = _load_key(args.key)
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
        dialect=getattr(args, 'dialect', None),
        enable_cloud=args.enable_cloud,
        accept_not_private=args.i_accept_not_private,
        system=args.system, apply_redaction=args.redact)
    print(f"[{result['notice']}]", file=sys.stderr)
    if result["redacted"]:
        print(f"[redacted before sending: {', '.join(result['redacted'])}]",
              file=sys.stderr)
    print(result["reply"])
    return 0


def cmd_private_chat(args) -> int:
    """Pseudonymised cloud path. Smaller disclosure — still a disclosure."""
    from .client import BlindkeepClient
    from .vault_proxy import EntityVault, private_cloud_complete

    key = _load_key(args.key)
    client = BlindkeepClient(args.url, key, pin_path=args.pin)

    if args.vault_record:
        vault = EntityVault.load(client, args.vault_record)
    else:
        vault = EntityVault()

    for value in args.declare or []:
        vault.declare(value)
    for pair in args.declare_as or []:
        kind, _, value = pair.partition(":")
        if not value:
            raise ValueError(f"--declare-as expects KIND:VALUE, got {pair!r}")
        vault.declare(value, kind=kind)

    api_key = args.api_key or os.environ.get("BLINDKEEP_CLOUD_KEY", "")
    result = private_cloud_complete(
        args.text, vault=vault, api_base=args.api_base, api_key=api_key,
        dialect=getattr(args, 'dialect', None),
        model=args.model, enable_cloud=args.enable_cloud,
        accept_not_private=args.i_accept_not_private, system=args.system)

    # Persist the mapping through the encrypted path so the next call reuses the
    # same placeholders. Without this the pseudonyms change every run and the
    # model loses the thread it was given the vault to keep.
    ref = vault.save(client)

    print(f"[{result['notice']}]", file=sys.stderr)
    print(f"[sent: {result['sent']}]", file=sys.stderr)
    print(f"[{result['residual_risk']}]", file=sys.stderr)
    print(f"[vault record: {ref['record_id']} — pass --vault-record to reuse]",
          file=sys.stderr)
    print(result["reply"])
    return 0


def cmd_frontier_chat(args) -> int:
    """Maximum-effort path: content gate + optional account-decoupled gateway.

    With --gateway-url + --token: client holds NO provider API key (historic
    account decoupling via blind token). With --api-base + --api-key: classic
    content-only path (account still yours).
    """
    from .frontier_private import (
        FrontierPrivateError,
        default_api_key,
        frontier_chat,
        make_cloud_remote,
        make_ollama_local,
    )

    if not args.enable_frontier or not args.accept_residual_risks:
        raise CliError(
            "frontier-chat needs both acknowledgements:\n"
            "  --enable-frontier\n"
            "  --accept-residual-risks\n"
            "Content is gated either way. Account identity is only decoupled "
            "when you use --gateway-url + --token (no client API key).")

    context: list[str] = []
    if args.with_keep:
        key = _load_key(args.key)
        from .client import BlindkeepClient
        from .memory_gate import Sensitivity, decode_label
        c = BlindkeepClient(args.url, key, pin_path=args.pin)
        try:
            for rec in c.list()[-args.recall:]:
                try:
                    opened = c.get(int(rec["index"]))
                    sens, _ = decode_label(opened.get("label") or "")
                    if sens is Sensitivity.SECRET:
                        continue
                    pt = opened["plaintext"]
                    if isinstance(pt, bytes):
                        pt = pt.decode("utf-8", "replace")
                    if pt:
                        context.append(pt)
                except Exception:
                    continue
        except Exception:
            pass

    local = make_ollama_local(args.ollama_base, args.local_model)
    account_decoupled = False

    if args.gateway_url:
        if not args.token:
            raise CliError(
                "--gateway-url requires --token (a blind token from the issuer).\n"
                "  blindkeep token issue --out token.json   # with issuer key\n"
                "  Or redeem against the gateway's issuer.")
        from .anon_token import Token
        from .frontier_gateway import make_gateway_remote
        with open(args.token, "r", encoding="utf-8") as f:
            blob = json.load(f)
        tok = Token(value_hex=blob["token_hex"], signature_hex=blob["signature_hex"])
        if not args.model:
            raise CliError("--model is required")
        remote = make_gateway_remote(
            args.gateway_url, tok, model=args.model,
            use_ohttp=bool(args.relay_url),
            ohttp_key_config_b64=args.ohttp_config,
            relay_url=args.relay_url,
        )
        account_decoupled = True
    else:
        api_key = args.api_key or default_api_key()
        if not args.api_base:
            raise CliError(
                "pass --api-base + key, OR --gateway-url + --token "
                "(account-decoupled historic path)")
        if not args.model:
            raise CliError("--model is required")
        if not api_key:
            raise CliError(
                "no API key: pass --api-key or set BLINDKEEP_CLOUD_KEY, "
                "or use --gateway-url + --token so the client never holds one")
        remote = make_cloud_remote(
            api_base=args.api_base, api_key=api_key, model=args.model,
            dialect=args.dialect)

    try:
        receipt = frontier_chat(
            args.text,
            local=local,
            remote=remote,
            context=context,
            enable_frontier=True,
            accept_residual_risks=True,
            max_specificity=args.max_specificity,
            ohttp_independent_operators=(
                True if getattr(args, "ohttp_independent", False) else None),
            account_decoupled=account_decoupled,
        )
    except FrontierPrivateError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1

    print(f"[{receipt.notice}]", file=sys.stderr)
    print(f"[mode: {receipt.mode} · attempts: {receipt.attempts} · "
          f"account_decoupled: {receipt.account_decoupled}]", file=sys.stderr)
    print(f"[sent toward provider / gateway:]", file=sys.stderr)
    print(receipt.sent, file=sys.stderr)
    print("[claims]", file=sys.stderr)
    for c in receipt.claims:
        print(f"  + {c}", file=sys.stderr)
    print("[residual — not claimed]", file=sys.stderr)
    for r in receipt.residual:
        print(f"  - {r}", file=sys.stderr)
    print(receipt.reply)
    return 0


def cmd_frontier_gateway(args) -> int:
    """Run the account-decoupled frontier gateway (holds the API key)."""
    from .frontier_gateway import (
        FrontierGateway, load_issuer, save_issuer, serve_gateway,
    )
    from .anon_token import Issuer

    api_key = args.api_key or os.environ.get("BLINDKEEP_CLOUD_KEY", "")
    if not api_key or not args.api_base:
        raise CliError("--api-base and --api-key (or BLINDKEEP_CLOUD_KEY) required")
    if args.issuer_key and os.path.exists(args.issuer_key):
        issuer = load_issuer(args.issuer_key)
    else:
        issuer = Issuer()
        if args.issuer_key:
            save_issuer(issuer, args.issuer_key)
            print(f"issuer key written to {args.issuer_key}", file=sys.stderr)
    gw = FrontierGateway(
        api_base=args.api_base, api_key=api_key,
        default_model=args.model or "default",
        dialect=args.dialect, issuer=issuer,
    )
    httpd = serve_gateway(gw, host=args.host, port=args.port)
    params = gw.public_params()
    print(f"frontier-gateway -> http://{args.host}:{args.port}", file=sys.stderr)
    print(f"  params: GET /v1/params", file=sys.stderr)
    print(f"  complete: POST /v1/complete  (header Blindkeep-Token)", file=sys.stderr)
    print(f"  ohttp: POST /ohttp", file=sys.stderr)
    print(f"  issuer n…{params['issuer_n_hex'][-16:]}", file=sys.stderr)
    print("  Ctrl-C to stop. Clients should NOT send a provider API key.",
          file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
        if args.issuer_key:
            save_issuer(gw.issuer, args.issuer_key)
    return 0


def cmd_frontier_relay(args) -> int:
    """Run an OHTTP relay (sees IPs, never plaintext)."""
    from .frontier_relay import serve_relay
    if not args.gateway:
        raise CliError("--gateway is required (gateway base URL)")
    httpd = serve_relay(args.gateway, host=args.host, port=args.port)
    print(f"frontier-relay -> http://{args.host}:{args.port}", file=sys.stderr)
    print(f"  forwards OHTTP to {args.gateway}", file=sys.stderr)
    print("  If YOU also run the gateway, network anonymity is VOID.",
          file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
    return 0


def cmd_attest(args) -> int:
    """Challenge a model host to prove it cannot read what it computes."""
    from .attest import AttestationError, Policy, attest_host

    try:
        policy = Policy.build(args.measurement, args.root,
                              max_age_seconds=args.max_age)
        result = attest_host(args.url, policy=policy, timeout=args.timeout)
    except AttestationError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1

    print(result.summary())
    for check in result.checks:
        print(f"  ok  {check}")
    return 0


def Policy_for(args):
    """The attestation policy named by the CLI flags."""
    from .attest import Policy
    return Policy.build(args.measurement, args.root, max_age_seconds=args.max_age)


def _hosted_completer(args, api_key):
    """A completer for any hosted endpoint, optionally spending an anonymous token.

    The token is what stops the request being attributable. Without it a question about nobody
    still arrives from a named subscriber, which tells the provider who asked even though it
    cannot tell what about — so the flag exists and its absence is reported rather than assumed
    away.
    """
    from .cloud_gate import cloud_complete

    headers = {}
    if getattr(args, "anon_token", None):
        from .anon_token import Token
        with open(args.anon_token, "r", encoding="utf-8") as f:
            blob = json.load(f)
        tok = Token(value_hex=blob["token_hex"], signature_hex=blob["signature_hex"])
        # The Privacy Pass shape: an entitlement presented alongside the request, carrying no
        # identity. Sent as a header rather than in the body so the model never reads it.
        headers["Blindkeep-Token"] = f"{tok.value_hex}.{tok.signature_hex}"

    def complete(prompt, system=None):
        return cloud_complete(
            prompt, api_base=args.api_base, api_key=api_key, model=args.model,
            system=system, enable_cloud=args.enable_cloud,
            accept_not_private=args.i_accept_not_private,
            headers=headers or None)["reply"]

    return complete


def _require_api_base_for_tier(args) -> None:
    """Refuse a missing endpoint before anything that needs a key.

    Every tier above local sends somewhere, and Blindkeep does not pick the
    somewhere. A shipped default endpoint is an endorsement, and on the paths
    that disclose it is the one choice the user must make consciously.

    This check is pure (no key, no network) so a fresh clone — no master key
    yet — still sees the "choose a provider" message rather than a key-path
    error that buries the real omission.
    """
    from .memory_gate import Tier

    tier = Tier[args.tier.upper()]
    if tier is Tier.LOCAL:
        return
    if args.api_base:
        return
    raise CliError(
        f"--api-base is required for --tier {tier.label}\n"
        f"  Blindkeep does not choose a provider for you, and does not "
        f"require one API. Closed or open weights, hosted or self-run:\n"
        f"    --api-base https://api.anthropic.com  --model <claude model>\n"
        f"    --api-base https://api.x.ai           --model <grok model>\n"
        f"    --api-base https://api.openai.com     --model <gpt model>\n"
        f"    --api-base http://127.0.0.1:8000      --model <self-hosted>\n"
        f"  The wire format is inferred from the endpoint; override it with "
        f"--dialect ({', '.join(sorted(dialects.DIALECTS))}).")


def _gate_backend(args, client):
    """Build the backend named by --tier, with the prover that tier requires."""
    from .memory_gate import (SimpleBackend, Tier, attestation_prover,
                              delegation_prover, loopback_prover, sealed_prover,
                              vault_prover)

    tier = Tier[args.tier.upper()]

    if tier is Tier.LOCAL:
        from .ollama_mem import OllamaMemory
        mem = OllamaMemory(client, ollama_base=args.ollama_base,
                           model=args.model)
        return SimpleBackend(
            name=f"ollama:{args.model}", claimed_tier=tier,
            completer=lambda p, s: mem.chat(p, system=s, remember=False,
                                            recall=0),
            prover=loopback_prover(args.ollama_base))

    _require_api_base_for_tier(args)

    api_key = args.api_key or os.environ.get("BLINDKEEP_CLOUD_KEY", "")

    if tier in (Tier.DELEGATED, Tier.SEALED):
        from .delegate import LeakGate
        from .ollama_mem import OllamaMemory

        # The abstraction is written by a model on THIS machine. Without one there is nothing to
        # abstract with, and the honest behaviour is to refuse rather than fall back to sending
        # the raw text — which is the failure this whole tier exists to prevent.
        mem = OllamaMemory(client, ollama_base=args.ollama_base,
                           model=args.local_model)
        local = lambda p, s: mem.chat(p, system=s, remember=False, recall=0)
        gate = LeakGate(max_specificity=args.max_specificity)

        remote = _hosted_completer(args, api_key)

        if tier is Tier.SEALED:
            policy = Policy_for(args)
            prover = sealed_prover(args.attest_url, policy, gate)
            name = f"sealed:{args.model}"
        else:
            prover = delegation_prover(gate)
            name = f"delegated:{args.model}"

        return SimpleBackend(name=name, claimed_tier=tier, completer=remote,
                             prover=prover, local=local, gate=gate)

    if tier is Tier.ATTESTED:
        from .attest import Policy, attest_host, attested_complete
        policy = Policy.build(args.measurement, args.root,
                              max_age_seconds=args.max_age)
        # Verify once, then reuse the Result for the completion so the call is
        # provably ordered after a passing check.
        result = attest_host(args.attest_url, policy=policy)
        return SimpleBackend(
            name=f"attested:{args.model}", claimed_tier=tier,
            completer=lambda p, s: attested_complete(
                p, api_base=args.api_base, api_key=api_key, model=args.model,
                result=result, system=s)["reply"],
            prover=lambda: attestation_prover(args.attest_url, policy)())

    # One hosted completer for every tier that talks to a provider. There used to be a second,
    # inline one here, and it silently dropped the anonymous token: the entitlement was read,
    # formatted and then never sent, so `--anon-token` appeared to work and protected nothing.
    # Two paths to the same destination is how a flag becomes decoration.
    cloud = _hosted_completer(args, api_key)

    if tier is Tier.PSEUDONYMOUS:
        from .vault_proxy import EntityVault
        vault = (EntityVault.load(client, args.vault_record)
                 if args.vault_record else EntityVault())
        for value in args.declare or []:
            vault.declare(value)
        for pair in args.declare_as or []:
            kind, _, value = pair.partition(":")
            if not value:
                raise ValueError(f"--declare-as expects KIND:VALUE, got {pair!r}")
            vault.declare(value, kind=kind)
        return SimpleBackend(name=f"pseudonymous:{args.model}",
                             claimed_tier=tier, completer=cloud,
                             prover=vault_prover(vault), vault=vault)

    return SimpleBackend(name=f"open:{args.model}", claimed_tier=Tier.OPEN,
                         completer=cloud)


def cmd_gate_chat(args) -> int:
    """One memory layer, any model, release decided by a PROVEN tier."""
    from .client import BlindkeepClient
    from .memory_gate import MemoryGate, Sensitivity

    # Endpoint before key: a missing --api-base is the user's real omission on
    # every tier above local, and must name itself rather than hide under
    # "no master key" when the keep has not been initialised yet.
    _require_api_base_for_tier(args)

    key = _load_key(args.key)
    client = BlindkeepClient(args.url, key, pin_path=args.pin)
    gate = MemoryGate(client, index_path=args.index)
    backend = _gate_backend(args, client)

    out = gate.chat(backend, args.text, system=args.system,
                    recall=args.recall, remember=not args.no_remember,
                    sensitivity=Sensitivity[args.sensitivity.upper()])

    print(f"[tier: {out['grant']}]", file=sys.stderr)
    print(f"[memory: {out['summary']}]", file=sys.stderr)
    if backend.vault is not None:
        ref = backend.vault.save(client)
        print(f"[vault record: {ref['record_id']}]", file=sys.stderr)
    print(out["reply"])
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
        key = _load_key(args.key)
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
        key = _load_key(args.key)
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
        key = _load_key(args.key)
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
    # Check the selector before building a client: `get` with neither flag used
    # to reach `int(None)` and surface as a TypeError about int().
    if args.record_id is None and args.index is None:
        raise CliError("get needs one of --index N or --record-id ID")
    if args.record_id is not None and args.index is not None:
        raise CliError("get takes --index or --record-id, not both")

    client = _client_from_args(args)
    # None (not "") means "use the label the record was stored with".
    label = args.label or None
    if args.record_id:
        result = client.get_by_id(args.record_id, label=label)
    else:
        result = client.get(args.index, label=label)
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
    client = _client_from_args(args, need_key=False)
    head = client.head()
    print(json.dumps(head, indent=2))
    return 0


def cmd_list(args) -> int:
    client = _client_from_args(args, need_key=False)
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
    n.add_argument("--accept-no-auth", action="store_true",
                   help="bind a non-loopback address despite there being no "
                        "authentication or TLS on this node")
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
    get.add_argument("--index", type=int, default=None)
    get.add_argument("--record-id", default=None)
    get.add_argument("--label", default="")
    get.add_argument("--raw", action="store_true", help="write raw bytes to stdout")
    get.set_defaults(func=cmd_get)

    head = sub.add_parser("head", parents=[common], help="fetch + verify signed tree head")
    head.set_defaults(func=cmd_head)

    lst = sub.add_parser("list", parents=[common], help="list record metadata")
    lst.set_defaults(func=cmd_list)

    st = sub.add_parser("status",
                        help="what this repo contains — tests counted, not stated")
    st.add_argument("--json", action="store_true")
    st.set_defaults(func=cmd_status)

    pr = sub.add_parser("prove",
                        help="prove a value is within a range, revealing nothing")
    pr.add_argument("--value", type=int, required=True)
    pr.add_argument("--bits", type=int, default=32,
                    help="prove 0 <= value < 2^bits")
    pr.add_argument("--context", default=None,
                    help="the statement this proof is bound to, e.g. "
                         "'desk:kage|limit:1024'; a proof does not transfer to "
                         "another context")
    pr.add_argument("--out", default=None, help="write the proof to a file")
    pr.set_defaults(func=cmd_prove)

    vp = sub.add_parser("verify-proof", help="verify a range proof")
    vp.add_argument("--proof", required=True)
    vp.add_argument("--commitment", default=None,
                    help="override the commitment in the proof file")
    vp.add_argument("--bits", type=int, default=None)
    vp.add_argument("--context", default=None)
    vp.set_defaults(func=cmd_verify_proof)

    pk = sub.add_parser("prove-in-keep",
                        help="prove you hold a record here, without saying which")
    pk.add_argument("--index", type=int, required=True,
                    help="the record to prove; NOT revealed by the proof")
    pk.add_argument("--url", default="http://127.0.0.1:8741")
    pk.add_argument("--key", default="data/client/master.key")
    pk.add_argument("--pin", default="data/client/pin.json")
    pk.add_argument("--out", default=None)
    pk.set_defaults(func=cmd_prove_in_keep)

    vk = sub.add_parser("verify-in-keep",
                        help="verify a membership proof against this keep")
    vk.add_argument("--proof", required=True)
    vk.add_argument("--url", default="http://127.0.0.1:8741")
    vk.add_argument("--key", default="data/client/master.key")
    vk.add_argument("--pin", default="data/client/pin.json")
    vk.set_defaults(func=cmd_verify_in_keep)

    zw = sub.add_parser("zk-witness",
                        help="export a halo2 membership witness for a record")
    zw.add_argument("--index", type=int, required=True)
    zw.add_argument("--url", default="http://127.0.0.1:8741")
    zw.add_argument("--key", default="data/client/master.key")
    zw.add_argument("--pin", default="data/client/pin.json")
    zw.add_argument("--out", default=None)
    zw.set_defaults(func=cmd_zk_witness)

    zp = sub.add_parser("zk-prove",
                        help="export a witness and prove it in one step")
    zp.add_argument("--index", type=int, required=True)
    zp.add_argument("--out", default="proof.json")
    zp.add_argument("--prover", default=None,
                    help="path to blindkeep-prove; also read from BLINDKEEP_PROVER or PATH")
    zp.add_argument("--url", default="http://127.0.0.1:8741")
    zp.add_argument("--key", default="data/client/master.key")
    zp.add_argument("--pin", default="data/client/pin.json")
    zp.set_defaults(func=cmd_zk_prove)

    tk = sub.add_parser("token",
                        help="issue an anonymous entitlement — prove you may ask, not who you are")
    tk.add_argument("action", choices=["issue", "inspect"])
    tk.add_argument("--out", default=None)
    tk.add_argument("--token", default=None, help="for inspect")
    tk.add_argument("--issuer-key", default="data/gateway_issuer.pem",
                    help="RSA PEM shared with frontier-gateway (created if missing)")
    tk.set_defaults(func=cmd_token)

    rp = sub.add_parser("read-private",
                        help="read a record without revealing which one — costs the whole keep")
    rp.add_argument("--index", type=int, required=True)
    rp.add_argument("--url", default="http://127.0.0.1:8741")
    rp.add_argument("--key", default="data/client/master.key")
    rp.add_argument("--pin", default="data/client/pin.json")
    rp.add_argument("--max-records", type=int, default=2000)
    rp.add_argument("--raw", action="store_true")
    rp.add_argument("--show-visibility", action="store_true",
                    help="print what the node can still see afterwards")
    rp.set_defaults(func=cmd_read_private)

    gs = sub.add_parser("gossip",
                        help="compare signed heads with another client; catch a split view")
    gs.add_argument("--url", default="http://127.0.0.1:8741")
    gs.add_argument("--key", default="data/client/master.key")
    gs.add_argument("--pin", default="data/client/pin.json")
    gs.add_argument("--log", default="data/client/heads.json",
                    help="your record of heads seen from this node")
    gs.add_argument("--theirs", default=None,
                    help="another client's exported heads")
    gs.add_argument("--proof", default=None,
                    help="where to write an equivocation proof if one is found")
    gs.set_defaults(func=cmd_gossip)

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
    cc.add_argument("--api-base", required=True,
                    help="required: Blindkeep does not choose a provider for you")
    cc.add_argument("--dialect", default=None, choices=sorted(dialects.DIALECTS),
                    help="wire format to speak; inferred from --api-base when omitted (any model, closed or open weights)")
    cc.add_argument("--api-key", default=None,
                    help="or set BLINDKEEP_CLOUD_KEY; a flag is visible in shell history")
    cc.add_argument("--model", required=True)
    cc.add_argument("--system", default=None)
    cc.add_argument("--redact", action="store_true",
                    help="best-effort secret removal; NOT a privacy guarantee")
    cc.add_argument("--enable-cloud", action="store_true")
    cc.add_argument("--i-accept-not-private", action="store_true")
    cc.set_defaults(func=cmd_cloud_chat)

    pc = sub.add_parser(
        "private-chat",
        help="hosted model with pseudonymised values — SMALLER disclosure, "
             "not a private one")
    pc.add_argument("--text", required=True)
    pc.add_argument("--url", default="http://127.0.0.1:8741")
    pc.add_argument("--key", default="data/client/master.key")
    pc.add_argument("--pin", default="data/client/pin.json")
    pc.add_argument("--vault-record", default=None,
                    help="record id of a stored entity vault; a new one is "
                         "created and saved if omitted")
    pc.add_argument("--declare", action="append", default=[],
                    help="a value to pseudonymise as PERSON (repeatable)")
    pc.add_argument("--declare-as", action="append", default=[],
                    help="KIND:VALUE, e.g. ORG:Acme (repeatable)")
    pc.add_argument("--api-base", required=True,
                    help="required: Blindkeep does not choose a provider for you")
    pc.add_argument("--dialect", default=None, choices=sorted(dialects.DIALECTS),
                    help="wire format to speak; inferred from --api-base when omitted (any model, closed or open weights)")
    pc.add_argument("--api-key", default=None,
                    help="or set BLINDKEEP_CLOUD_KEY; a flag is visible in shell history")
    pc.add_argument("--model", required=True)
    pc.add_argument("--system", default=None)
    pc.add_argument("--enable-cloud", action="store_true")
    pc.add_argument("--i-accept-not-private", action="store_true")
    pc.set_defaults(func=cmd_private_chat)

    at = sub.add_parser(
        "attest",
        help="challenge a model host to prove it cannot read your data")
    at.add_argument("--url", required=True, help="the host's attestation endpoint")
    at.add_argument("--measurement", action="append", default=[], required=True,
                    help="an approved code measurement, hex (repeatable)")
    at.add_argument("--root", action="append", default=[], required=True,
                    help="a trusted root key, hex (repeatable)")
    at.add_argument("--max-age", type=float, default=300.0,
                    help="reject reports older than this many seconds")
    at.add_argument("--timeout", type=float, default=10.0)
    at.set_defaults(func=cmd_attest)

    fc = sub.add_parser(
        "frontier-chat",
        help="max-effort frontier path: content gate; optional "
             "account-decoupled gateway (no client API key)")
    fc.add_argument("--text", required=True)
    fc.add_argument("--api-base", default=None,
                    help="direct path only — omit when using --gateway-url")
    fc.add_argument("--model", default=None)
    fc.add_argument("--api-key", default=None)
    fc.add_argument("--dialect", default=None, choices=sorted(dialects.DIALECTS))
    fc.add_argument("--gateway-url", default=None,
                    help="account-decoupled gateway (client sends blind token only)")
    fc.add_argument("--token", default=None,
                    help="JSON token file for gateway path")
    fc.add_argument("--relay-url", default=None,
                    help="OHTTP relay base (with --gateway-url + --ohttp-config)")
    fc.add_argument("--ohttp-config", default=None,
                    help="gateway ohttp_key_config_b64 from GET /v1/params")
    fc.add_argument("--local-model", default="llama3.2",
                    help="Ollama model that abstracts and re-specialises")
    fc.add_argument("--ollama-base", default="http://127.0.0.1:11434")
    fc.add_argument("--max-specificity", type=int, default=24)
    fc.add_argument("--with-keep", action="store_true",
                    help="use recent keep memories as private context for the gate")
    fc.add_argument("--url", default="http://127.0.0.1:8741")
    fc.add_argument("--key", default="data/client/master.key")
    fc.add_argument("--pin", default="data/client/pin.json")
    fc.add_argument("--index", default="data/client/gate_index.json")
    fc.add_argument("--recall", type=int, default=6)
    fc.add_argument("--ohttp-independent", action="store_true",
                    help="you assert relay≠gateway operators (code cannot verify)")
    fc.add_argument("--enable-frontier", action="store_true",
                    help="turn on the frontier-private path")
    fc.add_argument("--accept-residual-risks", action="store_true",
                    help="accept residual risks listed in the receipt")
    fc.set_defaults(func=cmd_frontier_chat)

    fg = sub.add_parser(
        "frontier-gateway",
        help="run account-decoupled gateway (holds API key; redeems blind tokens)")
    fg.add_argument("--host", default="127.0.0.1")
    fg.add_argument("--port", type=int, default=8751)
    fg.add_argument("--api-base", required=True)
    fg.add_argument("--api-key", default=None)
    fg.add_argument("--model", default=None)
    fg.add_argument("--dialect", default=None, choices=sorted(dialects.DIALECTS))
    fg.add_argument("--issuer-key", default="data/gateway_issuer.pem",
                    help="RSA PEM for blind tokens; created if missing")
    fg.set_defaults(func=cmd_frontier_gateway)

    fr = sub.add_parser(
        "frontier-relay",
        help="run OHTTP relay (sees IPs; never plaintext)")
    fr.add_argument("--host", default="127.0.0.1")
    fr.add_argument("--port", type=int, default=8750)
    fr.add_argument("--gateway", required=True,
                    help="gateway base URL (…/ohttp appended if needed)")
    fr.set_defaults(func=cmd_frontier_relay)

    gc = sub.add_parser(
        "gate-chat",
        help="one encrypted memory layer, any model, release by PROVEN tier")
    gc.add_argument("--text", required=True)
    gc.add_argument("--tier", required=True,
                    choices=["local", "sealed", "attested", "delegated",
                             "pseudonymous", "open"],
                    help="what the backend CLAIMS; it must prove it or be demoted")
    gc.add_argument("--sensitivity", default="personal",
                    choices=["public", "personal", "sensitive", "secret"],
                    help="class to store this exchange under")
    gc.add_argument("--url", default="http://127.0.0.1:8741")
    gc.add_argument("--key", default="data/client/master.key")
    gc.add_argument("--pin", default="data/client/pin.json")
    gc.add_argument("--index", default="data/client/gate_index.json")
    gc.add_argument("--recall", type=int, default=6)
    gc.add_argument("--no-remember", action="store_true")
    gc.add_argument("--system", default=None)
    gc.add_argument("--model", default="llama3.2")
    gc.add_argument("--local-model", default="llama3.2",
                    help="the LOCAL model that writes the abstraction for "
                         "--tier delegated / sealed")
    gc.add_argument("--max-specificity", type=int, default=None,
                    help="refuse an abstraction carrying more than N uncommon "
                         "terms; a proxy for how identifying it is, off by default")
    gc.add_argument("--anon-token", default=None,
                    help="a blind-signed entitlement from `blindkeep token`, so "
                         "the request is not attributable to you")
    gc.add_argument("--ollama-base", default="http://127.0.0.1:11434")
    gc.add_argument("--api-base", default=None,
                    help="required for every tier except local: Blindkeep does not choose a provider for you")
    gc.add_argument("--dialect", default=None, choices=sorted(dialects.DIALECTS),
                    help="wire format to speak; inferred from --api-base when omitted (any model, closed or open weights)")
    gc.add_argument("--api-key", default=None,
                    help="or set BLINDKEEP_CLOUD_KEY; a flag is visible in shell history")
    gc.add_argument("--attest-url", default=None,
                    help="attestation endpoint, required for --tier attested")
    gc.add_argument("--measurement", action="append", default=[])
    gc.add_argument("--root", action="append", default=[])
    gc.add_argument("--max-age", type=float, default=300.0)
    gc.add_argument("--vault-record", default=None)
    gc.add_argument("--declare", action="append", default=[])
    gc.add_argument("--declare-as", action="append", default=[])
    gc.add_argument("--enable-cloud", action="store_true")
    gc.add_argument("--i-accept-not-private", action="store_true")
    gc.set_defaults(func=cmd_gate_chat)

    return p


def main(argv=None) -> int:
    use_utf8_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except CliError as e:
        # A usage problem: the message is the whole point, so no "error:" noise.
        print(str(e), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        # Ctrl-C is how `blindkeep node` is meant to be stopped. Exiting with a
        # traceback made a normal shutdown look like a crash.
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as e:
        if os.environ.get("BLINDKEEP_DEBUG"):
            raise
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
