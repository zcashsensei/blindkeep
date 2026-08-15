"""Pseudonymisation proxy tests.

Three kinds of assertion, and the third is the point:

* it substitutes and restores correctly,
* it refuses rather than half-protecting,
* it FAILS to protect things it cannot protect, asserted deliberately so the
  claim in the docs can never quietly outgrow the code.
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oblivio.cloud_gate import CloudGateError
from oblivio.vault_proxy import (
    EntityVault,
    LeakError,
    VaultError,
    private_cloud_complete,
)

SERVERS = []
RECEIVED = []


def echo_provider(reply=None):
    """A provider that echoes the prompt back, so restoration is observable."""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(n) or b"{}")
            RECEIVED.append(payload)
            content = reply if reply is not None else payload["messages"][-1]["content"]
            body = json.dumps(
                {"choices": [{"message": {"content": content}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    SERVERS.append(httpd)
    return f"http://127.0.0.1:{httpd.server_address[1]}"


class StubClient:
    """Stands in for OblivioClient's put/get_by_id contract."""

    def __init__(self):
        self.records = {}

    def put(self, plaintext, label=""):
        rid = f"rec{len(self.records)}"
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        self.records[rid] = (label, plaintext)
        return {"record_id": rid}

    def get_by_id(self, record_id, label=None):
        lbl, pt = self.records[record_id]
        return {"record_id": record_id, "label": lbl, "plaintext": pt}


# --- declaring ---------------------------------------------------------------

def test_declared_value_gets_a_stable_placeholder():
    v = EntityVault()
    a = v.declare("Sarah Whitfield")
    b = v.declare("Sarah Whitfield")
    assert a == b, "the same value produced two placeholders"
    assert "PERSON_0" in a and v.tag in a


def test_placeholders_are_tagged_per_vault():
    a, b = EntityVault(), EntityVault()
    assert a.declare("Acme Holdings", kind="ORG") != b.declare("Acme Holdings", kind="ORG"), (
        "two vaults produced identical placeholders; a foreign placeholder "
        "would be forgeable")


def test_short_values_are_refused():
    v = EntityVault()
    for bad in ("Jo", "X", ""):
        try:
            v.declare(bad)
        except VaultError:
            continue
        raise AssertionError(f"declared {bad!r}, which is too short to be safe")


def test_kinds_are_normalised():
    v = EntityVault()
    assert "MEDICAL_RECORD" in v.declare("Ridgeway file", kind="medical record")


# --- substitution ------------------------------------------------------------

def test_declared_values_are_replaced():
    v = EntityVault()
    v.declare("Sarah")
    v.declare("Acme", kind="ORG")
    out = v.anonymize("Sarah at Acme owes 4000").text
    assert "Sarah" not in out and "Acme" not in out
    assert "owes 4000" in out, "substitution damaged the surrounding text"


def test_matching_is_case_insensitive_and_boundary_aware():
    v = EntityVault()
    v.declare("Sarah")
    out = v.anonymize("SARAH and sarah's dog, but not Sarahsson").text
    assert "SARAH" not in out and "sarah's" not in out
    assert "Sarahsson" in out, "a boundary-less match ate an unrelated word"


def test_patterns_catch_structured_secrets():
    v = EntityVault()
    text = ("mail me@example.com from 10.0.0.7 with "
            "sk-abcdefghijklmnopqrstuvwxyz123456")
    out = v.anonymize(text).text
    for leaked in ("me@example.com", "10.0.0.7", "sk-abcdefghij"):
        assert leaked not in out, f"pattern missed {leaked}"


def test_narrow_phone_pattern_leaves_ordinary_numbers_alone():
    v = EntityVault()
    text = "version 1.2.3 cost 4000 on 2026-08-06"
    assert v.anonymize(text).text == text, "a loose pattern mangled prose"


def test_overlapping_detections_keep_the_longest_span():
    v = EntityVault()
    # The email sits inside the declared value; replacing the email first would
    # leave the rest of the declared string exposed.
    v.declare("contact me@example.com now", kind="CONTACT")
    out = v.anonymize("please contact me@example.com now, thanks").text
    assert "me@example.com" not in out
    assert out.count("<") == 1, f"nested or duplicated substitution: {out}"


def test_substitution_is_deterministic():
    v = EntityVault(tag="fixed1")
    v.declare("Sarah")
    text = "Sarah emailed Sarah about Sarah"
    assert v.anonymize(text).text == v.anonymize(text).text


# --- refusing rather than half-protecting ------------------------------------

def test_surviving_declared_value_raises_instead_of_sending():
    """The backstop must catch a detector regression, not just trust it.

    Simulates the realistic failure it exists for — a detector that stops
    finding a value the vault knows is sensitive — rather than corrupting the
    vault's internals, which would prove nothing about reachable behaviour.
    """
    class BlindVault(EntityVault):
        def _declared_spans(self, text):
            return []                      # a detector that finds nothing

    v = BlindVault()
    v.declare("Sarah")
    try:
        v.anonymize("Sarah owes money")
    except LeakError as exc:
        assert "Sarah" in str(exc)
        return
    raise AssertionError("a known value was allowed through substitution")


def test_the_leak_backstop_is_not_vacuous():
    """Guard against the guard: prove the check can actually fail.

    An invariant that no input can trip is green for its whole life and
    protects nothing. This asserts the opposite of the test above — that a
    working detector produces no leak — so the pair together show the check
    discriminates rather than always passing.
    """
    v = EntityVault()
    v.declare("Sarah")
    assert v._leaks("Sarah owes money") == {"Sarah"}, "check cannot detect"
    assert v._leaks(v.anonymize("Sarah owes money").text) == set(), (
        "check fires on correctly substituted text")


def test_foreign_placeholder_in_input_is_refused():
    v = EntityVault()
    v.declare("Sarah")
    forged = f"<PERSON_0_{v.tag}> is my landlord"
    try:
        v.anonymize(forged)
    except VaultError:
        return
    raise AssertionError(
        "input forged a placeholder; it would expand into a real name")


# --- restoring ---------------------------------------------------------------

def test_round_trip_restores_the_original():
    v = EntityVault()
    v.declare("Sarah")
    v.declare("Acme", kind="ORG")
    original = "Sarah at Acme owes 4000"
    assert v.restore(v.anonymize(original).text) == original


def test_restore_tolerates_model_reformatting():
    v = EntityVault()
    p = v.declare("Sarah")
    body = p[1:-1]
    for mangled in (body, f"[{body}]", f"({body})", body.lower(), f"**{p}**"):
        assert "Sarah" in v.restore(f"I think {mangled} should be invoiced"), (
            f"restore failed on {mangled!r}")


def test_restore_does_not_confuse_index_1_with_index_10():
    v = EntityVault()
    for i in range(11):
        v.declare(f"Person Number {i}")
    p1 = v._by_value["person number 1"].placeholder
    p10 = v._by_value["person number 10"].placeholder
    assert v.restore(p10) == "Person Number 10", "index 1 ate the prefix of 10"
    assert v.restore(p1) == "Person Number 1"


# --- persistence -------------------------------------------------------------

def test_vault_survives_a_json_round_trip():
    v = EntityVault()
    v.declare("Sarah")
    v.declare("Acme", kind="ORG")
    back = EntityVault.from_json(v.to_json())
    assert back.tag == v.tag
    assert back.restore(back.anonymize("Sarah at Acme").text) == "Sarah at Acme"


def test_vault_persists_through_the_client():
    client = StubClient()
    v = EntityVault()
    v.declare("Sarah")
    ref = v.save(client)
    back = EntityVault.load(client, ref["record_id"])
    assert back.restore(back.anonymize("Sarah called").text) == "Sarah called"


def test_stored_vault_is_handed_to_the_client_not_written_alongside():
    """The mapping must go through the encrypted path, not to a loose file."""
    client = StubClient()
    EntityVault().save(client)
    assert client.records, "vault was not stored through the client"


def test_unsupported_vault_version_is_refused():
    try:
        EntityVault.from_json(json.dumps({"version": 99, "stable": True,
                                          "tag": "x", "counters": {},
                                          "mappings": []}))
    except VaultError:
        return
    raise AssertionError("a future vault format was loaded blindly")


# --- the proxied call --------------------------------------------------------

def test_provider_never_sees_the_real_value():
    RECEIVED.clear()
    base = echo_provider()
    v = EntityVault()
    v.declare("Sarah")
    out = private_cloud_complete(
        "what should Sarah do?", vault=v, api_base=base, api_key="k",
        model="m", enable_cloud=True, accept_not_private=True)
    wire = json.dumps(RECEIVED[-1])
    assert "Sarah" not in wire, "the real name reached the provider"
    assert out["reply"] == "what should Sarah do?", "reply was not restored"
    assert out["pseudonymized"] is True and out["private"] is False


def test_system_prompt_is_also_anonymised():
    RECEIVED.clear()
    base = echo_provider()
    v = EntityVault()
    v.declare("Sarah")
    private_cloud_complete("hello", vault=v, api_base=base, api_key="k",
                           model="m", system="You assist Sarah.",
                           enable_cloud=True, accept_not_private=True)
    assert "Sarah" not in json.dumps(RECEIVED[-1]), "system prompt leaked a name"


def test_gate_is_not_softened_by_pseudonymisation():
    RECEIVED.clear()
    base = echo_provider()
    v = EntityVault()
    try:
        private_cloud_complete("hi", vault=v, api_base=base, api_key="k",
                               model="m")
    except CloudGateError:
        assert not RECEIVED, "a request was sent despite the gate refusing"
        return
    raise AssertionError("the proxy bypassed the cloud opt-in")


def test_no_stored_memories_are_attached():
    RECEIVED.clear()
    base = echo_provider()
    v = EntityVault()
    private_cloud_complete("just this", vault=v, api_base=base, api_key="k",
                           model="m", enable_cloud=True,
                           accept_not_private=True)
    assert len(RECEIVED[-1]["messages"]) == 1, "extra context was attached"


def test_caller_can_see_exactly_what_left():
    RECEIVED.clear()
    base = echo_provider()
    v = EntityVault()
    v.declare("Sarah")
    out = private_cloud_complete("Sarah is late", vault=v, api_base=base,
                                 api_key="k", model="m", enable_cloud=True,
                                 accept_not_private=True)
    assert out["sent"] == RECEIVED[-1]["messages"][-1]["content"]
    assert "Sarah" not in out["sent"]


# --- asserted LIMITATIONS ----------------------------------------------------
# These tests pass by demonstrating failure. If one starts failing, the module
# got stronger and the documented claim must be updated to match.

def test_undeclared_names_are_transmitted_verbatim():
    """Deterministic detection cannot do NER. `declare()` is load-bearing."""
    v = EntityVault()
    text = "Beatrice Ngo runs the Camden branch"
    assert v.anonymize(text).text == text, (
        "detection improved beyond patterns + declarations — update the docs, "
        "which currently say undeclared prose entities are sent as written")


def test_quasi_identifiers_survive_and_still_identify():
    """The honest ceiling: removing the name does not remove the person."""
    v = EntityVault()
    v.declare("Sarah")
    out = v.anonymize(
        "Sarah is the only paediatric cardiologist in Truro who breeds "
        "Basenjis").text
    assert "Sarah" not in out
    assert "paediatric cardiologist in Truro" in out, (
        "this test asserts the LIMITATION: substitution removes identifiers, "
        "not identifiability")


def test_residual_risk_is_reported_not_hidden():
    v = EntityVault()
    v.declare("Sarah")
    anon = v.anonymize("Sarah lives alone above the pharmacy")
    assert "identifiability" in anon.unprotected_hint


def test_stable_placeholders_are_linkable_across_calls():
    """A persistent pseudonym is still a persistent identifier."""
    v = EntityVault()
    v.declare("Sarah")
    first = v.anonymize("Sarah called").text
    second = v.anonymize("Sarah emailed").text
    shared = first.split()[0]
    assert shared in second, "placeholders are not stable"
    # Asserted deliberately: the provider can link these two requests.


# --- isolation ---------------------------------------------------------------

def test_no_default_module_imports_the_proxy():
    """Same guarantee cloud_gate has: the cloud path stays unreachable by default.

    Enumerates the package rather than listing filenames, so a module added
    later is covered without anyone remembering to add it here.
    """
    import ast

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pkg = os.path.join(root, "oblivio")
    # The frontier modules ARE cloud paths, same as vault_proxy: reachable only through
    # `frontier` CLI commands that import them lazily, so importing one is choosing it.
    # See the matching note in test_cloud_gate.py -- reachability is proved by importing
    # the package in a clean interpreter, not by this list.
    cloud_path_modules = {"vault_proxy.py", "cloud_gate.py", "cli.py",
                          "progress.py", "frontier_gateway.py",
                          "frontier_private.py"}
    guarded = ("vault_proxy", "cloud_gate")

    for name in sorted(os.listdir(pkg)):
        if not name.endswith(".py") or name in cloud_path_modules:
            continue
        tree = ast.parse(open(os.path.join(pkg, name), encoding="utf-8").read(),
                         filename=name)
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""] + [a.name for a in node.names]
            for mod in names:
                for g in guarded:
                    assert g not in mod, f"{name} imports {g}"


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
    print(f"\n{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())
