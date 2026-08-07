"""Release-policy tests: what crosses to which model, and what proves it.

The assertion this module exists for is
`test_failed_attestation_demotes_and_withholds`: a backend that claims to be a
confidential enclave, cannot prove it, and therefore does not receive the
memories its claim would have unlocked.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blindkeep.memory_gate import (
    DEFAULT_POLICY,
    Grant,
    MemoryGate,
    PolicyRefusal,
    Release,
    Sensitivity,
    SimpleBackend,
    Tier,
    attestation_prover,
    decode_label,
    encode_label,
    loopback_prover,
    vault_prover,
)

TMP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_gate_tmp")


class StubClient:
    """Preserves the label through put/get, the way real encryption does."""

    def __init__(self):
        self.records = {}
        self.n = 0

    def put(self, plaintext, label=""):
        rid = f"rec{self.n}"
        self.n += 1
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        self.records[rid] = (label, plaintext)
        return {"record_id": rid, "index": len(self.records) - 1}

    def get_by_id(self, record_id, label=None):
        lbl, pt = self.records[record_id]
        return {"record_id": record_id, "label": lbl, "plaintext": pt}


class FakeVault:
    """Minimal duck-type of EntityVault, so this suite stays independent."""

    def __init__(self):
        self.map = {"Sarah": "<PERSON_0>"}

    def anonymize(self, text):
        out = text
        for k, v in self.map.items():
            out = out.replace(k, v)
        return type("A", (), {"text": out})()

    def restore(self, text):
        out = text
        for k, v in self.map.items():
            out = out.replace(v, k)
        return out


def fresh_gate(policy=None):
    path = os.path.join(TMP, f"index_{os.getpid()}_{id(object())}.json")
    if os.path.exists(path):
        os.remove(path)
    return MemoryGate(StubClient(), policy=policy, index_path=path)


def seeded_gate():
    g = fresh_gate()
    g.remember("the weather is nice", Sensitivity.PUBLIC)
    g.remember("Sarah is my landlord", Sensitivity.PERSONAL)
    g.remember("my diagnosis is X", Sensitivity.SENSITIVE)
    g.remember("my seed phrase is Y", Sensitivity.SECRET)
    return g


def backend(tier, prover=None, vault=None, completer=None):
    return SimpleBackend(
        name=f"test-{tier.label}", claimed_tier=tier,
        completer=completer or (lambda p, s: f"echo:{p}"),
        prover=prover, vault=vault)


def expect_refusal(fn, *, contains=None, exc=PolicyRefusal):
    try:
        fn()
    except exc as e:
        if contains:
            assert contains in str(e).lower(), f"wrong reason: {e}"
        return str(e)
    raise AssertionError("expected a refusal, got none")


# --- ordering and labels -----------------------------------------------------

def test_tiers_are_ordered_strongest_highest():
    assert Tier.LOCAL > Tier.ATTESTED > Tier.PSEUDONYMOUS > Tier.OPEN


def test_unknown_sensitivity_is_treated_as_the_most_secret():
    """A typo must cost recall, never exposure."""
    assert Sensitivity.parse("persnal") is Sensitivity.SECRET
    assert Sensitivity.parse("") is Sensitivity.SECRET


def test_unlabelled_records_are_not_public():
    sens, rest = decode_label("just-a-label")
    assert sens is Sensitivity.SECRET and rest == "just-a-label"


def test_label_round_trip():
    assert decode_label(encode_label(Sensitivity.PERSONAL, "chat")) == (
        Sensitivity.PERSONAL, "chat")


def test_default_policy_pins_secret_to_local():
    assert DEFAULT_POLICY[Sensitivity.SECRET] is Tier.LOCAL


# --- release by tier ---------------------------------------------------------

def test_open_backend_receives_only_public():
    rel = seeded_gate().release_for(backend(Tier.OPEN), n=10)
    assert rel.allowed == ["the weather is nice"]
    assert len(rel.withheld) == 3


def test_local_backend_receives_everything():
    prover = loopback_prover("http://127.0.0.1:11434")
    rel = seeded_gate().release_for(backend(Tier.LOCAL, prover), n=10)
    assert len(rel.allowed) == 4 and not rel.withheld


def test_attested_backend_receives_all_but_secret():
    grant = Grant(Tier.ATTESTED, Tier.ATTESTED, "test")
    rel = seeded_gate().release_for(
        backend(Tier.ATTESTED, lambda: grant), n=10)
    assert len(rel.allowed) == 3
    assert [s for _, s in rel.withheld] == [Sensitivity.SECRET]


def test_secret_never_leaves_even_for_a_proven_enclave():
    """The strongest remote proof still does not beat 'not on someone else's
    hardware'."""
    grant = Grant(Tier.ATTESTED, Tier.ATTESTED, "five checks passed")
    rel = seeded_gate().release_for(backend(Tier.ATTESTED, lambda: grant), n=10)
    assert "my seed phrase is Y" not in rel.allowed


def test_pseudonymous_backend_receives_substituted_text():
    vault = FakeVault()
    rel = seeded_gate().release_for(
        backend(Tier.PSEUDONYMOUS, vault_prover(vault), vault=vault), n=10)
    joined = " ".join(rel.allowed)
    assert "Sarah" not in joined and "<PERSON_0>" in joined
    assert len(rel.withheld) == 2, "sensitive and secret should be withheld"


# --- proof, and the absence of it --------------------------------------------

def test_failed_attestation_demotes_and_withholds():
    """The point of the module: an unprovable claim buys nothing.

    The backend says ATTESTED. Verification fails. It is treated as OPEN, so
    the memories its claim would have unlocked stay home.
    """
    gate = seeded_gate()
    unreachable = attestation_prover("http://127.0.0.1:1/attest", policy=None)
    rel = gate.release_for(backend(Tier.ATTESTED, unreachable), n=10)
    assert rel.grant.granted is Tier.OPEN
    assert rel.grant.demoted is True
    assert rel.allowed == ["the weather is nice"]
    assert len(rel.withheld) == 3


def test_demotion_is_loud_not_silent():
    unreachable = attestation_prover("http://127.0.0.1:1/attest", policy=None)
    rel = seeded_gate().release_for(backend(Tier.ATTESTED, unreachable), n=10)
    assert "DEMOTED" in rel.grant.summary()
    assert "attested" in rel.grant.summary() and "open" in rel.grant.summary()


def test_claim_without_a_prover_is_demoted():
    rel = seeded_gate().release_for(backend(Tier.LOCAL, prover=None), n=10)
    assert rel.grant.granted is Tier.OPEN
    assert "no prover" in rel.grant.reason


def test_non_loopback_endpoint_loses_local():
    rel = seeded_gate().release_for(
        backend(Tier.LOCAL, loopback_prover("http://192.168.1.50:11434")), n=10)
    assert rel.grant.granted is Tier.OPEN
    assert "loopback" in rel.grant.reason


def test_loopback_endpoint_keeps_local():
    rel = seeded_gate().release_for(
        backend(Tier.LOCAL, loopback_prover("http://localhost:11434")), n=10)
    assert rel.grant.granted is Tier.LOCAL


def test_pseudonymous_claim_without_a_vault_is_demoted():
    rel = seeded_gate().release_for(
        backend(Tier.PSEUDONYMOUS, vault_prover(None)), n=10)
    assert rel.grant.granted is Tier.OPEN


def test_a_raising_prover_demotes_rather_than_crashing():
    def boom():
        raise RuntimeError("hardware on fire")
    rel = seeded_gate().release_for(backend(Tier.ATTESTED, boom), n=10)
    assert rel.grant.granted is Tier.OPEN
    assert "hardware on fire" in rel.grant.detail


def test_open_backend_is_not_treated_as_demoted():
    rel = seeded_gate().release_for(backend(Tier.OPEN), n=10)
    assert rel.grant.demoted is False


# --- the classification is the ciphertext's, not the index's -----------------

def test_class_comes_from_the_decrypted_label_not_the_index_file():
    """The index is plaintext on disk. The authenticated label is the authority.

    Anything running as this user can edit the index; nothing can edit a label
    sealed inside an AEAD without the key.
    """
    gate = fresh_gate()
    gate.remember("my seed phrase", Sensitivity.SECRET)
    # Forge the on-disk index to claim the record is harmless.
    for entry in gate._index:
        entry["sensitivity"] = "public"
    gate._save_index()

    rel = gate.release_for(backend(Tier.OPEN), n=10)
    assert rel.allowed == [], "a forged index promoted a SECRET record"
    assert rel.withheld and rel.withheld[0][1] is Sensitivity.SECRET


def test_a_record_with_no_class_prefix_is_withheld():
    gate = fresh_gate()
    gate.client.put(b"legacy record", label="chat")     # stored outside the gate
    gate._index.append({"record_id": "rec0", "index": 0, "sensitivity": "public"})
    rel = gate.release_for(backend(Tier.OPEN), n=10)
    assert rel.allowed == [], "an unclassified record was released as public"


# --- strict mode and reporting ----------------------------------------------

def test_strict_mode_refuses_a_partial_release():
    expect_refusal(
        lambda: seeded_gate().release_for(backend(Tier.OPEN), n=10, strict=True),
        contains="not cleared for open")


def test_release_summary_names_what_was_withheld():
    rel = seeded_gate().release_for(backend(Tier.OPEN), n=10)
    s = rel.summary()
    assert "released 1" in s and "withheld 3" in s
    for expected in ("personal", "sensitive", "secret"):
        assert expected in s


def test_context_block_is_empty_when_nothing_cleared():
    gate = fresh_gate()
    gate.remember("secret thing", Sensitivity.SECRET)
    assert gate.release_for(backend(Tier.OPEN), n=10).context_block() == ""


def test_context_block_carries_released_memories():
    gate = fresh_gate()
    gate.remember("public thing", Sensitivity.PUBLIC)
    assert "public thing" in gate.release_for(
        backend(Tier.OPEN), n=10).context_block()


# --- chat across any backend -------------------------------------------------

def test_chat_works_against_any_backend_with_one_call_shape():
    seen = {}

    def completer(prompt, system):
        seen["system"] = system
        return "noted"

    gate = seeded_gate()
    out = gate.chat(backend(Tier.OPEN, completer=completer), "hello", recall=10)
    assert out["reply"] == "noted"
    assert out["tier"] == "open"
    assert "the weather is nice" in seen["system"]
    assert "my seed phrase is Y" not in seen["system"], "SECRET reached an open model"


def test_chat_pseudonymises_the_message_and_restores_the_reply():
    vault = FakeVault()
    seen = {}

    def completer(prompt, system):
        seen["prompt"] = prompt
        return f"I will contact {vault.map['Sarah']} today"

    gate = fresh_gate()
    gate.remember("Sarah is my landlord", Sensitivity.PERSONAL)
    out = gate.chat(
        backend(Tier.PSEUDONYMOUS, vault_prover(vault), vault=vault,
                completer=completer),
        "does Sarah owe rent?", recall=10)
    assert "Sarah" not in seen["prompt"], "the real name reached the model"
    assert "Sarah" in out["reply"], "the reply was not restored"


def test_chat_stores_both_turns_at_the_given_class():
    gate = fresh_gate()
    gate.chat(backend(Tier.OPEN), "hi", recall=0,
              sensitivity=Sensitivity.SENSITIVE)
    assert len(gate._index) == 2
    assert all(e["sensitivity"] == "sensitive" for e in gate._index)


def test_chat_can_decline_to_remember():
    gate = fresh_gate()
    gate.chat(backend(Tier.OPEN), "hi", recall=0, remember=False)
    assert gate._index == []


# --- isolation ---------------------------------------------------------------

def test_the_gate_itself_reaches_no_provider():
    """The gate must be handed a completer, never import one.

    That is what keeps the cloud path unreachable by default while the gate
    still routes to it.
    """
    import ast
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tree = ast.parse(
        open(os.path.join(root, "blindkeep", "memory_gate.py"),
             encoding="utf-8").read())
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""] + [a.name for a in node.names]
        for mod in names:
            for banned in ("cloud_gate", "vault_proxy"):
                assert banned not in mod, f"memory_gate imports {banned}"


def test_delegated_ranks_below_attested_and_above_pseudonymous():
    """Hardware enforces attestation; an abstraction is judged. The order says so."""
    assert Tier.ATTESTED > Tier.DELEGATED > Tier.PSEUDONYMOUS


def test_sensitive_now_requires_delegation_not_mere_substitution():
    """Substitution ships what it failed to detect. For SENSITIVE that is not good enough."""
    from blindkeep.memory_gate import DEFAULT_POLICY
    assert DEFAULT_POLICY[Sensitivity.SENSITIVE] is Tier.DELEGATED

    vault = FakeVault()
    rel = seeded_gate().release_for(
        backend(Tier.PSEUDONYMOUS, vault_prover(vault), vault=vault), n=10)
    assert any(s is Sensitivity.SENSITIVE for _, s in rel.withheld), (
        "a sensitive memory was released to a merely pseudonymous backend")


def test_a_delegated_backend_receives_sensitive_but_never_secret():
    from blindkeep.memory_gate import delegation_prover

    class Gate:
        def check(self, text):
            return None

    rel = seeded_gate().release_for(
        backend(Tier.DELEGATED, delegation_prover(Gate())), n=10)
    assert len(rel.allowed) == 3
    assert [s for _, s in rel.withheld] == [Sensitivity.SECRET]


def test_delegation_without_a_leak_gate_is_demoted():
    """Claiming to abstract is not abstracting."""
    from blindkeep.memory_gate import delegation_prover
    rel = seeded_gate().release_for(
        backend(Tier.DELEGATED, delegation_prover(None)), n=10)
    assert rel.grant.granted is Tier.OPEN
    assert "no leak gate" in rel.grant.reason


def run():
    os.makedirs(TMP, exist_ok=True)
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
    try:
        for f in os.listdir(TMP):
            os.remove(os.path.join(TMP, f))
        os.rmdir(TMP)
    except OSError:
        pass
    print(f"\n{len(passed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())
