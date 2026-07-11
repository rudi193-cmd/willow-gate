"""custody ledger Tier 1 tests — each maps to a gate in docs/custody-ledger-spec.md.

Deterministic, no model, no network. Every test names the spec gate it proves.
"""
import json

import pytest

from willow_gate.custody import (
    CustodyLedger, SecretRefused, GENESIS,
    canonicalize, event_hash, looks_like_secret,
    KIND_SESSION_ACTION, KIND_FILE_GATE_CROSS,
)


def _ledger_with_three():
    led = CustodyLedger()
    led.append({"kind": KIND_SESSION_ACTION, "actor": "willow", "tool": "read"}, ts="2026-07-11T00:00:00Z")
    led.append({"kind": KIND_SESSION_ACTION, "actor": "willow", "tool": "write"}, ts="2026-07-11T00:00:01Z")
    led.append({"kind": KIND_SESSION_ACTION, "actor": "willow", "tool": "grep"}, ts="2026-07-11T00:00:02Z")
    return led


# GATE: end-to-end chain verification passes.
def test_hash_chain_verifies_end_to_end():
    led = _ledger_with_three()
    assert led.verify().ok
    assert len(led) == 3
    evs = led.events()
    assert [e["seq"] for e in evs] == [0, 1, 2]
    assert evs[0]["ledger_prev_hash"] == GENESIS
    assert evs[1]["ledger_prev_hash"] == event_hash(evs[0])
    assert evs[2]["ledger_prev_hash"] == event_hash(evs[1])


# GATE: tampering any past entry fails verification.
def test_tamper_breaks_chain():
    led = _ledger_with_three()
    assert led.verify().ok
    # Alter a *past* event in place (seq 1); everything after should fail.
    led._events[1]["tool"] = "exfiltrate"
    res = led.verify()
    assert not res.ok
    assert res.at_seq == 2          # the first event whose prev_hash no longer matches
    assert "chain" in res.reason


# GATE: canonical form is byte-stable — key order cannot change a hash.
def test_canonical_form_is_byte_stable():
    a = {"kind": "x", "actor": "willow", "tool": "read", "note": None}
    b = {"note": None, "tool": "read", "actor": "willow", "kind": "x"}  # reordered + null
    assert canonicalize(a) == canonicalize(b)
    assert event_hash(a) == event_hash(b)
    # null policy: an omitted key and an explicit null are identical
    c = {"kind": "x", "actor": "willow", "tool": "read"}
    assert canonicalize(a) == canonicalize(c)
    # the signature field is excluded from the canonical bytes
    signed = dict(a, sig="deadbeef")
    assert canonicalize(signed) == canonicalize(a)


# GATE: a token-bearing event is refused and nothing is written.
def test_redaction_fail_closed():
    led = _ledger_with_three()
    before = len(led)
    head_before = led.head_hash
    poisoned = {
        "kind": KIND_FILE_GATE_CROSS,
        "gate": {"name": "github", "auth_ref": "ghp_" + "a" * 36},  # live-looking PAT
    }
    with pytest.raises(SecretRefused):
        led.append(poisoned)
    # nothing changed: no event stored, head unmoved, chain still valid
    assert len(led) == before
    assert led.head_hash == head_before
    assert led.verify().ok


def test_secret_detector_does_not_flag_content_hashes():
    # A 64-char sha256 hex must NOT be mistaken for a secret, or the ledger
    # would refuse its own chain fields.
    assert not looks_like_secret("a" * 64)
    assert not looks_like_secret(event_hash({"kind": "x"}))
    led = CustodyLedger()
    led.append({"kind": "file.write", "content_hash": event_hash({"kind": "x"})})
    assert led.verify().ok


# GATE: no in-place edit API — append is the only write.
def test_append_only_no_mutation_api():
    led = CustodyLedger()
    for bad in ("update", "delete", "edit", "remove", "set", "__setitem__", "pop"):
        assert not hasattr(led, bad), f"append-only ledger must not expose {bad!r}"
    # reserved fields cannot be supplied by a caller
    with pytest.raises(ValueError):
        led.append({"kind": "x", "seq": 99})
    with pytest.raises(ValueError):
        led.append({"kind": "x", "ledger_prev_hash": "beef"})
    with pytest.raises(ValueError):
        led.append({"actor": "willow"})  # missing kind


# GATE: persistence round-trips and re-verifies after reopen.
def test_persist_and_reload_verifies(tmp_path):
    p = tmp_path / "custody.jsonl"
    led = CustodyLedger(path=str(p))
    led.append({"kind": KIND_SESSION_ACTION, "actor": "willow", "tool": "read"}, ts="2026-07-11T00:00:00Z")
    led.append({"kind": KIND_SESSION_ACTION, "actor": "willow", "tool": "write"}, ts="2026-07-11T00:00:01Z")
    # file is append-only JSONL, one event per line
    lines = [l for l in p.read_text().splitlines() if l.strip()]
    assert len(lines) == 2
    assert json.loads(lines[0])["seq"] == 0
    # reload and verify the chain survives a round trip
    reloaded = CustodyLedger.load(str(p))
    assert len(reloaded) == 2
    assert reloaded.verify().ok
    assert reloaded.head_hash == led.head_hash


# ============================================================================
# Tier 2 — the session layer (H5 check-out reconciliation)
# ============================================================================
from willow_gate.custody import (  # noqa: E402
    Reconciliation, ChainError as _ChainError,
    session_check_in, session_record_action, session_check_out,
    KIND_SESSION_CHECKOUT,
)


# GATE (H5): declare tools:[read], then write — check-out must catch it.
def test_checkout_catches_declared_read_then_wrote():
    led = CustodyLedger()
    session_check_in(led, "s1", "willow", {"tools": ["read"], "trust_level": 1})
    session_record_action(led, "s1", "willow", "read")
    session_record_action(led, "s1", "willow", "write")   # undeclared
    recon = session_check_out(led, "s1")

    assert recon.reconciled is False
    assert recon.mismatches == ["write"]
    assert recon.fail_count_delta == 1
    # the mismatch is a durable ledger entry, and the chain still verifies
    checkout = led.events()[-1]
    assert checkout["kind"] == KIND_SESSION_CHECKOUT
    assert checkout["reconciled"] is False
    assert checkout["mismatches"] == ["write"]
    assert led.verify().ok


def test_checkout_clean_when_within_declared():
    led = CustodyLedger()
    session_check_in(led, "s1", "willow", {"tools": ["read", "write"]})
    session_record_action(led, "s1", "willow", "read")
    session_record_action(led, "s1", "willow", "write")
    recon = session_check_out(led, "s1")
    assert recon.reconciled is True
    assert recon.mismatches == []
    assert recon.fail_count_delta == 0
    assert bool(recon) is True


# GATE: the delta feeds the trust ladder's fail_count (ladder stays the owner).
def test_checkout_feeds_trust_ladder_fail_count():
    led = CustodyLedger()
    session_check_in(led, "s1", "willow", {"tools": ["read"]})
    session_record_action(led, "s1", "willow", "write")
    session_record_action(led, "s1", "willow", "execute")
    recon = session_check_out(led, "s1")
    assert recon.fail_count_delta == 2                 # write + execute undeclared
    assert recon.exit_fail_count(3) == 5               # entry 3 -> exit 5


def test_checkout_requires_a_checkin():
    led = CustodyLedger()
    session_record_action(led, "ghost", "willow", "write")
    with pytest.raises(_ChainError):
        session_check_out(led, "ghost")


def test_sessions_are_reconciled_independently():
    led = CustodyLedger()
    session_check_in(led, "a", "willow", {"tools": ["read"]})
    session_check_in(led, "b", "hanuman", {"tools": ["read", "write"]})
    session_record_action(led, "a", "willow", "write")     # a: undeclared
    session_record_action(led, "b", "hanuman", "write")    # b: declared
    ra = session_check_out(led, "a")
    rb = session_check_out(led, "b")
    assert ra.reconciled is False and ra.mismatches == ["write"]
    assert rb.reconciled is True and rb.mismatches == []


def test_declared_accepts_header_list_or_string():
    from willow_gate.custody import _declared_tools
    assert _declared_tools({"tools": ["read", "write"]}) == ["read", "write"]
    assert _declared_tools({"tools": "read, write"}) == ["read", "write"]
    assert _declared_tools(["write", "read", "read"]) == ["read", "write"]
    assert _declared_tools(None) == []


# ============================================================================
# Tier 3 — file custody (lineage, diffs, capture-gap detection)
# ============================================================================
import hashlib  # noqa: E402
from willow_gate.custody import (  # noqa: E402
    file_create, file_read, file_write, file_gate_cross, file_checkout,
    file_lineage, verify_lineage, detect_capture_gap, lineage_has_gaps,
    last_content_hash, KIND_CAPTURE_GAP, KIND_FILE_WRITE, KIND_FILE_CREATE,
)


def ch(s):  # a realistic content hash
    return hashlib.sha256(s.encode()).hexdigest()


# GATE: a file's full lineage is queryable start to finish, chain intact.
def test_file_lineage_queryable_and_chained():
    led = CustodyLedger()
    file_create(led, "notes.md", "willow", ch("v1"), path="notes.md")
    file_write(led, "notes.md", "willow", ch("v2"), diff_stat={"files": 1, "insertions": 3, "deletions": 0})
    file_write(led, "notes.md", "willow", ch("v3"))
    lin = file_lineage(led, "notes.md")
    assert [e["kind"] for e in lin] == [KIND_FILE_CREATE, KIND_FILE_WRITE, KIND_FILE_WRITE]
    # each version links to its parent by content hash
    assert lin[1]["parent_content_hash"] == ch("v1")
    assert lin[2]["parent_content_hash"] == ch("v2")
    assert lin[1]["diff_stat"] == {"files": 1, "insertions": 3, "deletions": 0}
    assert verify_lineage(led, "notes.md").ok
    assert led.verify().ok
    assert not lineage_has_gaps(led, "notes.md")


def test_file_write_autochains_to_last_hash():
    led = CustodyLedger()
    file_create(led, "f", "willow", ch("v1"))
    ev = file_write(led, "f", "willow", ch("v2"))          # no explicit parent
    assert ev["parent_content_hash"] == ch("v1")
    assert last_content_hash(led, "f") == ch("v2")


# GATE: an out-of-band edit shows as a capture_gap.
def test_out_of_band_edit_shows_as_capture_gap():
    led = CustodyLedger()
    file_create(led, "f", "willow", ch("v1"))
    file_write(led, "f", "willow", ch("v2"))
    # someone edits the file with no write event; we observe a new hash
    gap = detect_capture_gap(led, "f", ch("v_external"))
    assert gap is not None
    assert gap["kind"] == KIND_CAPTURE_GAP
    assert gap["expected_content_hash"] == ch("v2")
    assert gap["observed_content_hash"] == ch("v_external")
    assert led.events()[-1]["kind"] == KIND_CAPTURE_GAP    # durable
    assert lineage_has_gaps(led, "f")
    assert led.verify().ok                                 # the gap is a legit entry
    # idempotent: re-observing the same hash does not re-flag
    assert detect_capture_gap(led, "f", ch("v_external")) is None
    # and a legitimate write chains from the acknowledged break
    ev = file_write(led, "f", "willow", ch("v_next"))
    assert ev["parent_content_hash"] == ch("v_external")
    assert verify_lineage(led, "f").ok


def test_capture_gap_none_when_consistent():
    led = CustodyLedger()
    file_create(led, "f", "willow", ch("v1"))
    file_write(led, "f", "willow", ch("v2"))
    before = len(led)
    assert detect_capture_gap(led, "f", ch("v2")) is None   # matches last recorded
    assert len(led) == before                               # nothing written


def test_lineages_are_independent():
    led = CustodyLedger()
    file_create(led, "a", "willow", ch("a1"))
    file_create(led, "b", "hanuman", ch("b1"))
    file_write(led, "a", "willow", ch("a2"))
    assert last_content_hash(led, "a") == ch("a2")
    assert last_content_hash(led, "b") == ch("b1")
    assert [e["kind"] for e in file_lineage(led, "b")] == [KIND_FILE_CREATE]


# GATE: a gate crossing carrying a live secret is refused (fail-closed).
def test_file_gate_cross_redacts_live_secret():
    led = CustodyLedger()
    file_create(led, "f", "willow", ch("v1"))
    with pytest.raises(SecretRefused):
        file_gate_cross(led, "f", "willow",
                        {"name": "github", "auth_ref": "github_pat_" + "b" * 30})
    # a crossing recorded under a credential *id* is fine
    ev = file_gate_cross(led, "f", "willow",
                         {"name": "jeles", "auth_ref": "cred-7", "direction": "in"},
                         content_hash=ch("received"))
    assert ev["gate"]["auth_ref"] == "cred-7"
    assert led.verify().ok
