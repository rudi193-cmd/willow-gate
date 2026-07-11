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
