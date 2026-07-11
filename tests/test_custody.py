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


# ============================================================================
# Hardening regression tests — one per confirmed audit finding
# ============================================================================
import unicodedata  # noqa: E402
from willow_gate.custody import (  # noqa: E402
    file_create, file_write, file_gate_cross, verify_lineage,
    KIND_SESSION_ACTION as _SA, event_hash as _eh, canonicalize as _canon,
)


def _ch(s):
    return hashlib.sha256(s.encode()).hexdigest()


# HARDEN-1: H5 evasion via the file/gate path and untyped actions is now caught.
def test_h5_folds_file_write_carrying_session_id():
    led = CustodyLedger()
    session_check_in(led, "s1", "willow", {"tools": ["read"]})
    file_write(led, "f", "willow", _ch("v1"), session_id="s1")   # a write, not via session_record_action
    recon = session_check_out(led, "s1")
    assert recon.reconciled is False and "write" in recon.mismatches


def test_h5_folds_gate_cross_egress():
    led = CustodyLedger()
    session_check_in(led, "s1", "willow", {"tools": ["read"]})
    file_gate_cross(led, "f", "willow", {"name": "jeles", "auth_ref": "cred-7"}, session_id="s1")
    recon = session_check_out(led, "s1")
    assert recon.reconciled is False and "egress" in recon.mismatches


def test_h5_flags_untyped_action():
    led = CustodyLedger()
    session_check_in(led, "s1", "willow", {"tools": ["read"]})
    led.append({"kind": _SA, "session_id": "s1", "actor": "willow", "note": "did a thing"})
    recon = session_check_out(led, "s1")
    assert recon.reconciled is False and "action" in recon.mismatches


def test_h5_is_case_insensitive():
    led = CustodyLedger()
    session_check_in(led, "s1", "willow", {"tools": ["Read", "WRITE"]})
    session_record_action(led, "s1", "willow", "read")
    session_record_action(led, "s1", "willow", "Write")
    assert session_check_out(led, "s1").reconciled is True   # case cannot evade or false-flag


# HARDEN-2: redaction covers plaintext field-name secrets and secret keys.
def test_redaction_refuses_plaintext_field_secrets():
    led = CustodyLedger()
    for bad in ({"password": "hunter2"}, {"api_key": "letmein"}, {"client_secret": "x"}):
        with pytest.raises(SecretRefused):
            led.append(dict(bad, kind=_SA, actor="x"))
    assert len(led) == 0   # nothing written


def test_redaction_refuses_secret_as_dict_key():
    led = CustodyLedger()
    with pytest.raises(SecretRefused):
        led.append({"kind": _SA, "actor": "x", "meta": {"ghp_" + "a" * 36: "v"}})


def test_redaction_allows_credential_ids_and_hashes():
    led = CustodyLedger()
    led.append({"kind": KIND_FILE_GATE_CROSS, "actor": "x", "lineage_id": "f",
                "gate": {"auth_ref": "cred-7"}, "content_hash": _ch("v"),
                "private_key_id": "pk-1"})       # ids/refs/hashes are not secrets
    assert led.verify().ok


# HARDEN-3: canonicalization is sound and portable.
def test_canon_portable_ascii_nfc_and_fixed_point():
    ev = {"kind": _SA, "actor": "wíllow", "tool": "café", "note": None}
    b = _canon(ev)
    assert all(byte < 128 for byte in b)     # pure ASCII -> serializer-portable
    assert b == b'{"actor":"w\\u00edllow","kind":"session.action","tool":"caf\\u00e9"}'
    assert _canon(json.loads(b.decode())) == b               # fixed point
    # NFC: combining form collapses to the precomposed form
    assert _canon({"kind": _SA, "tool": "café"}) == _canon({"kind": _SA, "tool": "café"})


def test_canon_rejects_non_string_keys_and_floats():
    for bad in ({"kind": _SA, "m": {1: "a"}}, {"kind": _SA, "m": {True: "a"}},
                {"kind": _SA, "n": 1.5}, {"kind": _SA, "n": float("nan")}):
        with pytest.raises(ValueError):
            _canon(bad)
    # and via append() it fails closed (nothing written)
    led = CustodyLedger()
    with pytest.raises(ValueError):
        led.append({"kind": _SA, "n": 2.5})
    assert len(led) == 0


# HARDEN-4: load() fails closed on a tampered or corrupt file.
def test_load_fails_closed_on_tamper(tmp_path):
    p = tmp_path / "c.jsonl"
    led = CustodyLedger(path=str(p))
    for t in ("read", "write", "grep"):
        session_record_action(led, "s", "willow", t, ts="2026-07-11T00:00:00Z")
    lines = p.read_text().splitlines()
    row = json.loads(lines[1]); row["tool"] = "exfiltrate"        # tamper, do NOT re-derive
    lines[1] = json.dumps(row)
    p.write_text("\n".join(lines) + "\n")
    with pytest.raises(_ChainError):
        CustodyLedger.load(str(p))


def test_load_fails_closed_on_corrupt_line(tmp_path):
    p = tmp_path / "c.jsonl"
    p.write_text('{"kind":"session.action","actor":"x","seq":0,"ledger_prev_hash":"' + ("0" * 64) + '"}\n{ broken json\n')
    with pytest.raises(_ChainError):
        CustodyLedger.load(str(p))


# HARDEN-5 / R3-2: reconciled once — a re-check_out recomputes the truth without a
# duplicate emit and flags already_closed; it does NOT raise (so a forged checkout
# can't weaponize a raise into denial).
def test_double_checkout_is_idempotent_not_raising():
    led = CustodyLedger()
    session_check_in(led, "s1", "willow", {"tools": ["read"]})
    session_record_action(led, "s1", "willow", "write")
    r1 = session_check_out(led, "s1")
    assert r1.already_closed is False and r1.mismatches == ["write"]
    n = len(led)
    r2 = session_check_out(led, "s1")            # no raise
    assert r2.already_closed is True
    assert r2.mismatches == ["write"] and r2.reconciled is False
    assert len(led) == n                          # no duplicate session.checkout


# HARDEN-6: a write-first (un-provenanced) lineage does not verify.
def test_write_first_lineage_has_no_origin():
    led = CustodyLedger()
    file_write(led, "f", "willow", _ch("v1"))     # no file_create first
    res = verify_lineage(led, "f")
    assert not res.ok and "origin" in res.reason


# HARDEN-7: kind and ts are validated.
def test_unknown_kind_and_bad_ts_refused():
    led = CustodyLedger()
    with pytest.raises(ValueError):
        led.append({"kind": "bogus", "actor": "x"})
    with pytest.raises(ValueError):                       # naive (no tz)
        led.append({"kind": _SA, "actor": "x"}, ts="2026-07-11T00:00:00")
    with pytest.raises(ValueError):                       # garbage
        led.append({"kind": _SA, "actor": "x", "ts": "not-a-time"})
    led.append({"kind": _SA, "actor": "x"}, ts="2026-07-11T00:00:00+00:00")   # good
    assert led.verify().ok


# HARDEN-8: documented limits — Tier 1 CANNOT catch these without the Tier-4 sig.
def test_rederivation_forgery_passes_tier1_verify_documented_limit():
    led = CustodyLedger()
    for t in ("read", "write", "grep"):
        session_record_action(led, "s", "willow", t)
    # tamper a middle event AND re-derive every subsequent prev_hash
    led._events[1]["tool"] = "exfiltrate"
    for i in range(2, len(led._events)):
        led._events[i]["ledger_prev_hash"] = _eh(led._events[i - 1])
    assert led.verify().ok is True          # KNOWN LIMIT: only Tier-4 head-pinning catches this


def test_tail_truncation_passes_tier1_verify_documented_limit():
    led = CustodyLedger()
    for t in ("read", "write", "grep"):
        session_record_action(led, "s", "willow", t)
    led._events.pop()                       # drop the tail
    assert led.verify().ok is True          # KNOWN LIMIT: nothing pins the head at Tier 1


# ============================================================================
# Round-2 hardening — the re-audit findings (bypasses + new bugs)
# ============================================================================
from willow_gate.custody import file_checkout as _file_checkout  # noqa: E402


def _write_valid_chain(path, events):
    """Hand-build a self-consistent chain file (bypassing append's gates) to
    simulate an attacker's crafted file."""
    prev = GENESIS
    lines = []
    for i, e in enumerate(events):
        ev = dict(e); ev["seq"] = i; ev["ledger_prev_hash"] = prev
        prev = event_hash(ev)
        lines.append(json.dumps(ev))
    path.write_text("\n".join(lines) + "\n")


# R2-1: system-only kinds cannot be appended by a caller (closes the forge).
def test_system_only_kinds_refused_from_caller():
    led = CustodyLedger()
    for k in ("session.checkout", "capture_gap"):
        with pytest.raises(ValueError):
            led.append({"kind": k, "session_id": "s1", "actor": "x"})
    assert len(led) == 0


def test_forged_checkout_cannot_deny_reconciliation():
    led = CustodyLedger()
    session_check_in(led, "s1", "willow", {"tools": ["read"]})
    session_record_action(led, "s1", "willow", "write")
    with pytest.raises(ValueError):                      # forge blocked at the door
        led.append({"kind": "session.checkout", "session_id": "s1", "reconciled": True})
    recon = session_check_out(led, "s1")                 # real reconciliation still runs
    assert recon.reconciled is False and "write" in recon.mismatches


# R2-1: a reused session_id checks out again (no permanent lock-out).
def test_session_id_reuse_reconciles_new_window():
    led = CustodyLedger()
    session_check_in(led, "s1", "willow", {"tools": ["read"]})
    session_record_action(led, "s1", "willow", "read")
    assert session_check_out(led, "s1").reconciled is True
    # reuse the same id with a fresh check-in
    session_check_in(led, "s1", "willow", {"tools": ["read"]})
    session_record_action(led, "s1", "willow", "write")
    r = session_check_out(led, "s1")
    assert r.reconciled is False and r.mismatches == ["write"]


# R2-2: load() re-runs ALL fail-closed gates, not just the chain.
def test_load_rejects_smuggled_secret_kind_and_ts(tmp_path):
    for events in (
        [{"kind": "session.action", "actor": "x", "password": "hunter2"}],   # secret
        [{"kind": "TOTALLY_BOGUS", "actor": "x"}],                            # illegal kind
        [{"kind": "session.action", "actor": "x", "ts": "not-a-time"}],       # bad ts
        [{"kind": "session.action", "actor": "x", "ts": 12345}],              # non-string ts
    ):
        p = tmp_path / "c.jsonl"
        _write_valid_chain(p, events)
        with pytest.raises(_ChainError):
            CustodyLedger.load(str(p))


# R2-3: wrapped-value secrets, field-name set fixes.
def test_redaction_wrapped_value_secrets():
    led = CustodyLedger()
    for bad in ({"password": ["hunter2"]}, {"password": {"v": "hunter2"}}, {"api_key": ["letmein"]}):
        with pytest.raises(SecretRefused):
            led.append(dict(bad, kind="session.action", actor="x"))
    assert len(led) == 0


def test_redaction_no_false_positive_on_credential_ids():
    led = CustodyLedger()
    led.append({"kind": "session.action", "actor": "x", "credentials": "cred-7"})
    led.append({"kind": "session.action", "actor": "x", "credential": "id-9"})
    led.append({"kind": "session.action", "actor": "x", "token_id": "tok-1", "secret_ref": "s-1"})
    assert led.verify().ok and len(led) == 3


def test_redaction_high_signal_credential_field_names():
    # High-signal names AND any *_token (R4-2 restored the suffix) are refused...
    led = CustodyLedger()
    for bad in ({"bearer": "abc"}, {"session_token": "abc"}, {"access_token": "abc"},
                {"x_token": "abc"}):
        with pytest.raises(SecretRefused):
            led.append(dict(bad, kind="session.action", actor="x"))
    # ...while the bare `token`/`cookie` names remain non-triggers (too ambiguous).
    led.append({"kind": "session.action", "actor": "x", "token": "issue-1"})
    led.append({"kind": "session.action", "actor": "x", "cookie": "theme=dark"})
    assert led.verify().ok


# R2-4 / R3-3: file.checkout folds into H5 as its OWN capability (not egress).
def test_file_checkout_folds_into_h5():
    led = CustodyLedger()
    session_check_in(led, "s1", "willow", {"tools": ["read"]})
    _file_checkout(led, "f", "willow", session_id="s1")
    recon = session_check_out(led, "s1")
    assert recon.reconciled is False and "checkout" in recon.mismatches


def test_persist_is_ascii_and_reloads(tmp_path):
    p = tmp_path / "c.jsonl"
    led = CustodyLedger(path=str(p))
    led.append({"kind": "session.action", "actor": "willow", "tool": "café"}, ts="2026-07-11T00:00:00Z")
    raw = p.read_bytes()
    assert all(b < 128 for b in raw)                     # file uses the ASCII canonical policy
    assert CustodyLedger.load(str(p)).verify().ok


def test_declared_non_iterable_fails_closed():
    led = CustodyLedger()
    session_check_in(led, "s1", "willow", 5)             # malformed declared header
    with pytest.raises(ValueError):
        session_check_out(led, "s1")


def test_sig_must_be_a_string():
    led = CustodyLedger()
    with pytest.raises(ValueError):
        led.append({"kind": "session.action", "actor": "x", "sig": 123})
    led.append({"kind": "session.action", "actor": "x", "sig": "deadbeef"})   # ok
    assert led.verify().ok


# ============================================================================
# Round-3 hardening — pass-3 findings
# ============================================================================

# R3-1: a second check-in inside an OPEN window cannot wipe an undeclared capability.
def test_double_checkin_cannot_erase_evidence():
    led = CustodyLedger()
    session_check_in(led, "s1", "willow", {"tools": ["read"]})
    session_record_action(led, "s1", "willow", "write")     # undeclared
    session_check_in(led, "s1", "willow", {"tools": ["read", "write"]})  # 2nd checkin, no checkout
    r = session_check_out(led, "s1")
    assert r.reconciled is False and r.mismatches == ["write"]   # neither wiped nor re-broadened


# R3-1: a reused session_id (check-in AFTER a checkout) still opens a fresh window.
def test_reuse_after_checkout_still_opens_new_window():
    led = CustodyLedger()
    session_check_in(led, "s1", "willow", {"tools": ["read"]})
    session_record_action(led, "s1", "willow", "read")
    assert session_check_out(led, "s1").reconciled is True
    session_check_in(led, "s1", "willow", {"tools": ["read"]})
    session_record_action(led, "s1", "willow", "write")
    r = session_check_out(led, "s1")
    assert r.reconciled is False and r.mismatches == ["write"] and r.already_closed is False


# R3-2: a forged session.checkout in a LOADED file can neither deny nor mask.
def test_forged_checkout_in_loaded_file_cannot_deny_or_mask(tmp_path):
    p = tmp_path / "c.jsonl"
    _write_valid_chain(p, [
        {"kind": "session.checkin", "session_id": "s1", "actor": "w", "declared": {"tools": ["read"]}},
        {"kind": "session.checkout", "session_id": "s1", "actor": "w", "reconciled": True, "mismatches": []},
    ])
    led = CustodyLedger.load(str(p))                      # loads (self-consistent chain)
    led.append({"kind": "session.action", "session_id": "s1", "actor": "w", "tool": "write"})
    r = session_check_out(led, "s1")                      # no raise
    assert r.reconciled is False and r.mismatches == ["write"]   # truth recomputed, not masked
    assert r.already_closed is True


# R3-3: benign token/cookie/*_token fields are ACCEPTED (the missing FP-acceptance tests).
def test_redaction_no_false_positive_on_benign_token_fields():
    led = CustodyLedger()
    led.append({"kind": "session.action", "actor": "x", "next_token": "page2"})
    led.append({"kind": "session.action", "actor": "x", "continuation_token": "abc"})
    led.append({"kind": "session.action", "actor": "x", "cookie": "theme=dark"})
    led.append({"kind": KIND_FILE_GATE_CROSS, "actor": "x", "lineage_id": "f",
                "gate": {"name": "gh", "token": "issue-1234"}})
    assert led.verify().ok and len(led) == 4
    # the high-signal names still fire
    for bad in ({"session_token": "s"}, {"access_token": "a"}, {"bearer": "b"}):
        with pytest.raises(SecretRefused):
            led.append(dict(bad, kind="session.action", actor="x"))


# R3-3: declaring egress must NOT excuse a checkout (distinct capabilities).
def test_egress_does_not_excuse_checkout():
    led = CustodyLedger()
    session_check_in(led, "s1", "willow", {"tools": ["read", "egress"]})
    file_gate_cross(led, "f1", "willow", {"name": "jeles", "auth_ref": "c"}, session_id="s1")
    _file_checkout(led, "f2", "willow", session_id="s1")   # a DIFFERENT file leaving custody
    r = session_check_out(led, "s1")
    assert r.reconciled is False and r.mismatches == ["checkout"]   # egress declared, checkout not


# R3-3: load() raises ChainError (not raw ValueError) on an uncanonicalizable leaf,
# and re-checks sig type.
def test_load_raises_chainerror_on_float_and_bad_sig(tmp_path):
    # a float leaf can't even be hashed, so write it raw; load()'s verify() must
    # surface it as ChainError, not let the ValueError escape.
    p = tmp_path / "c.jsonl"
    p.write_text(json.dumps({"kind": "session.action", "actor": "x", "n": 1.5,
                             "seq": 0, "ledger_prev_hash": GENESIS}) + "\n")
    with pytest.raises(_ChainError):
        CustodyLedger.load(str(p))
    # non-string sig hashes fine (sig is excluded) but must be re-checked on load
    p2 = tmp_path / "c2.jsonl"
    _write_valid_chain(p2, [{"kind": "session.action", "actor": "x", "sig": 123}])
    with pytest.raises(_ChainError):
        CustodyLedger.load(str(p2))


# ============================================================================
# Round-4 — pass-4 findings (Tier-2 fixes + documented Tier-4-boundary limits)
# ============================================================================
from willow_gate.custody import (  # noqa: E402
    verify_lineage as _verify_lineage, KIND_FILE_CREATE as _FC,
)


# R4-1 (F3): a capability exercised BEFORE the first check-in is still caught.
def test_pre_checkin_action_is_folded():
    led = CustodyLedger()
    session_record_action(led, "s1", "willow", "write")     # capability first
    session_check_in(led, "s1", "willow", {"tools": ["read"]})   # then narrow declaration
    r = session_check_out(led, "s1")
    assert r.reconciled is False and r.mismatches == ["write"]


# R4-2 (F2): *_token fields are secret-bearing except the pagination allowlist.
def test_star_token_secrets_caught_cursors_allowed():
    led = CustodyLedger()
    for bad in ({"refresh_token": "1//0opaque"}, {"id_token": "opaque"}, {"csrf_token": "opaque"}):
        with pytest.raises(SecretRefused):
            led.append(dict(bad, kind="session.action", actor="x"))
    # pagination cursors that end in _token are allowed
    for ok in ({"next_token": "page2"}, {"page_token": "p"}, {"continuation_token": "c"}):
        led.append(dict(ok, kind="session.action", actor="x"))
    assert led.verify().ok


# R4-3 (F6): an untagged capability event is not attributable — DOCUMENTED LIMIT.
def test_untagged_capability_not_reconciled_documented_limit():
    led = CustodyLedger()
    session_check_in(led, "s1", "willow", {"tools": ["read"]})
    _file_checkout(led, "f", "willow", session_id=None)     # no session tag
    r = session_check_out(led, "s1")
    # KNOWN LIMIT: reconciliation can't attribute an untagged event; the Tier-3b
    # hook must inject session_id. Asserted so the boundary is explicit.
    assert r.reconciled is True and r.mismatches == []


# R4-4 (F1): forged checkout+checkin in a loaded file MASKS — DOCUMENTED LIMIT.
def test_forged_checkout_checkin_masks_documented_limit(tmp_path):
    p = tmp_path / "c.jsonl"
    _write_valid_chain(p, [
        {"kind": "session.checkin", "session_id": "s1", "actor": "w", "declared": {"tools": ["read"]}},
        {"kind": "session.action", "session_id": "s1", "actor": "w", "tool": "write"},   # undeclared
        {"kind": "session.checkout", "session_id": "s1", "actor": "w", "reconciled": True, "mismatches": []},
        {"kind": "session.checkin", "session_id": "s1", "actor": "w", "declared": {"tools": ["read"]}},
    ])
    led = CustodyLedger.load(str(p))
    r = session_check_out(led, "s1")
    # KNOWN LIMIT (Tier-4): the forged pair rolls the window forward; the real
    # write is masked. Only the signed head can authenticate the derived records.
    assert r.reconciled is True and r.mismatches == []


# R4-4 (F4): a forged checkout spoofs already_closed on a genuine mismatch — LIMIT.
def test_forged_checkout_spoofs_already_closed_documented_limit(tmp_path):
    p = tmp_path / "c.jsonl"
    _write_valid_chain(p, [
        {"kind": "session.checkin", "session_id": "s1", "actor": "w", "declared": {"tools": ["read"]}},
        {"kind": "session.action", "session_id": "s1", "actor": "w", "tool": "write"},
        {"kind": "session.checkout", "session_id": "s1", "actor": "w", "reconciled": True, "mismatches": []},
    ])
    led = CustodyLedger.load(str(p))
    r = session_check_out(led, "s1")
    # recon VALUES are still true (round-3 win) ...
    assert r.reconciled is False and r.mismatches == ["write"]
    # ... but already_closed is spoofed True by the forgery — a consumer honoring
    # it would skip the real ladder feed. KNOWN LIMIT until Tier-4.
    assert r.already_closed is True


# R4-4 (F5): a forged capture_gap launders a lineage — DOCUMENTED LIMIT.
def test_forged_capture_gap_launders_lineage_documented_limit(tmp_path):
    p = tmp_path / "c.jsonl"
    Z = _ch("attacker-content")
    _write_valid_chain(p, [
        {"kind": _FC, "lineage_id": "f", "actor": "w", "content_hash": _ch("v1")},
        {"kind": KIND_CAPTURE_GAP, "lineage_id": "f", "actor": "w",
         "expected_content_hash": _ch("v1"), "observed_content_hash": Z},
        {"kind": KIND_FILE_WRITE, "lineage_id": "f", "actor": "w",
         "content_hash": _ch("v2"), "parent_content_hash": Z},
    ])
    led = CustodyLedger.load(str(p))
    # KNOWN LIMIT (Tier-4): a write parented on attacker content Z chains cleanly
    # because the forged capture_gap made Z the baseline.
    assert _verify_lineage(led, "f").ok is True
