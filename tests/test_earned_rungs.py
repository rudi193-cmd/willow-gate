"""Earned-rung tally (box audit willow-gate B12).

pass_count / fail_count are in the agent's own HMAC-signed header, so an agent
registered for Elder could put pass_count=999 in its FIRST header and clear the
min_pass_count=50 threshold instantly — the rungs were self-certified. The gate
now accrues its own per-agent count from witnessed check-outs (capped by the
tools it authorized) and, under WILLOW_GATE_ENFORCE_EARNED_RUNGS, gates on that.
"""
import hashlib
import hmac
import json
import time

import pytest

from willow_gate import GateError, WillowGate, _SIGNED_FIELDS

SEC = b"elder-secret-0123456789abcdef012"


def sign(secret, h):
    canon = json.dumps({k: h[k] for k in _SIGNED_FIELDS},
                       sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(secret, canon, hashlib.sha256).hexdigest()


def hdr(secret, **over):
    h = dict(agent_id="E1", agent_name="elder", last_gate="G0", pass_count=0,
             fail_count=0, drift=50, nonce="e" * 32, trust_level=4,
             timestamp=int(time.time() * 1000), tools=["read"],
             state_hash="a" * 64, signature="0" * 64, reserved=0)
    h.update(over)
    h["signature"] = sign(secret, h)
    return h


@pytest.fixture
def gate(tmp_path):
    g = WillowGate(base_dir=tmp_path, require_pgp=False)
    g.register_agent("E1", SEC, max_trust=4)   # ceiling Elder, but nothing earned
    return g


def test_first_header_cannot_buy_elder_when_enforced(gate, monkeypatch):
    monkeypatch.setenv("WILLOW_GATE_ENFORCE_EARNED_RUNGS", "1")
    # Registered for Elder AND the header self-reports pass_count=999 — but the
    # gate's own tally is 0, so the earned threshold (min_pass_count 50) denies.
    with pytest.raises(GateError, match="pass_count 0 below required 50"):
        gate.check_in(hdr(SEC, pass_count=999, fail_count=0))


def test_header_counts_still_trusted_when_flag_off(gate):
    # Default (off): header counts remain authoritative — backward compatible, no
    # live agent is demoted by this landing.
    ok, _, s = gate.check_in(hdr(SEC, pass_count=999, fail_count=0))
    assert ok and s["trust_level"] == 4


def test_earned_agent_may_enter_when_enforced(gate, monkeypatch):
    monkeypatch.setenv("WILLOW_GATE_ENFORCE_EARNED_RUNGS", "1")
    # An operator (or accrual over real sessions) has recorded 50 earned passes.
    gate._tally["E1"] = {"pass": 50, "fail": 0}
    ok, _, s = gate.check_in(hdr(SEC, pass_count=0))   # header count now irrelevant
    assert ok and s["trust_level"] == 4


def test_accrual_is_capped_by_witnessed_tools(gate, monkeypatch):
    monkeypatch.setenv("WILLOW_GATE_ENFORCE_EARNED_RUNGS", "1")
    # Enter at Rookie (min_pass_count 0, read-only) — the rung a zero-tally agent
    # can hold — do one read, then check out CLAIMING a pass_delta of 999.
    _, _, s = gate.check_in(hdr(SEC, trust_level=1, tools=["read"], nonce="1" * 32))
    gate.authorize_tool(s, "read")
    exit_h = hdr(SEC, trust_level=1, tools=["read"], nonce="1" * 32,
                 pass_count=999, timestamp=s["entry_ms"] + 1000)
    ok, _ = gate.check_out(s, exit_h)
    assert ok
    # Accrual is min(claimed 999, distinct tools the gate authorized == {"read"}),
    # so the ladder cannot be inflated faster than real gate-cleared work.
    assert gate._agent_tally("E1") == {"pass": 1, "fail": 0}


def test_fail_tally_also_gates(gate, monkeypatch):
    monkeypatch.setenv("WILLOW_GATE_ENFORCE_EARNED_RUNGS", "1")
    gate._tally["E1"] = {"pass": 50, "fail": 5}     # earned passes but too many fails
    with pytest.raises(GateError, match="fail_count 5 exceeds 1"):
        gate.check_in(hdr(SEC, pass_count=0, fail_count=0))
