"""WillowGate logic tests. No network, no PGP required (require_pgp=False writes
a plaintext dev ledger). A separate test exercises the real encrypted ledger and
skips cleanly if gpg / python-gnupg are unavailable."""
import hashlib
import hmac
import json
import time

import pytest

from willow_gate import GateError, Tool, WillowGate, _SIGNED_FIELDS

SEC = b"rookie-secret-0123456789abcdef01"


def sign(secret, h):
    canon = json.dumps({k: h[k] for k in _SIGNED_FIELDS},
                       sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(secret, canon, hashlib.sha256).hexdigest()


def hdr(secret, **over):
    h = dict(agent_id="R1", agent_name="rookie", last_gate="G0", pass_count=0,
             fail_count=0, drift=50, nonce="a" * 32, trust_level=1,
             timestamp=int(time.time() * 1000), tools=["read"],
             state_hash="a" * 64, signature="0" * 64, reserved=0)
    h.update(over)
    h["signature"] = sign(secret, h)
    return h


@pytest.fixture
def gate(tmp_path):
    g = WillowGate(base_dir=tmp_path, require_pgp=False)
    g.register_agent("R1", SEC, max_trust=1)
    return g


def test_valid_checkin_and_read(gate):
    ok, _, s = gate.check_in(hdr(SEC))
    assert ok
    assert gate.authorize_tool(s, "read")[0]


def test_write_denied_for_rookie(gate):
    _, _, s = gate.check_in(hdr(SEC))
    assert not gate.authorize_tool(s, "write")[0]


def test_export_denied_for_rookie(gate):
    _, _, s = gate.check_in(hdr(SEC))
    assert not gate.authorize_tool(s, "read", export=True)[0]


def test_checkout(gate):
    _, _, s = gate.check_in(hdr(SEC))
    gate.authorize_tool(s, "read")
    e = hdr(SEC, timestamp=s["entry_ms"] + 1000, tools=["read"])
    ok, _ = gate.check_out(s, e)
    assert ok


def test_plaintext_ledger_filenames(gate):
    """Dev ledger files are <nonce>.<kind>.json — the kind appears once."""
    _, _, s = gate.check_in(hdr(SEC))
    gate.authorize_tool(s, "read")
    e = hdr(SEC, timestamp=s["entry_ms"] + 1000, tools=["read"])
    gate.check_out(s, e)
    names = sorted(p.name for p in gate.ledger_dir.iterdir())
    assert names == ["a" * 32 + ".entry.json", "a" * 32 + ".exit.json"]


def test_trust_claim_over_ceiling_rejected(gate):
    with pytest.raises(GateError):
        gate.check_in(hdr(SEC, nonce="b" * 32, trust_level=4))


def test_signature_mismatch_rejected(gate):
    h = hdr(SEC, nonce="c" * 32)
    h["signature"] = "f" * 64
    with pytest.raises(GateError):
        gate.check_in(h)


def test_reserved_trap_rejected(gate):
    with pytest.raises(GateError):
        gate.check_in(hdr(SEC, nonce="d" * 32, reserved=1))


def test_drift_over_limit_rejected(gate):
    with pytest.raises(GateError):
        gate.check_in(hdr(SEC, nonce="e" * 32, drift=6000))


def test_exiled_read_only_room(gate):
    esec = b"exiled-secret-0123456789abcdef01"
    gate.register_agent("E0", esec, max_trust=0)
    ok, _, s = gate.check_in(hdr(esec, agent_id="E0", agent_name="ex",
                                 nonce="f" * 32, trust_level=0, tools=["read"]))
    assert ok
    assert gate.authorize_tool(s, "read")[0]        # read is universal
    assert not gate.authorize_tool(s, "write")[0]   # but nothing else


def test_nonce_replay_rejected(gate):
    gate.check_in(hdr(SEC, nonce="1" * 32))
    with pytest.raises(GateError):
        gate.check_in(hdr(SEC, nonce="1" * 32))


def test_nonce_replay_across_restart_rejected(gate, tmp_path):
    gate.check_in(hdr(SEC, nonce="1" * 32))
    g2 = WillowGate(base_dir=tmp_path, require_pgp=False)  # fresh instance, same dir
    g2.register_agent("R1", SEC, max_trust=1)
    with pytest.raises(GateError):
        g2.check_in(hdr(SEC, nonce="1" * 32))


def test_steady_write_and_export_allowed(gate):
    ssec = b"steady-secret-0123456789abcdef01"
    gate.register_agent("S2", ssec, max_trust=2)
    ok, _, s = gate.check_in(hdr(ssec, agent_id="S2", agent_name="steady",
                                 nonce="2" * 32, trust_level=2,
                                 tools=["read", "write"], pass_count=5))
    assert ok
    assert gate.authorize_tool(s, "write")[0]
    assert gate.authorize_tool(s, "write", export=True)[0]


def test_pgp_ledger_round_trip(tmp_path):
    """The real encrypted ledger. Skips if gpg / python-gnupg unavailable or a
    throwaway key cannot be generated (e.g. GNUPGHOME path too long)."""
    gnupg = pytest.importorskip("gnupg")
    import os
    home = "/tmp/wg_test_gnupg"
    os.makedirs(home, exist_ok=True)
    os.chmod(home, 0o700)
    os.environ["GNUPGHOME"] = home
    g = gnupg.GPG(gnupghome=home)
    key = g.gen_key(g.gen_key_input(name_email="wg-test@local",
                                    key_type="RSA", key_length=2048,
                                    no_protection=True))
    if not key.fingerprint:
        pytest.skip("could not generate a throwaway PGP key in this environment")
    fpr = str(key.fingerprint)
    gate = WillowGate(base_dir=tmp_path, require_pgp=True, operator_key_fpr=fpr)
    gate.register_agent("R1", SEC, max_trust=1)
    ok, _, _ = gate.check_in(hdr(SEC))
    assert ok
    blob = next(gate.ledger_dir.glob("*.entry.gpg")).read_bytes()
    assert blob.startswith(b"-----BEGIN PGP MESSAGE-----")
    back = json.loads(g.decrypt(blob).data)
    assert back["agent_id"] == "R1"


def test_pgp_required_fails_closed_without_key(tmp_path):
    pytest.importorskip("gnupg")
    with pytest.raises(GateError):
        WillowGate(base_dir=tmp_path, require_pgp=True, operator_key_fpr="")


# ─── Check-out reconciliation (defense-in-depth) ─────────────────────────────
# The lock is authorize_tool() at the door, but check_out() re-reconciles the
# exit manifest against the session as a second line. These exercise the two
# distinct reconciliation checks and the exit-header re-authentication that had
# no adversarial coverage: an agent that DECLARED one thing and DID another.

SSEC = b"steady-secret-0123456789abcdef01"


def steady_session(gate, nonce="2" * 32):
    """A checked-in Steady session (read+write granted, pass_count satisfied)."""
    gate.register_agent("S2", SSEC, max_trust=2)
    _, _, s = gate.check_in(hdr(SSEC, agent_id="S2", agent_name="steady",
                                nonce=nonce, trust_level=2,
                                tools=["read", "write"], pass_count=5))
    return s


def steady_exit(s, **over):
    base = dict(agent_id="S2", agent_name="steady", nonce=s["nonce"],
                trust_level=2, tools=["read", "write"], pass_count=5,
                timestamp=s["entry_ms"] + 1000)
    base.update(over)
    return hdr(SSEC, **base)


def test_checkout_declared_read_did_write_rejected(gate):
    """The flagship adversary: a read-only Rookie declares only `read` at entry,
    then presents an exit manifest claiming it used `write`. The exit tool is
    not in the session grant -> out-of-band tool use."""
    _, _, s = gate.check_in(hdr(SEC))          # Rookie, tools=["read"]
    gate.authorize_tool(s, "read")
    e = hdr(SEC, timestamp=s["entry_ms"] + 1000, tools=["read", "write"])
    with pytest.raises(GateError, match="out-of-band"):
        gate.check_out(s, e)


def test_checkout_rejects_tool_granted_but_never_authorized(gate):
    """`write` IS in a Steady's grant, but it was never cleared through
    authorize_tool() during the session, so an exit manifest listing it is a
    call that bypassed the door."""
    s = steady_session(gate)
    gate.authorize_tool(s, "read")             # read only — write never authorized
    e = steady_exit(s, tools=["read", "write"])
    with pytest.raises(GateError, match="unauthorized"):
        gate.check_out(s, e)


def test_checkout_properly_authorized_write_passes(gate):
    """Positive control: a Steady that actually cleared read AND write through
    the door checks out clean with both in the exit manifest."""
    s = steady_session(gate)
    gate.authorize_tool(s, "read")
    gate.authorize_tool(s, "write")
    ok, _ = gate.check_out(s, steady_exit(s, tools=["read", "write"]))
    assert ok


def test_checkout_forged_exit_signature_rejected(gate):
    """The exit header is signed too — a forged exit signature is refused even
    though every immutable field matches the entry."""
    _, _, s = gate.check_in(hdr(SEC))
    gate.authorize_tool(s, "read")
    e = hdr(SEC, timestamp=s["entry_ms"] + 1000, tools=["read"])
    e["signature"] = "f" * 64
    with pytest.raises(GateError, match="signature"):
        gate.check_out(s, e)


def test_checkout_immutable_field_tamper_rejected(gate):
    """A pinned identity field (here trust_level) that differs between entry and
    exit is rejected before anything else — trust cannot be re-declared on the
    way out."""
    _, _, s = gate.check_in(hdr(SEC))
    gate.authorize_tool(s, "read")
    e = hdr(SEC, timestamp=s["entry_ms"] + 1000, tools=["read"], trust_level=4)
    with pytest.raises(GateError, match="does not match entry"):
        gate.check_out(s, e)


def test_checkout_exit_before_entry_rejected(gate):
    _, _, s = gate.check_in(hdr(SEC))
    gate.authorize_tool(s, "read")
    e = hdr(SEC, timestamp=s["entry_ms"], tools=["read"])   # not strictly after
    with pytest.raises(GateError, match="after entry"):
        gate.check_out(s, e)


def test_checkout_pass_count_decrease_rejected(gate):
    s = steady_session(gate)
    gate.authorize_tool(s, "read")
    e = steady_exit(s, tools=["read"], pass_count=4)         # entry was 5
    with pytest.raises(GateError, match="pass_count"):
        gate.check_out(s, e)


def test_checkout_fail_count_decrease_rejected(gate):
    s = steady_session(gate)
    gate.authorize_tool(s, "read")
    # Entry fail_count defaulted to 0; a negative exit count is a decrease.
    e = steady_exit(s, tools=["read"], fail_count=-1)
    with pytest.raises(GateError, match="fail_count"):
        gate.check_out(s, e)


# ─── Check-in shape and gate coverage ────────────────────────────────────────

def test_checkin_tools_exceed_grant_rejected(gate):
    """A Rookie declaring a tool above its ceiling (`execute`) is refused at the
    door, before any session exists."""
    with pytest.raises(GateError, match="exceed"):
        gate.check_in(hdr(SEC, nonce="7" * 32, tools=["execute"]))


def test_checkin_missing_field_rejected(gate):
    """The '13 in' half of the symmetry: a dropped field is refused."""
    h = hdr(SEC, nonce="8" * 32)
    del h["drift"]
    with pytest.raises(GateError, match="missing fields"):
        gate.check_in(h)


def test_checkin_extra_field_rejected(gate):
    """The other half: an unexpected 14th field is refused."""
    h = hdr(SEC, nonce="9" * 32)
    h["extra"] = "smuggled"
    with pytest.raises(GateError, match="unknown fields"):
        gate.check_in(h)


def test_checkin_min_pass_count_gate(gate):
    """Steady requires a minimum earned pass_count; too low is refused even with
    a valid signature and an in-ceiling trust claim."""
    gate.register_agent("S2", SSEC, max_trust=2)
    with pytest.raises(GateError, match="pass_count"):
        gate.check_in(hdr(SSEC, agent_id="S2", agent_name="steady",
                          nonce="a1" + "0" * 30, trust_level=2,
                          tools=["read", "write"], pass_count=0))


def test_checkin_max_fail_count_gate(gate):
    with pytest.raises(GateError, match="fail_count"):
        gate.check_in(hdr(SEC, nonce="b1" + "0" * 30, fail_count=6))


def test_checkin_unregistered_agent_rejected(gate):
    """A well-formed, plausibly-signed header for an agent the gate never
    registered has no expected signature to compare against -> hard stop."""
    with pytest.raises(GateError, match="unregistered"):
        gate.check_in(hdr(SEC, agent_id="GHOST", nonce="c1" + "0" * 30))


# ─── The harness: PREVENT, not just record ───────────────────────────────────
# bind_tools() wraps a session so the only way to run a tool is call(), which
# authorizes BEFORE invoking. These assert the difference the README draws
# between a gate that prevents and a ledger that merely diffs at exit: a denied
# tool must NEVER run, and an authorized run must reconcile at check-out with no
# hand-threading.

def test_harness_runs_an_allowed_tool_and_records_it(gate):
    _, _, s = gate.check_in(hdr(SEC))
    ran = []
    h = gate.bind_tools(s, [Tool("read", lambda: ran.append("read") or "page")])
    assert h.call("read") == "page"
    assert ran == ["read"]
    assert "read" in s["tools_used"]        # recorded, so check_out will reconcile


def test_harness_prevents_a_denied_tool_the_fn_never_runs(gate):
    """A Rookie is read-only. Binding a write tool and calling it must hard-stop
    BEFORE the callable — the side effect must not happen, and nothing is
    recorded as used."""
    _, _, s = gate.check_in(hdr(SEC))
    ran = []
    h = gate.bind_tools(s, [Tool("write", lambda: ran.append("write"))])
    with pytest.raises(GateError):
        h.call("write")
    assert ran == []                        # the tool never ran
    assert "write" not in s["tools_used"]   # and nothing was recorded


def test_harness_prevents_export_from_a_non_export_level(gate):
    _, _, s = gate.check_in(hdr(SEC))       # Rookie: write_export_allowed = False
    ran = []
    h = gate.bind_tools(s, [Tool("read", lambda: ran.append("x"), export=True)])
    with pytest.raises(GateError):
        h.call("read")                      # read clears the grant, export does not
    assert ran == []


def test_harness_unknown_tool_is_a_hard_stop(gate):
    _, _, s = gate.check_in(hdr(SEC))
    h = gate.bind_tools(s, [Tool("read", lambda: "ok")])
    with pytest.raises(GateError, match="unknown tool"):
        h.call("delete")


def test_harness_read_is_universal_even_for_exiled(gate):
    esec = b"exiled-secret-0123456789abcdef01"
    gate.register_agent("E0", esec, max_trust=0)
    _, _, s = gate.check_in(hdr(esec, agent_id="E0", agent_name="ex",
                                nonce="f" * 32, trust_level=0, tools=["read"]))
    h = gate.bind_tools(s, [Tool("read", lambda: "readable")])
    assert h.call("read") == "readable"


def test_harness_does_not_expose_the_callables(gate):
    _, _, s = gate.check_in(hdr(SEC))
    h = gate.bind_tools(s, [Tool("read", lambda: "secret-fn")])
    assert h.tools == ("read",)             # names only — no un-gated path to fn


def test_harness_makes_checkout_reconcile_end_to_end(gate):
    """The payoff: a Steady runs read+write ONLY through the harness, and
    check_out reconciles with no manual authorize_tool calls — the wiring is
    what keeps 'declared == did' true."""
    s = steady_session(gate)
    h = gate.bind_tools(s, [Tool("read", lambda: 1), Tool("write", lambda: 2)])
    assert h.call("read") == 1
    assert h.call("write") == 2
    ok, _ = gate.check_out(s, steady_exit(s, tools=["read", "write"]))
    assert ok


def test_harness_denied_tool_stays_out_of_the_exit_manifest(gate):
    """Ties the harness to the reconciliation gate: because a prevented write is
    never recorded as used, a later exit manifest claiming it is still caught as
    out-of-band — prevention and audit agree."""
    s = steady_session(gate)
    h = gate.bind_tools(s, [Tool("read", lambda: 1)])   # write NOT bound
    h.call("read")
    with pytest.raises(GateError):
        h.call("write")                                 # unknown to this harness
    # an exit manifest that nonetheless claims write is rejected at check_out
    with pytest.raises(GateError, match="unauthorized"):
        gate.check_out(s, steady_exit(s, tools=["read", "write"]))
