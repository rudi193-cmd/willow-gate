"""WillowGate logic tests. No network, no PGP required (require_pgp=False writes
a plaintext dev ledger). A separate test exercises the real encrypted ledger and
skips cleanly if gpg / python-gnupg are unavailable."""
import hashlib
import hmac
import json
import time

import pytest

from willow_gate import GateError, WillowGate, _SIGNED_FIELDS

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
