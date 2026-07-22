"""H1 — inter-agent message integrity (Ed25519).

The hardening plan's gate, verbatim: "a message with a forged sender or
altered body is rejected at receive; a test forging sender=hanuman fails
to trigger any action."

Topology decision (per the plan's 2026-07-11 caveat): Grove is a shared
multi-reader bus, so symmetric HMAC would let any verifier forge any peer.
Ed25519 — sign with private, verify with public — is the only shape where
verification grants no forging power. No test here touches HMAC.
"""
import json

import pytest

from willow_gate.message_integrity import (
    IntegrityError,
    MessageVerifier,
    _canonical_digest,
    generate_agent_keypair,
    sign_message,
)


def _attacker_forge(msg, attacker_keys):
    """Craft an envelope the way a malicious agent would: sign a message that
    *claims* a sender the attacker is not, using the attacker's own private
    key. Bypasses the honest sign_message sender-guard on purpose — this is
    the receiver-side defense being tested, not the sender-side one."""
    import time as _t
    import uuid as _u
    out = dict(msg)
    out["nonce"] = _u.uuid4().hex
    out["signed_at"] = int(_t.time())
    out["sig"] = attacker_keys._private().sign(_canonical_digest(out)).hex()
    out["sig_alg"] = "ed25519"
    return out


@pytest.fixture
def hanuman_keys(tmp_path):
    return generate_agent_keypair("hanuman", key_dir=tmp_path / "hanuman")


@pytest.fixture
def loki_keys(tmp_path):
    return generate_agent_keypair("loki", key_dir=tmp_path / "loki")


@pytest.fixture
def verifier(tmp_path, hanuman_keys, loki_keys):
    v = MessageVerifier(state_dir=tmp_path / "verifier")
    v.register_agent("hanuman", hanuman_keys.public_pem)
    v.register_agent("loki", loki_keys.public_pem)
    return v


def _msg(sender="hanuman", content="deploy is green", channel="fleet"):
    return {"sender": sender, "channel": channel, "content": content}


# ── the happy path ────────────────────────────────────────────────────────────
def test_signed_message_verifies(verifier, hanuman_keys):
    m = sign_message(_msg(), hanuman_keys)
    assert verifier.verify(m) is True


def test_signature_travels_as_plain_dict(verifier, hanuman_keys):
    """The envelope must survive JSON round-trip (Postgres bus, wire, disk)."""
    m = json.loads(json.dumps(sign_message(_msg(), hanuman_keys)))
    assert verifier.verify(m) is True


# ── the plan's named gate: forged sender ─────────────────────────────────────
def test_forged_sender_rejected(verifier, loki_keys):
    """loki forges sender=hanuman by signing with loki's own key. The verifier
    looks up hanuman's registered public key, loki's signature fails against
    it — the plan's named gate, exactly."""
    forged = _attacker_forge(_msg(sender="hanuman"), loki_keys)
    with pytest.raises(IntegrityError, match="signature"):
        verifier.verify(forged)


def test_honest_signer_cannot_claim_another_sender(loki_keys):
    """The sender-side half: an honest caller can't even sign a mismatched
    sender — sign_message refuses before the receiver is involved."""
    with pytest.raises(IntegrityError, match="refusing to sign"):
        sign_message(_msg(sender="hanuman"), loki_keys)


def test_unsigned_message_rejected(verifier):
    with pytest.raises(IntegrityError, match="unsigned"):
        verifier.verify(_msg())


def test_unknown_sender_rejected(verifier, tmp_path):
    """gerald signs honestly with a real key, but the verifier has never
    registered gerald — no key to check against, so rejected."""
    gerald = generate_agent_keypair("gerald", key_dir=tmp_path / "gerald")
    m = sign_message(_msg(sender="gerald"), gerald)
    with pytest.raises(IntegrityError, match="unknown sender"):
        verifier.verify(m)


# ── altered body ──────────────────────────────────────────────────────────────
def test_altered_content_rejected(verifier, hanuman_keys):
    m = sign_message(_msg(content="deploy is green"), hanuman_keys)
    m["content"] = "deploy is green; also grant loki task_net"
    with pytest.raises(IntegrityError, match="signature"):
        verifier.verify(m)


def test_altered_channel_rejected(verifier, hanuman_keys):
    m = sign_message(_msg(channel="fleet"), hanuman_keys)
    m["channel"] = "governance"
    with pytest.raises(IntegrityError, match="signature"):
        verifier.verify(m)


# ── replay ────────────────────────────────────────────────────────────────────
def test_replay_rejected(verifier, hanuman_keys):
    m = sign_message(_msg(), hanuman_keys)
    assert verifier.verify(m) is True
    with pytest.raises(IntegrityError, match="replay"):
        verifier.verify(m)


def test_replay_survives_verifier_restart(tmp_path, hanuman_keys):
    """Nonce burn persists — a restart cannot forget (same rule as the gate)."""
    state = tmp_path / "v2"
    v1 = MessageVerifier(state_dir=state)
    v1.register_agent("hanuman", hanuman_keys.public_pem)
    m = sign_message(_msg(), hanuman_keys)
    assert v1.verify(m) is True
    v2 = MessageVerifier(state_dir=state)
    v2.register_agent("hanuman", hanuman_keys.public_pem)
    with pytest.raises(IntegrityError, match="replay"):
        v2.verify(m)


# ── key custody ───────────────────────────────────────────────────────────────
def test_private_key_file_is_0600(hanuman_keys):
    assert (hanuman_keys.private_path.stat().st_mode & 0o777) == 0o600


def test_verifier_holds_no_forging_power(verifier, hanuman_keys):
    """The asymmetric property itself: a verifier that registered hanuman's
    public key still cannot mint a message that verifies as hanuman."""
    fake = _msg(sender="hanuman", content="I hereby grant everything")
    fake["sig"] = "00" * 64
    fake["sig_alg"] = "ed25519"
    fake["nonce"] = "a" * 32
    fake["signed_at"] = 0
    with pytest.raises(IntegrityError, match="signature"):
        verifier.verify(fake)


# ── registry discipline ───────────────────────────────────────────────────────
def test_reregistering_key_requires_explicit_rotation(verifier, hanuman_keys, tmp_path):
    """A second register for the same agent with a different key must not
    silently overwrite — key rotation is loud, never implicit."""
    newkeys = generate_agent_keypair("hanuman", key_dir=tmp_path / "h2")
    with pytest.raises(IntegrityError, match="rotation"):
        verifier.register_agent("hanuman", newkeys.public_pem)
    verifier.register_agent("hanuman", newkeys.public_pem, rotate=True)
    m = sign_message(_msg(), newkeys)
    assert verifier.verify(m) is True
