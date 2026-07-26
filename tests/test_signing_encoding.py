"""Canonical signing-encoding golden vector (box audit A6).

Four repos hand-rolled the HMAC signing message; one (Nestor) used a naive
``"\\x1f".join(...)`` that was forgeable, while willow-gate / willow-mcp
session_binder / the-squirrel used the collision-safe canonical JSON. They now
all use the canonical form. This test pins the EXACT bytes so willow-gate can't
drift; willow-mcp/tests/test_signing_encoding.py pins the SAME golden, so the two
independent copies (session_binder deliberately does not depend on willow-gate)
are held byte-identical — the divergence that caused the forgery can't recur.

If this vector changes, the signing encoding changed: every other copy's golden
must change in lockstep, and every already-signed header/session is invalidated.
"""
from willow_gate import canonical_header_bytes

# A fixed, fully-populated header (values chosen to exercise ints, negatives, a
# list, and long hex — anything that a sloppy encoder might reorder or merge).
SAMPLE = {
    "agent_id": "sean", "agent_name": "Sean", "last_gate": "G7",
    "pass_count": 50, "fail_count": 1, "drift": -12, "nonce": "n" * 32,
    "trust_level": 4, "timestamp": 1721880000000, "tools": ["read", "write"],
    "state_hash": "a" * 64, "reserved": 0,
}

# The fleet canonical signing encoding. MUST match willow-mcp/session_binder and
# the-squirrel byte-for-byte (A6).
GOLDEN = (
    '{"agent_id":"sean","agent_name":"Sean","drift":-12,"fail_count":1,'
    '"last_gate":"G7","nonce":"nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn","pass_count":50,'
    '"reserved":0,'
    '"state_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    '"timestamp":1721880000000,"tools":["read","write"],"trust_level":4}'
)


def test_canonical_encoding_matches_the_fleet_golden():
    assert canonical_header_bytes(SAMPLE).decode() == GOLDEN


def test_key_order_is_stable_regardless_of_input_order():
    shuffled = dict(reversed(list(SAMPLE.items())))
    assert canonical_header_bytes(shuffled).decode() == GOLDEN
