"""A9 — the fleet trust ladder is ONE canonical identity->authority model.

The 2026-07-24 box scan (A9) flagged the trust model living in three
incompatible shapes: willow-gate's rich ``TrustLevel`` ladder (here),
willow-mcp's ``session_binder.TRUST_LEVELS`` ``(name, read_only)``, and
willow-mcp's ``tier_policy`` tool-class ceiling. Nothing cross-checks them, so
they can silently disagree — and then an agent's authority depends on *which*
gate evaluates it (a "Rookie" on this ladder that is ``full_access`` in a
manifest is exactly the hole willow-mcp's tier_policy closes at enforcement).

They express the SAME ladder today. This pins THIS repo's ladder to the
canonical below; willow-mcp pins the *identical* canonical in its own
``tests/test_trust_ladder_canonical.py``. If either repo's ladder drifts from
the canonical, its test fails loudly — the same golden-vector discipline the A6
signing-encoding guard uses across the two repos (they can't share code:
``session_binder`` deliberately does not import willow-gate).

Canonical: ``level -> (name, read_only, cumulative privilege classes)``.
``query`` is a read-synonym fleet-wide (willow-mcp tier_policy documents that no
capability is "query but not read"), so it is folded into ``read`` before
comparison. Privilege is cumulative: read ⊆ +write(Steady) ⊆ +execute(Veteran)
⊆ +admin(Elder); Exiled/Rookie are read-only.
"""
from willow_gate import TRUST_LEVELS

# The one fleet ladder. This dict MUST be identical to CANONICAL in
# willow-mcp/tests/test_trust_ladder_canonical.py — that is the cross-repo
# agreement A9 is about. Change the ladder in BOTH repos or not at all.
CANONICAL = {
    0: ("Exiled",  True,  frozenset()),
    1: ("Rookie",  True,  frozenset({"read"})),
    2: ("Steady",  False, frozenset({"read", "write"})),
    3: ("Veteran", False, frozenset({"read", "write", "execute"})),
    4: ("Elder",   False, frozenset({"read", "write", "execute", "admin"})),
}


def _fold_query(tools) -> frozenset:
    """query ≡ read fleet-wide — normalize before comparing the two ladders."""
    return frozenset("read" if t == "query" else t for t in tools)


def test_trust_levels_match_the_fleet_canonical():
    got = {
        n: (tl.name, tl.read_only, _fold_query(tl.allowed_tools))
        for n, tl in TRUST_LEVELS.items()
    }
    assert got == CANONICAL, (
        "willow-gate's TRUST_LEVELS drifted from the fleet canonical trust "
        "ladder. If this change is intended, update CANONICAL here AND the "
        "matching pin in willow-mcp/tests/test_trust_ladder_canonical.py — the "
        "two authority models must not diverge (box audit A9).")
