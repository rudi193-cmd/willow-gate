# willow-gate

A minimalist check-in / check-out gate for agents. Symmetric 13-field
validation, a five-rung trust ladder, an announce-loud-for-the-untrusted
inversion, and a PGP-encrypted flat-file ledger. Hard stops, no swallowed
exceptions.

From the WillowGate DRAFT_SPEC (v0314), hardened and verified.

## The idea

Every agent knocks on the door with the same 13 fields going in and 13 coming
out. What it declares on entry is reconciled against what it actually did on
exit. Trust is not *asserted* — it is **bound**: the `signature` field is an
HMAC over the header keyed by a per-agent secret the gate holds, and a claimed
`trust_level` is capped at the agent's registered ceiling. "Elder" is not a
text field anyone can type.

Read is universal — even an outsider (Exiled) may read, loudly. What outsiders
cannot do is *take information anywhere else*: export/exfiltration is gated, and
the lower the trust, the louder every action is announced.

## Trust levels

| Level | Name | Session | Export | Announcement | Tools |
|---|---|---|---|---|---|
| 0 | Exiled | read-only | ❌ | maximum | read |
| 1 | Rookie | read-only | ❌ | large | read |
| 2 | Steady | read + write | ✅ | medium | read, write |
| 3 | Veteran | read + write | ✅ | small | + query, execute |
| 4 | Elder | read + write | ✅ | minimal | + admin |

Drift and fail budgets **tighten** as trust rises — the most powerful rung is
held to the strictest tolerances, not the loosest.

## Enforcement vs. audit — read this first

WillowGate **prevents** only when a harness routes every tool call through
`authorize_tool()` *before* the tool runs. Wired into a pre-tool hook it is a
gate: a denied call never executes. Un-wired, it is a loud **ledger** — it
records and announces, but cannot stop what it is never asked about. Decide
which one you are building, and wire accordingly.

The identity binding is **symmetric** (HMAC — the gate holds each agent's
secret). Asymmetric "agent signs, gate verifies with only a public key" needs
the `signature` field widened beyond 64 hex.

## Install

```bash
pip install -e .        # python-gnupg is required for the encrypted ledger
```

## Quickstart

```python
from willow_gate import WillowGate

# Ledger encrypts to the operator's PGP key — never a bundled key.
gate = WillowGate(operator_key_fpr="<your PGP fingerprint>")

# Bind an identity to a shared secret and a trust CEILING. Operator-side only.
gate.register_agent("R1", secret=b"...32+ bytes...", max_trust=1)

ok, msg, session = gate.check_in(header)                 # 13 fields, HMAC-signed
allowed, why = gate.authorize_tool(session, "read")      # call before EVERY tool
ok, msg = gate.check_out(session, exit_header)           # 13 fields, diffed
```

For local logic testing without PGP, pass `require_pgp=False` — this writes a
plaintext ledger and is for development only, never production.

## Tests

```bash
pip install -e '.[dev]'
pytest
```

Covers trust binding, the registered ceiling cap, inline `authorize_tool`
prevention, export denial, nonce replay (including across a restart, via the
persistent nonce store), the reserved trap field, drift limits, the
read-universal / Exiled-read-only rule, and symmetric check-out. A separate
PGP round-trip test (skipped if `gpg`/`python-gnupg` are unavailable) proves the
encrypted ledger encrypts and decrypts.

## License

MIT
