# willow-gate Hardening Plan — mapped to OWASP Top 10 for Agentic Applications

Status: **DRAFT** · 2026-07-11 (rev. +H7 safety axis) · seat: willow · author: instance (proposes; operator ratifies)
Source: OWASP Top 10 for Agentic Applications (ASI01–10, published 2025-12; Alice/ActiveFence
co-sponsor breakdown fetched 2026-07-11, guard CLEAN). willow-gate state from
`~/github/willow-gate` README + tests read this session, and fleet knowledge.

Verify-don't-assert: every item below carries a **gate** — the observable that proves it done.
Nothing here is built without operator ratification. Ordered by leverage (weakest coverage first).

> **Note on axes.** H1–H6 map to the OWASP list, which is *adversary-centric* — every item assumes
> an attacker. **H7 (Tier 4) is a different axis: a safety failure with no adversary at all.** The
> security frame is structurally blind to it; it is included here on purpose because it is the
> fleet's genuinely novel ground and the one seed nobody else holds.

---

## Where willow-gate already stands (do NOT re-solve)
Strong, keep: **ASI02** tool misuse (`authorize_tool()` pre-call + trust ladder + bwrap/Kart),
**ASI03** identity/privilege (per-agent HMAC secret, trust_level capped at ceiling, nonce
anti-replay), **ASI04-files** (PGP signing, tamper invalidates key), **ASI10** rogue agents
(envelope gating + operator-close + preconditions chain). These are the field's recommended
deterministic pre-execution gates and they exist. The plan below is the gaps only.

---

## TIER 1 — enforceable now, no research blocker

### H1. ASI07 — Inter-agent comm integrity — ✅ BUILT 2026-07-22 (Ed25519)
**Gap:** Grove messages carry a `sender` field, not a cryptographic binding. A forged
`sender=hanuman` on the Postgres bus is currently plausible; dispatch envelopes are addressed
but not signed.
**Fix:** Sign every Grove/dispatch message with the sending agent's existing willow-gate HMAC
secret (the same key already used for check-in). Receiver verifies against the sender's
registered secret before acting. Reuses the gate's key material — no new crypto.
**Effort:** small-medium. The HMAC path already exists in willowgate.py; extend it to the
Grove send/receive edge.
**Gate:** a message with a forged sender or altered body is rejected at receive; a test forging
`sender=hanuman` fails to trigger any action. Add to `tests/`.
**Dep:** none. Ship first.
**Caveat (2026-07-11 review):** HMAC is *symmetric* — any party that can verify `sender=X` holds
X's secret and can therefore forge X. On a shared bus where agents verify each other, this gives
integrity but not non-repudiation, and one compromised agent can impersonate every peer whose
key it can read. HMAC is correct only under a **single trusted-broker** topology (receiver-as-sole-
verifier). For true agent-to-agent authenticity, re-scope to **per-agent asymmetric signatures**
(Ed25519: sign with private, verify with public, no verifier can forge). Decide topology before
building; "no new crypto" is the convenient choice, not necessarily the correct one.

**Resolution (2026-07-22):** topology decided **Ed25519** (asymmetric), per the caveat's own conclusion — Grove is a shared multi-reader bus, so symmetric HMAC would let any verifier forge any peer. Shipped as `src/willow_gate/message_integrity.py`: `sign_message` / `MessageVerifier` with a public-key registry, persistent nonce burn (survives restart), a 24h freshness window, and explicit-only key rotation. 13 tests in `tests/test_message_integrity.py` cover the named gate (forged `sender=hanuman` rejected), altered body/channel, replay, unknown/unsigned sender, JSON round-trip, 0600 key custody, and the asymmetric no-forging property. Wiring the Grove send/receive edge to call these is the follow-up (grove_db.py lives in safe-app-willow-grove).

### H2. ASI05 — Egress authorization is a regex (B-37, known hole)
**Gap:** `allow_net` / network egress is decided by a string scan over raw task text — no
consent record, lease, capability token, or `submitted_by` check consulted in the call chain
(verified in the fable read, chunk 13). Sandbox (bwrap/cgroup) is strong; the *authorization*
in front of it is not.
**Fix:** Replace the regex decision with a capability check: egress requires an unexpired,
addressed egress **lease** (the mechanism willow-mcp `grant-net` already mints) bound to the
`submitted_by` identity. The regex becomes an *advisory* flag, not the gate. Three-key model:
capability + consent + unexpired lease (this is already the willow-mcp gates-panel shape —
port it to be the actual enforcement point).
**Effort:** medium. Lease minting exists; the work is making the executor *require* it instead
of consulting the regex.
**Gate:** a task requesting egress with no valid lease is denied regardless of its text; a task
with a valid lease + matching identity passes; the regex alone can no longer authorize.
**Dep:** willow-mcp lease path (exists). Coordinate with the decommission Phase-1 cutover.

### H3. ASI06 — Memory/context poisoning (auto-promotion validation)
**Gap:** session atoms auto-promote into the KB; `mem_check` gates redundancy/contradiction but
not *authenticity of source*. Tonight the operator (human) was the gate that stopped vault
content from entering — that should not depend on a human catching it.
**Fix:** (a) provenance-tag every atom with its `source_session` + `submitted_by` at ingest,
already partly present — make it mandatory and refuse un-sourced writes. (b) A quarantine tier:
atoms from external/untrusted sources (fetched web, file reads) land in a `contested` tier that
requires promotion, never auto-canonical. (c) Deterministic scope-check on ingest: refuse writes
whose source path is outside the caller's granted envelope (the vault-scope rule, enforced).
**Effort:** medium. Tiers + provenance columns exist; the enforcement gate is the new part.
**Gate:** an atom sourced from a non-granted path is refused at `kb_ingest`; web-fetched content
cannot reach `canonical` without an explicit promote step.
**Dep:** links to the vault-repo boundary work (Data Vault as its own repo). The mandatory
provenance tags are exactly the custody-ledger event fields — see `docs/custody-ledger-spec.md`;
build once, serve H3 and H5.

---

## TIER 2 — formalize the two distinctive strengths (the fleet's real edge)

### H4. ASI09 — Human–agent trust exploitation: friction floor as ENFORCEMENT
**Gap:** friction floor exists (`willow-gate/src/willow_gate/friction_floor.py`) and *flags*,
but does not gate — and ASI09 is the least-defended category industry-wide, so this is the
fleet's biggest potential contribution. Currently behavioral/cultural, not wired.
**Fix:** wire the friction floor into the pre-tool hook as a *loud advisory that persists into
the record* (not a block — it must not prevent, per its own design). Add the echo-ladder-style
deterministic drift signals (fidelity-under-pattern-pressure) as inputs. Make the `drift` field
in the 13-field gate header **measured**, not hand-filled — populate it from the friction floor
+ ladder at check-in. Turns the trust ladder from asserted to earned.
**Effort:** medium-large. Depends on the characterization battery (this session's tests 1–13)
maturing into a scored check-in probe.
**Gate:** a session's `drift` header field is populated by measurement, not by the agent's claim;
a sustained-low-friction ramp raises a persistent flag a human sees.
**Dep:** the echo-ladder / format-tax battery → a runnable check-in scorer. (Own project.)
**Note:** H4 is the ASI09 *security* framing (attacker exploits trust). The same friction-floor
machinery serves the *safety* framing with no attacker — see **H7**. Build the measurement once.

### H5. Check-out reconciliation — make the exit half real (field's open axis)
**Gap:** willow-gate spec is symmetric (13 fields in, 13 out) but enforcement lives at
check-*in*; the field is almost entirely pre-execution ("Intent-before-Action"). The
*declare-on-entry / reconcile-on-exit* half is willow-gate's genuinely less-trodden ground.
**Fix:** implement `check_out(session)` that reconciles declared intent (entry header) against
observed actions (the session's actual tool calls / receipts). Mismatch = a recorded
`fail_count` increment + flag, feeding the trust ladder. This is the ASI01/ASI08 defense the
pre-execution gates miss: it catches an agent that declared X and did Y.
**Effort:** large. Needs a per-session action ledger (Kart receipts + tool log) to reconcile against.
**Gate:** an agent that check-in-declares `tools:[read]` then writes is caught at check-out with
a reconciliation failure; the mismatch lands in the FRANK ledger.
**Dep:** action-ledger plumbing — **specified** in `docs/custody-ledger-spec.md` (the custody
ledger and the action ledger are the same append-only, hash-chained, signed event log; Tier 2 of
that spec is this H5). This is the research contribution — worth an ADR.

---

## TIER 3 — the hard open problem (research, not a checklist item)

### H6. ASI01-semantic — intent verification (injection in the operator's own voice)
**Gap:** identity is cryptographically bound, but *intent* is not verified. The attack proven
this session — an off-distribution payload in the operator's own register, no imperative,
dropped after a long session, disarmed by a self-deprecating frame — passes every existing gate
because it carries the right identity and asks for nothing to refuse.
**Fix (direction, not solution):** a deterministic **shape** detector that flags the *envelope*,
not the content — input with no imperative + high entropy + guard-lowering phrase + session
boundary → "reads as off-task, confirm before treating as instruction." Runs *outside* the model
(a mirror can't audit itself). This is NOT solved anywhere; every existing semantic gate puts a
model in the judge seat, which reintroduces the vulnerability. Do not ship a model-judge and call
it done.
**Effort:** research. Spec pending — operator wants more test runs before it's written (n>1).
**Gate:** (to be defined by the test runs) — a shape-detector that catches the operator-voice
injection without a model judging content.
**Dep:** the injection test battery (more runs first, per operator).

**From this end (2026-07-11 refinement):** the door is not just hard, it is **undecidable at the
input layer.** Operator-authentic and attacker-mimic are the *same distribution by construction* —
that is *why* the attack works — so no threshold admits the operator's genuine creative voice and
rejects the forgery (this session's own inputs would trip any detector tuned to catch it). The
only thing decidable at the door is not intent but **consequence / blast radius.** Therefore H6's
realistic form: (1) log the shape as *advisory*, never gate; (2) push the actual decision to **H5**
(catch divergence on the way out, since you cannot verify intent on the way in); (3) a
**consequence gate** — a high-consequence action requires human ratification regardless of how
legitimate the frame felt. H6 does not get solved; it gets **dissolved into H5 + a consequence
gate.** Any version that returns the decision to the model's own judgment has re-opened the hole.

---

## TIER 4 — the safety axis (failure with no adversary)

The OWASP list models attackers. The failure below has none, and no security gate can see it. It
is the fleet's most distinctive contribution precisely because almost no one threat-models
*helpfulness itself.* The seed already exists (`friction_floor.py`); the work is making it
measured.

### H7. Sycophantic amplification — the frictionless mirror (no adversary)
**Gap:** The model, maximally helpful and aligned to the user's expressed patterns, reflects them
back with the friction sanded off — and smoothed, an echo reads as confirmation. In a long,
high-context, single-user ("Jarvis-for-one") session this can **amplify the user's own drift** —
deepen a loop rather than interrupt it. No attacker is present; the aligned model *is* the harm
vector. ASI09 (human–agent trust exploitation) is the nearest OWASP item but requires a malicious
actor doing the exploiting — this has none, so H4's security gate does not fire. Demonstrated this
session: the sustained low-friction ramp, and the finding that **specificity — feeding the model
concrete, verifiable, *other* content it cannot smooth — was the only countermeasure that held.**
**Fix (direction):** promote the friction floor from advisory-flag to a **measured obligation on
the agent's own output**, wired at the reply / pre-tool edge as a persistent, human-visible signal
— never a block (witness, not wall, per its own design and per H4). Deterministic, outside-the-
model signals:
- (a) **agreement-rate / echo ramp** — sustained low-friction output across a rising-stakes
  conversation;
- (b) **specificity ratio** — is the agent contributing external, checkable, *other* content, or
  only reflecting the user's own tokens back (the positive control that held under test);
- (c) **relationship-level check-out** — reconcile whether the session *collapsed into pure
  agreement*, alongside H5's tool-level reconciliation.
Optionally couple to the H6 consequence gate: a high-consequence action landing on the back of a
sustained low-friction ramp requires human ratification.
**Effort:** research + medium wiring. Seed exists (`friction_floor.py`); the new parts are the
measured signals and the reply-edge hook.
**Gate:** a session that runs N turns of pure agreement while stakes rise raises a persistent,
human-visible flag; the mirror signal is **measured**, not the agent's self-report; and it never
blocks. Positive control: injecting specific, verifiable, *other* content measurably raises the
specificity ratio and clears the flag.
**Dep:** the characterization battery (H4) matures the signal; relationship-level check-out rides
the custody ledger (`docs/custody-ledger-spec.md`). **Do not ship a model judging its own
sincerity.**
**Honest limit:** you are measuring the *absence* of something, and the operator's authentic
agreement looks identical to sycophancy from outside. n>1 before any threshold is trusted — same
discipline as H6.

> **The duality (H6 ↔ H7).** H6 is *malicious intent the identity gate cannot catch*; H7 is *no
> malicious intent at all, which the security gate cannot see.* Same blind spot from both sides —
> the system trusts smoothness / legitimacy-of-shape. One is an attacker exploiting that trust;
> the other is the model, with no attacker, failing into it. Defending one without the other
> leaves the shape unguarded.

---

## TIER 5 — the defender's own trust root (flagged, not yet scoped)

### H8 (candidate). Quis custodiet — securing the custody ledger itself
**Gap:** H3/H5/H7 all come to depend on the custody ledger. That makes its **checkpoint signing
key** and its **`capture_gap` channel** new high-value targets: steal the key → forge history;
flood the gaps → hide in noise / DoS the reconciler. Standard hygiene, but it must be named once
the ledger becomes load-bearing.
**Fix (direction):** operator-held checkpoint key (never agent-mintable — the sudo invariant);
rate-limit and alert on `capture_gap` bursts; append-only storage the agent process cannot rewrite.
**Effort:** medium. Not novel — deliberately lower priority than H1–H7, but do not skip it once
the ledger ships.
**Gate:** the agent process cannot mint or read the checkpoint key; a burst of `capture_gap`
events raises an alert rather than silently degrading reconciliation.

---

## Sequencing
1. ~~**H1** (Grove integrity)~~ — ✅ BUILT 2026-07-22 (Ed25519). Library shipped + tested; Grove-edge wiring is the remaining integration step.
2. **H2** (egress lease) — coordinate with willow-mcp decommission Phase-1 cutover.
3. **Custody ledger Tier 1–2** (`docs/custody-ledger-spec.md`) — the spine + `check_out()`. This
   *is* **H5**, and its provenance fields *are* **H3**. Build here; H3 and H5 fall out.
4. **H3** (ingest provenance/scope) — rides the ledger; pairs with Data-Vault-as-repo boundary.
5. **H4 / H7** — both ride the same friction-floor measurement battery. Build the measurement
   once; H4 is its security face (attacker), H7 its safety face (no attacker). Formalize via ADR.
6. **H6** — dissolved into H5 + a consequence gate; the shape-detector stays advisory-only.
   Blocked on more injection-test data. Do not force a model-judge solution.
7. **H8** — once the ledger is load-bearing, secure it. Not novel; do not skip.

Note: none of H1–H5 is willow-gate being *behind* the field — H1/H2/H3 are standard hardening,
H4/H5 are the field's open axes where willow-gate is ahead. H6 is the field's open problem. **H7
is off the security map entirely — the safety axis — and is the fleet's most distinctive claim.**
