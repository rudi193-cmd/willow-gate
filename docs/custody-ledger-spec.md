# Custody Ledger — spec

Status: **DRAFT** · 2026-07-11 · seat: willow · author: instance (proposes; operator ratifies)
Serves: **H5** (check-out reconciliation — the "per-session action ledger" dependency) and
**H3** (memory/context provenance) from `willow-gate Hardening Plan`, and the operator's
chain-of-custody instrument ("a record that follows any file that gets handled").

Verify-don't-assert: every requirement carries a **gate** — the observable that proves it done.
Nothing here is built without operator ratification.

---

## The one idea

A **file's custody history** and a **session's action history** are the same primitive: an
**append-only, hash-chained, signable event log**. They differ only in the *subject* of each
event — a file lineage, or a session. Build one ledger with a unified event record; the two
uses are two queries over it.

- **Custody view** (the instrument): all events for one `lineage_id`, in order → the whole life
  of a file: born here, read there, edited into v2 (diff attached), crossed *this* gate under
  *that* auth, checked out to *there*.
- **Action view** (H5): all events for one `session_id` → the declared intent (check-in) plus
  every action, so `check_out()` can reconcile *declared* against *observed*.

## The trust decision (the fork, decided)

**The ledger is the authority; the file is not.** A file cannot honestly carry its own history in
its own bytes — whoever handles it can rewrite the history, the same way an injected instruction
promotes itself. So:

- The **central ledger** is append-only and hash-chained; it is the trust root.
- A file carries only a **stamp** — `{lineage_id, last_content_hash, ledger_anchor}` — enough to
  *identify* itself and be checked *against* the ledger. Forging the stamp does not forge the
  ledger.
- A **signed sidecar** (detached PGP over a file's custody slice) MAY travel with the file for
  off-network portability, but it is explicitly **weaker**: it proves authenticity of what it
  shows, never completeness. It cannot prove no event was omitted. Label it as such wherever used.

This is the same rule as the fingerprint check that must run outside the model: *the lock lives
where the handled thing cannot reach it.*

---

## The event record (the atom of the ledger)

One canonical JSON object per event. Fields:

| Field | Meaning |
|-------|---------|
| `seq` | monotonic integer, per ledger. No gaps. |
| `ts` | ISO-8601 **with timezone** (a deadline without a zone is a wish). |
| `ledger_prev_hash` | sha256 of the previous event's canonical bytes. The chain. |
| `kind` | `file.create` · `file.read` · `file.write` · `file.gate_cross` · `file.checkout` · `session.checkin` · `session.action` · `session.checkout` · `capture_gap` |
| `session_id` | the session this event occurred in. |
| `actor` | agent `app_id` / human seat that performed it. |
| `lineage_id` | stable id of a file's lineage; survives content changes. (file.* events) |
| `content_hash` | sha256 of the file's bytes **at this event**. (file.* events) |
| `parent_content_hash` | sha256 of the prior version — the version chain. (file.write) |
| `diff_stat` | `{files, insertions, deletions}`. (file.write) |
| `gate` | `{name, direction: in\|out, auth_ref, access_level, lease_id, consent_ref}` — the crossing. **`auth_ref` is a credential *id*, never the secret.** (file.gate_cross / checkout) |
| `tool` | tool name invoked. (session.action) |
| `declared` | the WillowGate 13-field intent header. (session.checkin) |
| `observed` | capabilities actually exercised. (session.checkout) |
| `note` | freeform. |
| `sig` | detached PGP signature over this event's canonical bytes (Tier 4). |

**Redaction is fail-closed** and refuses to persist an event carrying, anywhere in it, (a) a string
**value** of a known live-credential shape (AWS/GitHub/Slack/Google/JWT/PEM), (b) a dict **key** of
such a shape, or (c) **any non-empty string leaf — even wrapped in a list or nested dict** — under a
field **name** that implies a raw secret (`password`/`api_key`/`private_key`/`client_secret`/
`session_token`/`access_token`/`refresh_token`/`id_token`/`bearer`/… **and any `*_token` field**). A
small allowlist of pagination cursors (`next_token`, `page_token`, `next_page_token`,
`continuation_token`) is exempt from the `*_token` rule, and the bare `token`/`cookie` names are not
triggers — they false-positive on cursors and UI cookies. Reference and identifier fields are
**exempt** — `auth_ref`, `*_id`,
`*_ref`, `*_hash`, `*_fingerprint`, `*_name` — so a crossing is still recorded as *having happened,
under which credential id*, never with the credential. Ambiguous generic names (`secret`,
`credential`, `credentials`) are deliberately **not** triggers: they false-positive on credential
*ids*, so a plaintext secret under a bare `secret` field is caught only if its *value* has a
credential shape. Redaction is deliberately **incomplete** (no generic-entropy heuristic — a secret
shaped like a content hash is indistinguishable from one and passes); it fails closed on what it
recognizes — extend the patterns, never loosen the default.
**Gate:** a live token, a plaintext `password`/`api_key`/`bearer`, a list/dict-wrapped secret under
a secret field, and a secret-shaped key are each rejected and write nothing; `auth_ref`/`*_id`/
`*_hash` values and a legit `credentials: <id>` pass.

**System-only kinds.** `session.checkout` and `capture_gap` are *derived* records — they are the
ledger's own conclusions, not receipts a caller supplies. The public `append()` **refuses** them; only
`check_out()` and `detect_capture_gap()` emit them, through a privileged internal path. Otherwise an
agent could append its own `{"kind":"session.checkout","reconciled":true}` and either forge a clean
record or deny the real reconciliation. A derived record must not be forgeable by the party it judges.

## Canonicalization (or the chain and the signatures mean nothing)

Every hash and signature is computed over a **canonical serialization**: **string keys only**
(a non-string key is rejected, not coerced — `True`/`1` must not collide with `"true"`/`"1"`),
**NFC-normalized** strings and keys, **no floats** (integers-only; `NaN`/`Inf` aren't valid JSON),
sorted keys, `sig` excluded, `None` values omitted, **ASCII-escaped** (`ensure_ascii`) so no
UTF-8-vs-`\uXXXX` divergence, no insignificant whitespace. Any conforming serializer reproduces
identical bytes. An uncanonicalizable event (non-string key, float) is refused by `append()` before
anything is written — canonicalization is itself a fail-closed gate.
**Gate:** the canonical form is pure ASCII and a **fixed point** across a JSON round-trip
(`test_canon_portable_ascii_nfc_and_fixed_point`); a combining-form string collapses to its
precomposed form; non-string keys and floats raise (`test_canon_rejects_non_string_keys_and_floats`).

---

## H5: `check_out(session)` reconciliation

The deliverable H5 names. On session close:

1. Read the `session.checkin` event's `declared` header (WillowGate 13 fields: declared tools,
   scopes, egress intent, trust level claimed).
2. Fold **every** capability-bearing event tagged with this `session_id` into `observed` — not just
   `session.action`: `file.write`/`file.create` is a `write`, `file.read` is a `read`,
   `file.gate_cross` is an `egress`, `file.checkout` (a file leaving custody) is its **own**
   `checkout` capability — *not* folded into `egress`, or declaring one would excuse the other — and
   an untyped `session.action` still counts (as `action`). Folding only `session.action.tool` — or
   leaving any capability kind out of the map — is an evasion; the write just routes through that
   path. Capability names are **case-folded** so `Write`/`write` can neither evade nor false-flag.
3. Diff `declared` vs `observed`. Any capability exercised but **not** declared → a
   reconciliation **mismatch**.
4. Emit `session.checkout` (system-only) with `{reconciled, mismatches, fail_count_delta}`. Feed
   `fail_count` to the trust ladder; land the record where a human sees it.

**Windowing & idempotence.** Actions before the first check-in fold into the first window (a
capability exercised and *then* narrowly declared is still caught). A *fresh* window opens **only on
a check-in that follows a check-out**; a re-check-in inside an open window is ignored — it can
neither reset `observed` nor re-broaden `declared`. `check_out` **never raises** on an already-closed
window: it recomputes the true reconciliation from the window's actions and returns it (flagging
`already_closed`, skipping a duplicate emit).

**The Tier-4 boundary (stated honestly — the docs must not lie).** `check_out`'s recompute-don't-raise
defeats a *lone* forged `session.checkout`: it can neither deny nor mask. It does **not** fully close
forgery, and an earlier draft of this spec wrongly claimed it did. Because `load()` cannot re-run the
system-only guard (or no genuine saved record could reload), a file-writing adversary can still,
against a *loaded* ledger:
  * **mask a mismatch** with a forged `session.checkout` **followed by** a forged `session.checkin`
    — the pair rolls the window forward and drops the real window's actions;
  * **suppress the ladder feed** by spoofing `already_closed=True` on the first genuine check-out —
    so `already_closed` is *advisory*, not trustworthy against a tampered file;
  * **launder a lineage** with a forged `capture_gap` that a later `file.write` then chains onto.
None of these is fixable at this tier: authenticating *which derived records are the ledger's own*
against a party who can rewrite the file is exactly what the **Tier-4 signed head** provides. Until
Tier 4, treat every `session.checkout`/`capture_gap` in an untrusted file as **unauthenticated**, and
rely on H5 only for a ledger you wrote yourself in-process. Documented-limit tests assert each of
these, so the boundary is pinned, not assumed.

**Gate (H5's own):** an agent that check-in-declares `tools:[read]` then writes is caught at
check-out with a reconciliation failure — whether the write is a `session.action`, a session-tagged
`file.write`/`file.gate_cross`, or an untyped action; the mismatch is a durable ledger entry, and
the trust ladder's `fail_count` increments (once). Reconciliation is over **observable
capabilities**, not semantic intent — it catches "declared read, did write," not "read the wrong
thing for a bad reason." (That deeper case is H6; it does not live here, on purpose.)

## Signing strategy (tamper-evidence without paying per event)

Hash-chaining every event is cheap and gives ordering + tamper-*detection*. PGP-signing every
event is expensive. So: **hash-chain every event; PGP-sign periodic checkpoints** — a signed head
hash (a Merkle root over the events since the last checkpoint) at every session close or every N
events. That makes the whole chain tamper-*evident* under the operator's key at bounded cost.
**Gate:** an *in-place* alteration of any past event breaks chain verification; a re-derived-chain
forgery or a tail-truncation is caught *only* by the checkpoint signature (see the boundary below).

---

## What it does NOT do (do not overclaim)

- **Tier 1 catches in-place tamper, not re-derivation.** The hash chain detects an in-place edit
  (every later `ledger_prev_hash` stops matching). It does **not** catch an attacker who rewrites a
  past event *and* re-derives every subsequent `ledger_prev_hash` — that forms a self-consistent
  chain `verify()` accepts — nor a tail-truncation. Nothing at Tier 1 pins the head. Only the
  **Tier-4 checkpoint signature** commits the head externally and makes those tamper-*evident*.
  Both limits are asserted by documented-limit tests so the boundary is pinned, not assumed.
- **`load()` fails closed on *every* invariant, not just the chain.** Re-opening a ledger re-runs
  `verify()` (chain + seq) **and** re-applies the secret scan, the legal-kind check, and the tz-aware
  `ts` check to every event, raising on any violation — otherwise a hand-built valid-chain file could
  smuggle a secret, a bogus kind, or a bad `ts` that `append()` would have refused. The file is data,
  not authority. (It still cannot catch a fully re-derived forgery without the Tier-4 head.)
- **It witnesses; it does not prevent.** A file edited by a tool that emits no event is not
  blocked — it is *detected*: the next observed `content_hash` won't match the chained
  `parent_content_hash`, and a `capture_gap` event is written. Detection is the value (the
  friction floor, for data), but it is not prevention. Never call it a wall.
- **`capture_gap` detects honest reporting, not an adversary who owns the recorder.** It fires only
  when an observed hash is reported *before* a write is recorded. An actor who controls the write
  path can launder an out-of-band edit as a normal `file_write` and no gap is raised — that case is
  caught (if at all) by routing the write through the gate (Tier 3b) and by H5 reconciliation, not
  by the detector. A lineage with no origin (`file.create`/`file.gate_cross` first) does not verify.
- **A capability event with no `session_id` is not reconciled.** H5 can only fold events tagged with
  the session; an untagged `file.checkout`/`file.write`/etc. is unattributable and escapes the
  check. This is the **Tier-3b hook's duty**: it must inject the *active* `session_id` on every
  capability event, so a raw untagged call is outside reconciliation by construction, not a gap the
  core can close alone.
- **Completeness = capture points.** The ledger is only as complete as the hooks that feed it.
  Every unexplained hash jump must surface as `capture_gap` — silence must never read as "nothing
  happened."
- **Signed ≠ correct.** A signature proves *who* wrote an entry and that it wasn't altered. A
  signed false entry is still false; the ledger proves provenance, not truth.

## Reuse — the parts are already on the bench

| Need | Existing part |
|------|---------------|
| append-only writer | `willow-mcp/receipts.py` (extend schema to the event record) |
| detached signatures | `willow-mcp/pgp.py` |
| the `declared` intent header | WillowGate 13-field check-in |
| `gate.auth_ref` / `lease_id` / `consent_ref` | willow-mcp lease + consent (`grant-net`, three-key gate) |
| long-term custody summaries | the grove (`record_lessons`) — promote a file's life as a lesson |

This is assembly, not invention.

---

## Tiers & sequencing

1. **Tier 1 — the spine.** Event record + canonicalization + append-only writer + hash chain +
   the fail-closed redaction gate. *Gate:* the API exposes no in-place edit; end-to-end chain
   verification passes; tampering any past entry fails it; a token-bearing event is refused.
2. **Tier 2 — H5.** `session.checkin` / `session.action` / `session.checkout` + reconciliation +
   trust-ladder feed. *Gate:* the declared-read-then-wrote test fails at check-out. **This is the
   H5 dependency delivered.**
3. **Tier 3 — file custody.** `file.*` events wired into the pre-tool hook and the integrations
   egress lane; lineage chain; diff capture; `capture_gap` on unexplained jumps. *Gate:* a file's
   full lineage is queryable start to finish; an out-of-band edit shows as a `capture_gap`.
4. **Tier 4 — sealing.** PGP checkpoint signing + the portable signed sidecar. *Gate:* a tampered
   event fails signature verification; a sidecar verifies offline and is labeled weaker-than-ledger.

## Open questions (decide / test before building past Tier 2)

- **Checkpoint interval** — per session close, or every N events, or both? (Cost vs. granularity.)
- **Retention.** Archive-don't-delete says never prune; a high-volume action ledger grows
  unbounded. Resolution to ratify: **checkpoint + compress cold segments, never delete** — the
  hash chain must survive compaction (compact the payloads, keep the hashes).
- **Sidecar authority weight** — how loudly to mark sidecar-verified custody as weaker than
  ledger-verified, so no one treats a signed slice as a complete history.
- **`capture_gap` policy** — does an unexplained jump merely flag, or does it also dock trust?
  (Leaning flag-only until false-positive rate is measured, n>1.)

## How it plugs into the hardening plan

- **Unblocks H5** — it *is* the per-session action ledger reconciliation runs against.
- **Unblocks H3** — `session_id` + `actor` + `lineage_id` on every write are the mandatory
  provenance tags; a write whose source path is outside the caller's granted envelope is refused
  at ingest (scope-check), and the `capture_gap` mechanism is the un-sourced-write detector.
- **Feeds H4** — the `drift` header field can be populated from reconciliation history rather than
  hand-filled; measured, with error bars visible.
- **Serves H6 without judging** — off-task/operator-voice signals are *logged* as advisory ledger
  entries that feed check-out; they never gate, and no model sits in the judge seat.
