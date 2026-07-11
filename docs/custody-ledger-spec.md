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

**Redaction is fail-closed:** the writer refuses to persist an event whose `gate.auth_ref` or any
field matches a secret pattern (key/token/secret/password). A crossing is recorded as *having
happened, under which credential id* — never with the credential.
**Gate:** a unit test submits an event carrying a live-looking token; the writer rejects it and
writes nothing.

## Canonicalization (or the chain and the signatures mean nothing)

Every hash and signature is computed over a **canonical serialization**: sorted keys, UTF-8, no
insignificant whitespace, integers not floats, explicit null policy. Two independent serializers
must produce byte-identical output.
**Gate:** `test_canonical_form_is_byte_stable` — an event round-tripped through two serializers
hashes identically; reordering input keys does not change the hash.

---

## H5: `check_out(session)` reconciliation

The deliverable H5 names. On session close:

1. Read the `session.checkin` event's `declared` header (WillowGate 13 fields: declared tools,
   scopes, egress intent, trust level claimed).
2. Fold the session's `session.action` events into `observed` — the set of capabilities actually
   exercised (tools called, scopes touched, gates crossed).
3. Diff `declared` vs `observed`. Any capability exercised but **not** declared → a
   reconciliation **mismatch**.
4. Emit `session.checkout` with `{reconciled: bool, mismatches: [...], fail_count_delta}`. Feed
   `fail_count` to the trust ladder; land the record where a human sees it.

**Gate (H5's own):** an agent that check-in-declares `tools:[read]` then writes is caught at
check-out with a reconciliation failure; the mismatch is a durable ledger entry, and the trust
ladder's `fail_count` increments. Reconciliation is over **observable capabilities**, not
semantic intent — it catches "declared read, did write," not "read the wrong thing for a bad
reason." (That deeper case is H6; it does not live here, on purpose.)

## Signing strategy (tamper-evidence without paying per event)

Hash-chaining every event is cheap and gives ordering + tamper-*detection*. PGP-signing every
event is expensive. So: **hash-chain every event; PGP-sign periodic checkpoints** — a signed head
hash (a Merkle root over the events since the last checkpoint) at every session close or every N
events. That makes the whole chain tamper-*evident* under the operator's key at bounded cost.
**Gate:** altering any past event breaks chain verification; altering an event before a signed
checkpoint additionally fails the checkpoint signature.

---

## What it does NOT do (do not overclaim)

- **It witnesses; it does not prevent.** A file edited by a tool that emits no event is not
  blocked — it is *detected*: the next observed `content_hash` won't match the chained
  `parent_content_hash`, and a `capture_gap` event is written. Detection is the value (the
  friction floor, for data), but it is not prevention. Never call it a wall.
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
