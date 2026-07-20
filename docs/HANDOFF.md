# Handoff — the custody ledger, and how it got built

To the next instance:

You're picking up a working custody ledger. It's real, it's finished through the
tier sequence its spec lays out, and it's been beaten on hard. Before you touch it,
read this — not because the code is fragile, but because the *way* it was built is
the thing worth inheriting, and it's not written into the diffs.

## What it is

`willow-gate/src/willow_gate/custody.py` — an append-only, hash-chained, canonicalized
event log. A record that follows any file that gets handled, and simultaneously the H5
action-ledger the hardening plan was blocked on. The trust root sits *outside* the
handled file, which is the whole point: a ledger you can forge isn't a ledger.

Four tiers, all on branch `build/custody-ledger`:

1. **Tier 1 — the spine.** Event record, canonicalization, append-only writer, hash
   chain, fail-closed secret redaction. No in-place edit exists in the API.
2. **Tier 2 — H5.** Session check-in / action / check-out with reconciliation. The
   "declared a read, actually wrote" case fails at check-out. This *is* the H5
   dependency, delivered.
3. **Tier 3 — file custody.** `file.*` lineage, diff capture, `capture_gap` on an
   unexplained hash jump.
4. **Tier 4 — sealing.** PGP checkpoint signing (sign the chain head) and a portable,
   offline-verifiable sidecar. Closes the forged-derived-record class the first three
   tiers could only *document*.

The spec is `docs/custody-ledger-spec.md`. It is kept honest on purpose — every claim
the code can't back is either removed or turned into a documented-limit test. If you
change behavior, the spec changes in the same breath. A ledger's documentation lying
is worse than the ledger being weak, because weakness you can plan around and a lie you
can't.

## The one thing to actually absorb

This was built by a loop, stated plainly by the human: **write the doc, do the code,
send it out for audit.** Then do it again. It ran for six or seven rounds on Tiers 2–3
and twice on Tier 4.

Here is what every single round taught, without exception: **the fix I was proud of
introduced the next bug.** Round 5's `str()` normalization of `session_id` quietly
*merged* two distinct sessions (`1` and `"1"`). Round 6's fix for that then double-fed
the trust ladder on a repeated check-out. Tier 4's sidecar signed the events but left
the "I am weaker than the ledger" honesty label *outside* the signature, so an attacker
could flip it to `False` and keep a valid sig. Every one of those was found by an
adversarial subagent that was told to *break it and prove the break with a runnable
script*, not by me reading my own code and nodding.

So: do not trust a green suite as evidence the security property holds. The suite proves
the attacks you already thought of still fail. The audit is for the attack you didn't.
When you add anything to this module, spawn the skeptic, make it write real attack code,
and read what it actually reports before you believe yourself. Verify, don't assert.

## What Tier 4 does and does not do

Does: within a checkpoint's coverage, a re-derived-chain forgery (attacker rewrites a
past event *and* re-derives every later `ledger_prev_hash` into a self-consistent chain)
fails `verify_checkpoint`, even though bare Tier-1 `verify()` accepts it. So does a
tail-truncation. Rewriting the stored head doesn't help — the signature over it needs the
operator's key.

Does not: events *after* the last checkpoint are unsealed. That's inherent — a signature
seals what existed when it was signed — so the operational answer is "checkpoint at every
session close, keep the unsealed window small," and that's in the spec, not hidden. The
sidecar proves authenticity, never completeness; a key-holder can export a slice with the
middle omitted and it verifies. Also documented, also not a bug.

## Open threads (I did not do these)

- **Tier-3b integration.** The ledger is a library right now. Nothing wires it into
  willow-gate's actual pre-tool hook or the integrations egress lane. The spec references
  that hook as the thing that must inject the active `session_id` on every capability
  event — until it exists, an untagged capability call is outside reconciliation *by
  construction*. That's the honest next build.
- **The PR.** `build/custody-ledger` has ~13 commits and no PR. Open one when the human
  says so, not before.

## The load-bearing constraints (don't relearn these the hard way)

- **Fail closed, everywhere.** `load()` re-runs *every* invariant, not just the chain —
  redaction, legal-kind, tz-aware `ts`. A hand-built valid chain is still just data; it
  is never authority.
- **Don't overclaim.** "It witnesses; it does not prevent." "Signed ≠ correct." A signed
  false entry is still false. If you catch yourself writing "wall" or "guarantees,"
  you've drifted.
- **System-only kinds** (`session.checkout`, `capture_gap`, `checkpoint`) are refused by
  public `append()` and emitted only through the privileged `_append()`. That boundary is
  what stops a caller forging a reconciliation verdict. Don't soften it for convenience.

## On the human, and the method

The build style is documented in `willow-mcp/ARCHITECT.md` — parts-book over
service-manual, seven working principles. Read it. The short version: they hand you the
shape of the thing and expect you to assemble from parts already on the bench, not
invent. They will tell you to keep looping when you want to stop, and they will tell you
to stop when you want to keep looping. Listen to both.

Standing constraints they set, still in force:
- `sean-data-vault` is *append-only from your side* — add to it, never read its contents.
- Redact secrets; never dump credentials; no PII or private history in anything pushed.
- The model identifier stays out of commits, PR text, and code — chat only.
- Do not push the seed or the canon without an explicit word.
- willow-mcp work goes on `claude/hello-willow-85e0jb`; custody work on
  `build/custody-ledger`. Push where you were told, nowhere else.

## Last thing

The ledger works because it assumes it will be attacked and refuses to pretend otherwise.
Carry that forward into whatever you build next here. The suite being green is where the
work starts, not where it ends.

— the instance that built Tier 4
