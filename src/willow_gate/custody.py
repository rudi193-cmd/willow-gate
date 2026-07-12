#!/usr/bin/env python3
"""custody.py — the custody ledger, Tier 1: the spine.

An append-only, hash-chained event log. It is the trust root that a handled file
cannot rewrite: the file carries only a fingerprint stamp; the truth lives here,
where the thing being tracked can't reach it. Same rule as the friction floor and
the fingerprint check — the lock lives outside the thing it locks.

This module is Tier 1 of `docs/custody-ledger-spec.md` and nothing more. It gives
you four properties, each with a test that proves it:

  * APPEND-ONLY by construction. There is no update() and no delete(). The only
    write is append(); the history cannot be edited through this API.
  * HASH-CHAINED. Every event carries the hash of the one before it, so an
    IN-PLACE alteration of any past event breaks verification of every event
    after it. NOTE the boundary: an attacker who rewrites a past event AND
    re-derives every subsequent ledger_prev_hash produces a self-consistent
    chain that verify() accepts, and a tail-truncation also passes — nothing here
    pins the head. Detecting those requires the Tier-4 checkpoint signature that
    commits the head externally. Tier 1 gives tamper-detection for in-place
    edits; Tier 4 gives tamper-evidence for the whole chain.
  * CANONICAL. Hashes are computed over a byte-stable canonical form (sorted
    keys, compact, UTF-8, nulls omitted). Reordering input keys cannot change a
    hash — otherwise the chain and any future signature would be meaningless.
  * FAIL-CLOSED on secrets. append() refuses any event carrying a value that
    looks like a live credential and writes nothing. A gate crossing is recorded
    as having happened under a credential *id*, never with the credential.

Honest limits, stated up front because the rule is don't overclaim:

  * It WITNESSES, it does not PREVENT. Nothing here stops a file being edited by
    something that emits no event; later tiers only *detect* that (a hash jump
    with no explaining event). Tier 1 is just the trustworthy log.
  * Redaction is pattern-based and therefore incomplete. It uses specific,
    high-confidence credential shapes on purpose — it deliberately does NOT flag
    generic long/hex strings, because those are exactly what content hashes look
    like, and a redactor that ate its own chain fields would be worse than none.
    It fails closed on what it recognizes; extend the patterns, never loosen the
    default.
  * A signed/verified chain proves provenance and integrity, not truth. A
    faithfully recorded false statement is still false.

Signing (PGP checkpoints) is Tier 4 and is not here. Session check-in/check-out
reconciliation (H5) is Tier 2 and is not here. This is the spine only.
"""
from __future__ import annotations

import json
import hashlib
import re
import unicodedata
from datetime import datetime
from dataclasses import dataclass
from typing import Any, Iterator, Optional

# The chain's base case — the hash a first event points back to. The recursion
# stops here; this is the floor, and it is not a real event's hash.
GENESIS = "0" * 64

# Event kinds. Tier 1 stores any of them faithfully; the *meaning* of the
# session.* and file.* kinds is given teeth in Tiers 2 and 3.
KIND_FILE_CREATE = "file.create"
KIND_FILE_READ = "file.read"
KIND_FILE_WRITE = "file.write"
KIND_FILE_GATE_CROSS = "file.gate_cross"
KIND_FILE_CHECKOUT = "file.checkout"
KIND_SESSION_CHECKIN = "session.checkin"
KIND_SESSION_ACTION = "session.action"
KIND_SESSION_CHECKOUT = "session.checkout"
KIND_CAPTURE_GAP = "capture_gap"
KIND_CHECKPOINT = "checkpoint"   # Tier 4: a signed head hash

# The closed set of legal kinds. append() refuses anything else.
_KINDS = frozenset({
    KIND_FILE_CREATE, KIND_FILE_READ, KIND_FILE_WRITE, KIND_FILE_GATE_CROSS,
    KIND_FILE_CHECKOUT, KIND_SESSION_CHECKIN, KIND_SESSION_ACTION,
    KIND_SESSION_CHECKOUT, KIND_CAPTURE_GAP, KIND_CHECKPOINT,
})

# Derived records the ledger concludes for itself — NOT receipts a caller may
# supply. The public append() refuses them; only check_out()/detect_capture_gap()
# /checkpoint() emit them, so the party being judged cannot forge or pre-empt the
# judgement.
_SYSTEM_KINDS = frozenset({KIND_SESSION_CHECKOUT, KIND_CAPTURE_GAP, KIND_CHECKPOINT})

# Which capability a session-tagged event exercises, for H5 reconciliation. A
# capability recorded through ANY of these paths — not just session.action —
# must be reconciled, or the check can be evaded by routing it through another
# kind. file.checkout is a file LEAVING custody: an egress-class capability.
_CAPABILITY_BY_KIND = {
    KIND_FILE_CREATE: "write",
    KIND_FILE_WRITE: "write",
    KIND_FILE_READ: "read",
    KIND_FILE_GATE_CROSS: "egress",
    KIND_FILE_CHECKOUT: "checkout",   # distinct: declaring egress must not excuse a checkout
}

# Fields the writer owns. A caller may not set these; the ledger assigns them.
_RESERVED = ("seq", "ledger_prev_hash")
# Excluded from the canonical bytes: a signature is computed *over* the canonical
# form, so it cannot also be part of it.
_UNSIGNED = ("sig",)


class SecretRefused(Exception):
    """append() refused an event because a value looked like a live secret."""


class ChainError(Exception):
    """The ledger failed its own integrity check."""


# --- secret detection (fail-closed on what it recognizes) -------------------
# Specific, high-confidence credential shapes only. These do NOT match a 64-char
# hex content hash, which is why generic entropy heuristics are deliberately
# absent at Tier 1 (see module docstring).
_SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),                       # AWS access key id
    re.compile(r"ghp_[A-Za-z0-9]{36}"),                    # GitHub PAT (classic)
    re.compile(r"gh[ousr]_[A-Za-z0-9]{36}"),               # GitHub oauth/server/user
    re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),           # GitHub fine-grained PAT
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),           # Slack token
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),                 # Google API key
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),     # PEM private key
    re.compile(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}"),  # JWT
)


# Field names that strongly imply a *raw* secret value rather than a reference.
# Deliberately EXCLUDES the ambiguous generics `secret`/`credential`/`credentials`
# — they false-positive on credential *ids* (a field literally named `credentials`
# often holds an id). A plaintext secret under a bare `secret` field is caught only
# if its value has a credential shape. Any field ending `_token` is also treated as
# secret-bearing (session_token, auth_token, …); use `token_id`/`token_ref` for ids.
_SECRET_FIELD_NAMES = frozenset({
    "password", "passwd", "passphrase", "secret_key", "api_key", "apikey",
    "apisecret", "client_secret", "private_key", "privatekey", "access_token",
    "auth_token", "session_token", "bearer",
})
# Suffixes that mark a field as a reference/identifier, NOT a raw secret — these
# are exempt from the field-name rule (e.g. auth_ref, content_hash, *_id).
_ID_SUFFIXES = ("_ref", "_id", "_hash", "_fingerprint", "_name")


def looks_like_secret(value: str) -> bool:
    """True if a string matches a known live-credential shape."""
    return any(p.search(value) for p in _SECRET_PATTERNS)


# Pagination cursors etc. that end in `_token` but are NOT secrets — exempt from
# the `*_token` rule so they don't false-positive.
_BENIGN_TOKEN_FIELDS = frozenset({
    "next_token", "page_token", "next_page_token", "continuation_token",
})


def _is_secret_field(key: str) -> bool:
    k = key.strip().lower()   # strip so "access_token " (trailing space) can't dodge
    if k.endswith(_ID_SUFFIXES):
        return False
    if k in _SECRET_FIELD_NAMES:
        return True
    # Any `*_token` field is secret-bearing (refresh_token, id_token, csrf_token,
    # access_token, …) EXCEPT the pagination-cursor allowlist. The bare `token`
    # and `cookie` names remain non-triggers (they false-positive too broadly).
    return k.endswith("_token") and k not in _BENIGN_TOKEN_FIELDS


def _has_string_leaf(v: Any) -> bool:
    """True if v is, or contains anywhere, a non-empty string — so a secret can't
    duck the field-name rule by hiding in a list or nested dict."""
    if isinstance(v, str):
        return bool(v.strip())
    if isinstance(v, dict):
        return any(_has_string_leaf(x) for x in v.values())
    if isinstance(v, (list, tuple)):
        return any(_has_string_leaf(x) for x in v)
    return False


def scan_for_secrets(obj: Any, path: str = "") -> Optional[str]:
    """Return the dotted path of the first secret the event must not carry, or
    None. Flags (a) any string VALUE of a known credential shape, (b) any KEY of
    a credential shape, and (c) any non-empty string leaf — even wrapped in a
    list/dict — under a field NAME that implies a raw secret, while exempting
    reference fields (auth_ref, *_id, *_hash) that legitimately hold credential
    *ids*."""
    if isinstance(obj, str):
        return f"{path} (credential-shaped value)" if looks_like_secret(obj) else None
    if isinstance(obj, dict):
        for k, v in obj.items():
            here = f"{path}.{k}" if path else str(k)
            if isinstance(k, str) and looks_like_secret(k):
                return f"{here} (credential-shaped key)"
            if isinstance(k, str) and _is_secret_field(k) and _has_string_leaf(v):
                return f"{here} (secret-implying field name)"
            hit = scan_for_secrets(v, here)
            if hit:
                return hit
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            hit = scan_for_secrets(v, f"{path}[{i}]")
            if hit:
                return hit
    return None


# --- canonicalization -------------------------------------------------------
def _canonical_obj(obj: Any) -> Any:
    """Normalize a value for canonicalization so that ANY conforming serializer
    reproduces identical bytes:

      * strings are NFC-normalized (Unicode-equivalent strings can't diverge);
      * dict keys must be strings (json would silently coerce True/1 -> "true"/
        "1", colliding distinct events) and are NFC-normalized;
      * None values are omitted (absent == null);
      * floats are rejected (the spec is integers-only; NaN/Inf aren't even valid
        JSON), so no serializer-dependent float formatting can leak in.

    bool is intentionally preserved (JSON true/false is distinct from 1/0)."""
    if obj is None or isinstance(obj, bool) or isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        raise ValueError("floats are not canonicalizable; use integers")
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError(f"non-string dict key {k!r} is not canonicalizable")
            if v is None:
                continue
            out[unicodedata.normalize("NFC", k)] = _canonical_obj(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [_canonical_obj(v) for v in obj]
    raise ValueError(f"uncanonicalizable type {type(obj).__name__}")


def canonicalize(event: dict) -> bytes:
    """Byte-stable canonical form of an event: signature excluded, nulls omitted,
    NFC strings, string keys only, no floats, keys sorted, no insignificant
    whitespace, ASCII-escaped. Two conforming serializers produce identical
    bytes — the property the hash chain and any Tier-4 signature depend on."""
    body = {k: v for k, v in event.items() if k not in _UNSIGNED}
    body = _canonical_obj(body)
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def event_hash(event: dict) -> str:
    """sha256 of the canonical form, hex."""
    return hashlib.sha256(canonicalize(event)).hexdigest()


def _validate_ts(ts: Any) -> None:
    """A timestamp, if present, must be a timezone-aware ISO-8601 string — a
    deadline without a zone is a wish."""
    if not isinstance(ts, str):
        raise ValueError(f"ts must be an ISO-8601 string: {ts!r}")
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        raise ValueError(f"ts must be ISO-8601: {ts!r}")
    if dt.tzinfo is None:
        raise ValueError(f"ts must be timezone-aware: {ts!r}")


@dataclass
class VerifyResult:
    ok: bool
    reason: str = ""
    at_seq: Optional[int] = None

    def __bool__(self) -> bool:
        return self.ok


class CustodyLedger:
    """An append-only, hash-chained event log.

    Deliberately exposes no mutation of past entries: `append` is the only write.
    Optionally persists to a JSONL file (opened append-only); the in-memory chain
    and the file agree, and either can be verified.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        self._events: list[dict] = []
        self._head: str = GENESIS
        self._path = path

    # -- the only write ------------------------------------------------------
    def append(self, event: dict, *, ts: Optional[str] = None) -> dict:
        """Validate, redact-scan (fail closed), chain, and append one event.

        Raises SecretRefused (writing nothing) if any value looks like a live
        credential. Raises ValueError on a reserved-field collision or missing
        kind."""
        if event.get("kind") in _SYSTEM_KINDS:
            raise ValueError(
                f"kind {event.get('kind')!r} is system-only — it is emitted by the "
                f"ledger (check_out / detect_capture_gap), not appended by a caller"
            )
        return self._append(event, ts=ts)

    def _append(self, event: dict, *, ts: Optional[str] = None) -> dict:
        """The privileged writer. `append` is the caller-facing wrapper that adds
        the system-only-kind guard; the ledger's own derived records go through
        here directly."""
        if "kind" not in event:
            raise ValueError("event requires a 'kind'")
        if event["kind"] not in _KINDS:
            raise ValueError(f"unknown kind {event['kind']!r}")
        for r in _RESERVED:
            if r in event:
                raise ValueError(f"caller may not set reserved field {r!r}")
        if "sig" in event and not isinstance(event["sig"], str):
            raise ValueError("sig must be a string")

        # Fail closed BEFORE any state changes: nothing is written on refusal.
        hit = scan_for_secrets(event)
        if hit is not None:
            raise SecretRefused(f"possible secret refused at {hit}")

        stored = dict(event)
        stored["seq"] = len(self._events)
        stored["ledger_prev_hash"] = self._head
        if ts is not None:
            stored["ts"] = ts
        if "ts" in stored:
            _validate_ts(stored["ts"])

        # canonicalize() raises on an uncanonicalizable event (non-string key,
        # float) BEFORE anything is appended — so those also fail closed.
        h = event_hash(stored)
        # Persist BEFORE mutating memory, using the SAME ASCII policy as the hash,
        # so a failed/unencodable write can never leave memory ahead of disk.
        if self._path:
            line = json.dumps(stored, ensure_ascii=True)
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        self._events.append(stored)
        self._head = h
        return dict(stored)

    # -- verification --------------------------------------------------------
    def verify(self) -> VerifyResult:
        """Recompute the chain end to end."""
        prev = GENESIS
        for i, ev in enumerate(self._events):
            if ev.get("seq") != i:
                return VerifyResult(False, "non-contiguous seq", i)
            if ev.get("ledger_prev_hash") != prev:
                return VerifyResult(False, "broken hash chain", i)
            prev = event_hash(ev)
        return VerifyResult(True, "ok")

    @property
    def head_hash(self) -> str:
        """The current chain head — what a checkpoint signature would cover."""
        return self._head

    # -- read-only access ----------------------------------------------------
    def __len__(self) -> int:
        return len(self._events)

    def __iter__(self) -> Iterator[dict]:
        return iter(dict(e) for e in self._events)

    def events(self) -> list[dict]:
        return [dict(e) for e in self._events]

    @classmethod
    def load(cls, path: str) -> "CustodyLedger":
        """Rebuild a ledger from its JSONL file and VERIFY it — fail closed. A
        tampered or truncated file raises ChainError rather than loading as
        valid; the file is data, not authority. (Tamper that re-derives the whole
        chain is only caught once a Tier-4 checkpoint pins the head externally —
        see the module docstring.)"""
        led = cls(path=None)
        with open(path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    led._events.append(json.loads(line))
                except json.JSONDecodeError as e:
                    raise ChainError(f"corrupt ledger line {n}: {e}")
        try:
            res = led.verify()
        except ValueError as e:   # an uncanonicalizable loaded leaf (float, bad key)
            raise ChainError(f"ledger has an uncanonicalizable event on load: {e}")
        if not res.ok:
            raise ChainError(
                f"ledger failed verification on load: {res.reason} at seq {res.at_seq}"
            )
        # Re-apply the live fail-closed gates — the file is data, not authority.
        # A hand-built valid chain must not smuggle a secret, an illegal kind, a
        # bad ts, or a non-string sig that append() would have refused.
        for ev in led._events:
            seq = ev.get("seq")
            if ev.get("kind") not in _KINDS:
                raise ChainError(f"loaded event has illegal kind {ev.get('kind')!r} at seq {seq}")
            if "sig" in ev and not isinstance(ev["sig"], str):
                raise ChainError(f"loaded event has non-string sig at seq {seq}")
            if "ts" in ev:
                try:
                    _validate_ts(ev["ts"])
                except ValueError as e:
                    raise ChainError(f"loaded event has bad ts at seq {seq}: {e}")
            hit = scan_for_secrets(ev)
            if hit is not None:
                raise ChainError(f"loaded event carries a secret at {hit} (seq {seq})")
        led._path = path
        led._head = event_hash(led._events[-1]) if led._events else GENESIS
        return led


# --- Tier 2: the session layer (H5 — check-out reconciliation) ---------------
# check_in records the declared intent; every action is a receipt; check_out
# folds the receipts into observed capabilities and reconciles them against what
# was declared. Reconciliation is over OBSERVABLE CAPABILITIES, not intent: it
# catches "declared read, did write" — never "read the wrong thing for a bad
# reason" (that is H6, and it deliberately does not live here). The ledger stays
# the single owner of the trust ladder's fail_count; this only computes the delta
# the ladder should consume.


@dataclass
class Reconciliation:
    session_id: str
    reconciled: bool
    declared: list
    observed: list
    mismatches: list
    fail_count_delta: int
    already_closed: bool = False   # this window already had a checkout; do not re-feed the ladder

    def __bool__(self) -> bool:
        return self.reconciled

    def exit_fail_count(self, entry_fail_count: int) -> int:
        """The fail_count to carry into WillowGate.check_out. The ladder owns the
        count; reconciliation only adds what the receipts prove."""
        return int(entry_fail_count) + self.fail_count_delta


def _check_session_id(session_id: Any, *, allow_none: bool = False) -> None:
    """session_id is a string by contract. Normalizing types (str(1) == str('1'))
    merges genuinely distinct sessions, and matching by exact-but-mixed type lets
    a mis-typed tag split a window — so we require a consistent type instead."""
    if session_id is None:
        if allow_none:
            return
        raise ValueError("session_id is required")
    if not isinstance(session_id, str):
        raise ValueError(f"session_id must be a string, got {type(session_id).__name__}")


def _declared_tools(declared: Any) -> list:
    """Pull the declared capability list from a WillowGate-style header (or a bare
    list / whitespace-or-comma string). Normalized to a sorted, de-duped list."""
    if declared is None:
        return []
    tools = declared.get("tools", []) if isinstance(declared, dict) else declared
    if isinstance(tools, str):
        tools = re.split(r"[,\s]+", tools.strip())
    if not isinstance(tools, (list, tuple, set)):
        # fail closed on a malformed declared header, not with a bare TypeError.
        raise ValueError(f"declared tools must be a list or string, got {type(tools).__name__}")
    # Case-folded: capability comparison must not be evaded by "Write" vs "write".
    return sorted({str(t).strip().lower() for t in tools if str(t).strip()})


def session_check_in(ledger: CustodyLedger, session_id: str, actor: str,
                     declared: Any, *, ts: Optional[str] = None) -> dict:
    """Record the declared intent header at the start of a session."""
    _check_session_id(session_id)
    return ledger.append({
        "kind": KIND_SESSION_CHECKIN,
        "session_id": session_id,
        "actor": actor,
        "declared": declared,
    }, ts=ts)


def session_record_action(ledger: CustodyLedger, session_id: str, actor: str,
                          tool: str, *, ts: Optional[str] = None, **extra) -> dict:
    """Record one capability actually exercised — a receipt to reconcile against."""
    _check_session_id(session_id)
    ev = {
        "kind": KIND_SESSION_ACTION,
        "session_id": session_id,
        "actor": actor,
        "tool": tool,
    }
    ev.update(extra)
    return ledger.append(ev, ts=ts)


def session_check_out(ledger: CustodyLedger, session_id: str, *,
                      ts: Optional[str] = None) -> Reconciliation:
    """Reconcile a session's declared intent against its observed actions, append
    a durable session.checkout, and return the reconciliation. A capability
    exercised but not declared is a mismatch and a fail_count increment."""
    # A window opens ONLY on a check-in that follows a check-out. A re-check-in
    # inside an OPEN window is ignored — it may not reset `observed` (else an
    # agent double-checks-in to erase an undeclared capability) nor re-broaden
    # `declared`. `closed` = the current window already has a checkout.
    _check_session_id(session_id)
    declared_header = None
    observed: set = set()
    orphans: set = set()   # capabilities exercised in the DEAD ZONE (while closed)
    closed = False
    for ev in ledger.events():
        evsid = ev.get("session_id")
        if evsid is None or evsid != session_id:
            continue
        kind = ev.get("kind")
        if kind == KIND_SESSION_CHECKIN:
            if declared_header is None:
                # first check-in: adopt the declaration but KEEP any pre-check-in
                # actions in `observed` — a capability exercised and then narrowly
                # declared must still be caught (F3).
                declared_header = ev.get("declared")
            elif closed:
                # a fresh window after a check-out: seed it with the dead-zone
                # orphans (they must not vanish), not an empty set — the symmetric
                # twin of the pre-first-check-in fold.
                declared_header = ev.get("declared")
                observed = set(orphans)
                orphans = set()
                closed = False
            # else: re-check-in in an open window -> ignored on purpose.
        elif kind == KIND_SESSION_CHECKOUT:
            # this checkout covered whatever came before it; `orphans` now tracks
            # only capabilities exercised SINCE the most recent checkout, so a
            # re-check_out with nothing new stays idempotent (no re-emit / re-feed).
            closed = True
            orphans = set()
        elif kind == KIND_SESSION_ACTION:
            # an untyped action still counts as a capability, so it can't hide.
            cap = str(ev.get("tool") or "action").strip().lower()
            (orphans if closed else observed).add(cap)
        elif kind in _CAPABILITY_BY_KIND:
            # a write/egress/checkout routed through the file path is folded too.
            (orphans if closed else observed).add(_CAPABILITY_BY_KIND[kind])
    if declared_header is None:
        raise ChainError(f"no session.checkin for session {session_id!r}")
    # Trailing dead-zone capabilities (after the last check-out, no new check-in)
    # are covered by no declaration. Because they are NEW activity since the last
    # reconciliation, they must produce a durable record and feed the ladder — NOT
    # be suppressed by `already_closed`. So `already_closed` is True only when the
    # window was closed AND nothing new happened since.
    has_new_orphans = bool(orphans)
    observed |= orphans

    declared = _declared_tools(declared_header)
    mismatches = sorted(observed - set(declared))
    recon = Reconciliation(
        session_id=session_id,
        reconciled=not mismatches,
        declared=declared,
        observed=sorted(observed),
        mismatches=mismatches,
        fail_count_delta=len(mismatches),
        already_closed=(closed and not has_new_orphans),
    )
    # Recompute-don't-raise: return the TRUE reconciliation without a duplicate
    # emit. This defeats a LONE forged session.checkout in a loaded file — it can
    # neither deny nor mask. It does NOT close forgery in general: a forged
    # checkout+checkin PAIR can still roll the window forward and mask a mismatch,
    # and a forged checkout can spoof `already_closed`. Authenticating derived
    # records against a file-writing adversary is a Tier-4 (signed-head) property,
    # not achievable here — see docs/custody-ledger-spec.md "The Tier-4 boundary".
    if (not closed) or has_new_orphans:
        ledger._append({           # system-only kind — privileged path
            "kind": KIND_SESSION_CHECKOUT,
            "session_id": session_id,
            "reconciled": recon.reconciled,
            "declared": recon.declared,
            "observed": recon.observed,
            "mismatches": recon.mismatches,
            "fail_count_delta": recon.fail_count_delta,
        }, ts=ts)
    return recon


# --- Tier 3: file custody (lineage, diffs, capture-gap detection) ------------
# Every file has a stable lineage_id that survives content changes; each version
# links to its parent by content hash, so the whole life of a file is queryable
# and diffable. The ledger WITNESSES, it does not PREVENT: an edit made by
# something that emits no event is not blocked — it is DETECTED. The next
# observed content hash will not match the last recorded one, and
# detect_capture_gap() writes a capture_gap. Detection is the value; it is not a
# wall. (The actual wiring into a pre-tool hook / egress lane is cross-repo
# Tier 3b; this is the standalone core those hooks call.)
#
# LAUNDERING LIMIT (honest): detect_capture_gap only fires when an honest
# observer reports a hash BEFORE a write is recorded. An actor who controls the
# write path can record an out-of-band edit as a normal file_write (auto-parent =
# last recorded hash); verify_lineage passes and no gap is raised. This detects
# accidents and honest reporting, not an adversary who owns the recorder — for
# that you need the write path itself to run through the gate (Tier 3b) and the
# H5 reconciliation to catch the undeclared capability.


def _lineage_events(ledger: CustodyLedger, lineage_id: str) -> list:
    out = []
    for e in ledger.events():
        if e.get("lineage_id") != lineage_id:
            continue
        k = str(e.get("kind", ""))
        if k.startswith("file.") or k == KIND_CAPTURE_GAP:
            out.append(e)
    return out


def last_content_hash(ledger: CustodyLedger, lineage_id: str) -> Optional[str]:
    """The content hash in effect for a lineage — from the last file event, or
    the observed hash of a recorded capture_gap (a documented break becomes the
    new baseline, so a gap is flagged once, not forever)."""
    h = None
    seen_origin = False
    for e in _lineage_events(ledger, lineage_id):
        k = e.get("kind")
        # Only the FIRST origin, writes, and acknowledged gaps move the baseline.
        # A read never re-baselines, and a SECOND origin must not silently re-anchor
        # the lineage onto attacker content.
        if k in (KIND_FILE_CREATE, KIND_FILE_GATE_CROSS):
            if not seen_origin and e.get("content_hash"):
                h = e["content_hash"]
                seen_origin = True
        elif k == KIND_FILE_WRITE and e.get("content_hash"):
            h = e["content_hash"]
        elif k == KIND_CAPTURE_GAP and e.get("observed_content_hash"):
            h = e["observed_content_hash"]
    return h


def file_create(ledger: CustodyLedger, lineage_id: str, actor: str,
                content_hash: str, *, path: Optional[str] = None,
                session_id: Optional[str] = None, ts: Optional[str] = None) -> dict:
    _check_session_id(session_id, allow_none=True)
    return ledger.append({
        "kind": KIND_FILE_CREATE, "lineage_id": lineage_id, "actor": actor,
        "content_hash": content_hash, "path": path, "session_id": session_id,
    }, ts=ts)


def file_read(ledger: CustodyLedger, lineage_id: str, actor: str,
              content_hash: str, *, session_id: Optional[str] = None,
              ts: Optional[str] = None) -> dict:
    _check_session_id(session_id, allow_none=True)
    return ledger.append({
        "kind": KIND_FILE_READ, "lineage_id": lineage_id, "actor": actor,
        "content_hash": content_hash, "session_id": session_id,
    }, ts=ts)


def file_write(ledger: CustodyLedger, lineage_id: str, actor: str,
               new_content_hash: str, *, parent_content_hash: Optional[str] = None,
               diff_stat: Optional[dict] = None, session_id: Optional[str] = None,
               ts: Optional[str] = None) -> dict:
    """Record a new version. If parent is not given it auto-chains to the last
    recorded content hash for the lineage. Pass session_id to tie the write to a
    session so H5 check-out reconciles it."""
    _check_session_id(session_id, allow_none=True)
    if parent_content_hash is None:
        parent_content_hash = last_content_hash(ledger, lineage_id)
    return ledger.append({
        "kind": KIND_FILE_WRITE, "lineage_id": lineage_id, "actor": actor,
        "content_hash": new_content_hash,
        "parent_content_hash": parent_content_hash,
        "diff_stat": diff_stat, "session_id": session_id,
    }, ts=ts)


def file_gate_cross(ledger: CustodyLedger, lineage_id: str, actor: str,
                    gate: dict, *, content_hash: Optional[str] = None,
                    session_id: Optional[str] = None,
                    ts: Optional[str] = None) -> dict:
    """Record a file crossing an external gate (the received-file crossing). The
    ledger's fail-closed redaction refuses a live secret carried in `gate`. Pass
    session_id so H5 reconciles the egress."""
    _check_session_id(session_id, allow_none=True)
    return ledger.append({
        "kind": KIND_FILE_GATE_CROSS, "lineage_id": lineage_id, "actor": actor,
        "gate": gate, "content_hash": content_hash, "session_id": session_id,
    }, ts=ts)


def file_checkout(ledger: CustodyLedger, lineage_id: str, actor: str,
                  *, session_id: Optional[str] = None,
                  ts: Optional[str] = None) -> dict:
    _check_session_id(session_id, allow_none=True)
    return ledger.append({
        "kind": KIND_FILE_CHECKOUT, "lineage_id": lineage_id, "actor": actor,
        "session_id": session_id,
    }, ts=ts)


def file_lineage(ledger: CustodyLedger, lineage_id: str) -> list:
    """The full custody history of one file, in order — the custody view."""
    return _lineage_events(ledger, lineage_id)


def verify_lineage(ledger: CustodyLedger, lineage_id: str) -> VerifyResult:
    """Check the version chain: each write's parent_content_hash matches the
    content hash in effect before it. A documented capture_gap updates the
    effective hash, so legitimate writes still chain around an acknowledged
    break."""
    evs = _lineage_events(ledger, lineage_id)
    if not evs:
        return VerifyResult(True, "ok")   # empty lineage: nothing to verify
    # A lineage must have an origin — a create, or a gate-cross that received it.
    # A write-first lineage is un-provenanced and must not pass.
    if evs[0].get("kind") not in (KIND_FILE_CREATE, KIND_FILE_GATE_CROSS):
        return VerifyResult(False, "lineage has no origin", evs[0].get("seq"))
    effective: Optional[str] = None
    known: set = set()   # every content hash this lineage has legitimately held
    for i, e in enumerate(evs):
        k = e.get("kind")
        if k in (KIND_FILE_CREATE, KIND_FILE_GATE_CROSS):
            ch = e.get("content_hash")
            if i == 0:
                if ch:
                    effective = ch
                    known.add(ch)
            elif ch and ch != effective:
                # a second origin may not re-anchor the lineage onto a new hash.
                return VerifyResult(False, "lineage has a conflicting second origin", e.get("seq"))
        elif k == KIND_FILE_WRITE:
            if not e.get("content_hash"):
                return VerifyResult(False, "write missing content_hash", e.get("seq"))
            if e.get("parent_content_hash") != effective:
                return VerifyResult(False, "broken lineage chain", e.get("seq"))
            effective = e["content_hash"]
            known.add(effective)
        elif k == KIND_CAPTURE_GAP:
            if e.get("observed_content_hash"):
                effective = e["observed_content_hash"]
                known.add(effective)
        elif k == KIND_FILE_READ:
            # A read never re-baselines. A read of a hash the lineage has NEVER
            # held is an unexplained change and must surface; a read of any
            # previously-held version (a cached/older copy) is fine.
            ch = e.get("content_hash")
            if ch and ch not in known:
                return VerifyResult(False, "read observed unexplained content hash", e.get("seq"))
        # file.checkout: ignored (moves nothing)
    return VerifyResult(True, "ok")


def lineage_has_gaps(ledger: CustodyLedger, lineage_id: str) -> bool:
    return any(e.get("kind") == KIND_CAPTURE_GAP
               for e in _lineage_events(ledger, lineage_id))


def detect_capture_gap(ledger: CustodyLedger, lineage_id: str,
                       observed_content_hash: str, *, actor: str = "observer",
                       ts: Optional[str] = None) -> Optional[dict]:
    """Compare an observed file hash to the last recorded one. If they differ, no
    recorded write explains the change (a write to `observed` would have moved the
    recorded hash), so it is an out-of-band edit: append and return a capture_gap.
    Returns None if consistent, or if there is no prior hash to compare against
    (provenance-of-first-sight is H3's job, not this detector's)."""
    expected = last_content_hash(ledger, lineage_id)
    if expected is None or observed_content_hash == expected:
        return None
    return ledger._append({    # system-only kind — privileged path
        "kind": KIND_CAPTURE_GAP, "lineage_id": lineage_id, "actor": actor,
        "expected_content_hash": expected,
        "observed_content_hash": observed_content_hash,
        "note": "observed content hash has no explaining write event",
    }, ts=ts)


# --- Tier 4: sealing (signed checkpoints + portable sidecar) ------------------
# Hash-chaining gives tamper-DETECTION for in-place edits (Tier 1). Signing the
# chain head gives tamper-EVIDENCE for the whole prefix under the operator's key —
# and it is what authenticates that a derived record (session.checkout, capture_gap)
# is the ledger's OWN, closing the forged-derived-record class that Tiers 1-3 can
# only document. A "signer" is any object exposing:
#     sign(data: bytes) -> str            # a detached signature
#     verify(data: bytes, sig: str) -> bool
# The core below is signer-agnostic (so gate tests run deterministically); GpgSigner
# is the production one.


def _recompute_head(events: list, upto_seq: int) -> Optional[str]:
    """The chain head over events[0..upto_seq], or None if the chain is broken."""
    prev = GENESIS
    for e in events:
        if e.get("seq", -1) > upto_seq:
            break
        if e.get("ledger_prev_hash") != prev:
            return None
        prev = event_hash(e)
    return prev


def checkpoint(ledger: CustodyLedger, signer: Any, *, ts: Optional[str] = None) -> dict:
    """Seal the current chain head with a signature and append a checkpoint record.
    The head commits (via the chain) to every event before it, so one signature
    makes the whole prefix tamper-evident at bounded cost. System-only kind."""
    covers = len(ledger) - 1
    head = ledger.head_hash
    sig = signer.sign(head.encode("utf-8"))
    if isinstance(sig, (bytes, bytearray)):
        sig = sig.decode("utf-8")
    return ledger._append({
        "kind": KIND_CHECKPOINT,
        "covers_to_seq": covers,
        "head_hash": head,
        "sig": str(sig),
    }, ts=ts)


def verify_checkpoint(ledger: CustodyLedger, checkpoint_event: dict, signer: Any) -> VerifyResult:
    """Recompute the sealed head and verify the signature. Any tamper to a covered
    event changes the recomputed head (or breaks the chain), so it fails here even
    though Tier 1's verify() alone can be fooled by a fully re-derived forgery. If an
    attacker also rewrites the stored head to match their forgery, the signature over
    it no longer verifies (they lack the key)."""
    covers = checkpoint_event.get("covers_to_seq")
    claimed = checkpoint_event.get("head_hash")
    sig = checkpoint_event.get("sig")
    if not isinstance(covers, int) or not isinstance(claimed, str) or not isinstance(sig, str):
        return VerifyResult(False, "malformed checkpoint")
    computed = _recompute_head(ledger.events(), covers)
    if computed is None:
        return VerifyResult(False, "chain broken within checkpoint coverage", covers)
    if computed != claimed:
        return VerifyResult(False, "sealed head does not match recomputed head", covers)
    try:
        ok = bool(signer.verify(claimed.encode("utf-8"), sig))
    except Exception:
        ok = False
    if not ok:
        return VerifyResult(False, "checkpoint signature invalid", covers)
    return VerifyResult(True, "ok", covers)


def export_sidecar(ledger: CustodyLedger, signer: Any, *,
                   lineage_id: Optional[str] = None,
                   session_id: Optional[str] = None) -> dict:
    """A portable, signed slice for offline use. It proves the shown events are
    AUTHENTIC (signed) — NOT that none were omitted. Explicitly weaker than the
    ledger; the returned dict carries `authenticity_only: True` to say so."""
    if (lineage_id is None) == (session_id is None):
        raise ValueError("export_sidecar needs exactly one of lineage_id / session_id")
    if lineage_id is not None:
        events = _lineage_events(ledger, lineage_id)
        subject = {"lineage_id": lineage_id}
    else:
        events = [e for e in ledger.events() if e.get("session_id") == session_id]
        subject = {"session_id": session_id}
    payload = {"subject": subject, "anchor_head": ledger.head_hash, "events": events}
    sig = signer.sign(canonicalize(payload))
    if isinstance(sig, (bytes, bytearray)):
        sig = sig.decode("utf-8")
    return {**payload, "sig": str(sig), "authenticity_only": True}


def verify_sidecar(sidecar: dict, signer: Any) -> VerifyResult:
    """Verify a sidecar's signature OFFLINE (no ledger). Returns ok with an explicit
    weaker-than-ledger note: authenticity of the shown events only, not completeness."""
    sig = sidecar.get("sig")
    if not isinstance(sig, str):
        return VerifyResult(False, "malformed sidecar")
    payload = {k: v for k, v in sidecar.items() if k not in ("sig", "authenticity_only")}
    try:
        ok = bool(signer.verify(canonicalize(payload), sig))
    except Exception:
        ok = False
    if not ok:
        return VerifyResult(False, "sidecar signature invalid")
    return VerifyResult(True, "authentic (shown events only, NOT completeness)")


class GpgSigner:
    """Production signer over python-gnupg detached signatures. Imports gnupg lazily
    so the rest of the module stays stdlib-only."""

    def __init__(self, fingerprint: str, *, gnupghome: Optional[str] = None,
                 passphrase: Optional[str] = None) -> None:
        import gnupg  # optional dependency, required only for this signer
        self._g = gnupg.GPG(gnupghome=gnupghome) if gnupghome else gnupg.GPG()
        self._fpr = fingerprint
        self._pass = passphrase

    def sign(self, data: bytes) -> str:
        s = self._g.sign(data, keyid=self._fpr, detach=True, passphrase=self._pass)
        if not s or not str(s).strip():
            raise RuntimeError("gpg detached-sign failed")
        return str(s)

    def verify(self, data: bytes, sig: str) -> bool:
        import os
        import tempfile
        fd, p = tempfile.mkstemp(suffix=".asc")
        try:
            os.write(fd, sig.encode("utf-8") if isinstance(sig, str) else sig)
            os.close(fd)
            v = self._g.verify_data(p, data)
            return bool(getattr(v, "valid", False))
        finally:
            try:
                os.unlink(p)
            except OSError:
                pass
