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
  * HASH-CHAINED. Every event carries the hash of the one before it, so altering
    any past event breaks verification of every event after it.
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


def looks_like_secret(value: str) -> bool:
    """True if a string matches a known live-credential shape."""
    return any(p.search(value) for p in _SECRET_PATTERNS)


def scan_for_secrets(obj: Any, path: str = "") -> Optional[str]:
    """Return the dotted path of the first secret-looking value, or None."""
    if isinstance(obj, str):
        return path if looks_like_secret(obj) else None
    if isinstance(obj, dict):
        for k, v in obj.items():
            hit = scan_for_secrets(v, f"{path}.{k}" if path else str(k))
            if hit:
                return hit
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            hit = scan_for_secrets(v, f"{path}[{i}]")
            if hit:
                return hit
    return None


# --- canonicalization -------------------------------------------------------
def _strip(obj: Any) -> Any:
    """Explicit null policy: omit keys whose value is None (absent == null),
    recursively. Everything else is passed through untouched."""
    if isinstance(obj, dict):
        return {k: _strip(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip(v) for v in obj]
    return obj


def canonicalize(event: dict) -> bytes:
    """Byte-stable canonical form of an event: signature excluded, nulls
    omitted, keys sorted, no insignificant whitespace, UTF-8. Two callers that
    build the same event (in any key order) get identical bytes."""
    body = {k: v for k, v in event.items() if k not in _UNSIGNED}
    body = _strip(body)
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def event_hash(event: dict) -> str:
    """sha256 of the canonical form, hex."""
    return hashlib.sha256(canonicalize(event)).hexdigest()


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
        if "kind" not in event:
            raise ValueError("event requires a 'kind'")
        for r in _RESERVED:
            if r in event:
                raise ValueError(f"caller may not set reserved field {r!r}")

        # Fail closed BEFORE any state changes: nothing is written on refusal.
        hit = scan_for_secrets(event)
        if hit is not None:
            raise SecretRefused(f"value at {hit!r} looks like a live secret")

        stored = dict(event)
        stored["seq"] = len(self._events)
        stored["ledger_prev_hash"] = self._head
        if ts is not None:
            stored["ts"] = ts

        h = event_hash(stored)
        self._events.append(stored)
        self._head = h
        if self._path:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(stored, ensure_ascii=False) + "\n")
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
        """Rebuild a ledger from its JSONL file (for verify-after-reopen)."""
        led = cls(path=None)
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    led._events.append(json.loads(line))
        led._path = path
        led._head = event_hash(led._events[-1]) if led._events else GENESIS
        return led
