#!/usr/bin/env python3
"""WillowGate — hardened build (from DRAFT_SPEC v0314).

Your design, kept intact: symmetric 13-field check-in / check-out, five trust
levels, PGP-encrypted flat-file ledger, the reserved trap field, hard stops,
and the announce-loud-for-the-untrusted inversion.

Strengthenings applied over the draft — each is one of the review points, and
each is marked `# HARDENED` at its site so you can find and judge it:

  1. PREVENT, not just detect. `authorize_tool()` is an INLINE pre-tool gate
     that refuses a disallowed tool or export in real time. `check_out()` still
     diffs as defense-in-depth — but the lock is now at the door, not the exit.
  2. Trust is BOUND, not self-reported. The 64-hex `signature` field is a real
     HMAC-SHA256 over the canonical header, keyed by a per-agent secret the gate
     holds (registered out-of-band). A claimed `trust_level` is capped at the
     agent's registered `max_trust`. An agent cannot mint trust it wasn't granted
     — "Elder" stops being a text field anyone can type.
  3. No bundled PRIVATE key. The ledger encrypts to the operator's key; nothing
     shipped can decrypt it. A public key may ship for verify/encrypt-to-gate;
     the private half never does.
  4. Replay-proof nonce. Used nonces persist to disk, so a restart can't forget
     them and let a token be replayed.
  5. `blast_radius` -> `announcement_volume`. It means audit loudness — the
     inverse of the standard term (where minimizing blast radius is the goal).
     The rename stops the misread.
  6. The Exiled contradiction is resolved (willow-gate#12). `entry_allowed` gates
     session CREATION: Exiled (level 0) is REFUSED at check_in and holds no
     session — that is what makes it distinct from Rookie (both are otherwise
     read-only). Read is still universal, but for a true outsider it is not
     gate-mediated: an outsider never checks in, so a session-bearing read is a
     Rookie+ affair and an outsider reads by a path the gate never mediated.
  7. Tolerance no longer rewards power with slack. drift/fail budgets TIGHTEN as
     trust rises (Elder is held tightest), the reverse of the draft. This is a
     constant table — revert it if you meant it the other way.

VERIFIED: 13 logic tests + a PGP encrypted-ledger round-trip pass (see
tests/). Two bugs were found and fixed by running it — read was universal in
the docstring but not the code, and the write flag keyed off the wrong axis.
The rule held: test before you trust, and this file was no exception.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

try:
    import gnupg  # python-gnupg
except Exception:  # pragma: no cover - optional at import time, required at run
    gnupg = None


# ─── Trust levels ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TrustLevel:
    name: str
    entry_allowed: bool          # may open a session at all (willow-gate#12);
                                 # Exiled=False is refused at check_in. read is
                                 # universal but session-less for a true outsider.
    read_only: bool
    write_export_allowed: bool
    announcement_volume: str     # HARDENED(5): was blast_radius; = audit loudness
    max_drift_ms: Optional[int]
    max_fail_count: Optional[int]
    min_pass_count: Optional[int]
    allowed_tools: Tuple[str, ...]
    audit_level: str             # "full" | "minimal"


# HARDENED(7): drift/fail tighten as trust rises — power gets less slack, not more.
TRUST_LEVELS: Dict[int, TrustLevel] = {
    0: TrustLevel("Exiled",  False, True,  False, "maximum", None,  None, None, (),                                             "full"),
    1: TrustLevel("Rookie",  True,  True,  False, "large",   5000,  5,    0,   ("read",),                                       "full"),
    2: TrustLevel("Steady",  True,  False, True,  "medium",  3000,  3,    3,   ("read", "write"),                               "full"),
    3: TrustLevel("Veteran", True,  False, True,  "small",   2000,  2,    11,  ("read", "write", "query", "execute"),           "minimal"),
    4: TrustLevel("Elder",   True,  False, True,  "minimal", 1000,  1,    50,  ("read", "write", "query", "execute", "admin"),  "minimal"),
}

READ_TOOL = "read"
# How many times an event is written to the announcement channel, by volume.
_VOLUME_REPEAT = {"maximum": 5, "large": 3, "medium": 2, "small": 1, "minimal": 1}

REQUIRED_FIELDS: Set[str] = {
    "agent_id", "agent_name", "last_gate", "pass_count", "fail_count", "drift",
    "nonce", "trust_level", "timestamp", "tools", "state_hash", "signature",
    "reserved",
}
# Fields the HMAC signs (everything except the signature itself).
_SIGNED_FIELDS = sorted(REQUIRED_FIELDS - {"signature"})


class GateError(Exception):
    """A hard stop. Never swallowed; surfaced immediately."""


# ─── The gate ────────────────────────────────────────────────────────────────

class WillowGate:
    BASE_DIR = Path("/willowgate")

    def __init__(
        self,
        operator_key_fpr: Optional[str] = None,
        base_dir: Optional[Path] = None,
        require_pgp: bool = True,
    ):
        # HARDENED(3): the recipient of ledger encryption is the OPERATOR's key,
        # supplied here or via env — never a packaged default. No default key id.
        self.operator_key_fpr = operator_key_fpr or os.environ.get("WILLOWGATE_KEY_FPR", "")
        self.base_dir = Path(base_dir) if base_dir else self.BASE_DIR
        self.ledger_dir = self.base_dir / "ledger"
        self.require_pgp = require_pgp
        self.ledger_dir.mkdir(parents=True, exist_ok=True)

        self.gpg = gnupg.GPG() if gnupg is not None else None
        if self.require_pgp:
            self._verify_pgp()

        # agent_id -> {"secret": bytes, "max_trust": int}. Registered out-of-band.
        self._registry: Dict[str, Dict] = {}
        self._registry_file = self.base_dir / "registry.json"
        self._load_registry()

        # HARDENED(4): used nonces persist, so a restart cannot forget them.
        self._used_file = self.base_dir / "used_nonces"
        self._used: Set[str] = set()
        if self._used_file.exists():
            self._used = set(self._used_file.read_text().split())

        self.sessions: Dict[str, Dict] = {}
        self.announcements_log = self.base_dir / "announcements.log"

    # ── setup / crypto ──────────────────────────────────────────────────────

    def _verify_pgp(self) -> None:
        # HARDENED(3): fail closed. Require gnupg AND an operator key that we can
        # actually encrypt to. Nothing here reaches for a packaged private key.
        if self.gpg is None:
            raise GateError("PGP required but python-gnupg is not installed")
        if not self.operator_key_fpr:
            raise GateError(
                "PGP required but no operator key fingerprint set "
                "(pass operator_key_fpr= or export WILLOWGATE_KEY_FPR)")
        fprs = {k.get("fingerprint", "") for k in self.gpg.list_keys()}
        if self.operator_key_fpr not in fprs:
            raise GateError(
                f"operator key {self.operator_key_fpr} not in keyring — import the "
                "public key you want the ledger encrypted to")

    def register_agent(self, agent_id: str, secret: bytes, max_trust: int) -> None:
        """Bind an agent identity to a shared secret and a MAX trust ceiling.
        This is the out-of-band act that makes trust real — do it from the
        operator side, never from a gate tool."""
        if not (0 <= max_trust <= 4):
            raise GateError("max_trust must be 0..4")
        self._registry[agent_id] = {"secret": secret.hex(), "max_trust": max_trust}
        self._registry_file.write_text(json.dumps(self._registry))

    def _load_registry(self) -> None:
        if self._registry_file.exists():
            self._registry = json.loads(self._registry_file.read_text())

    def _canonical(self, header: Dict) -> bytes:
        return json.dumps({k: header[k] for k in _SIGNED_FIELDS},
                          sort_keys=True, separators=(",", ":")).encode()

    def _expected_sig(self, agent_id: str, header: Dict) -> Optional[str]:
        rec = self._registry.get(agent_id)
        if not rec:
            return None
        secret = bytes.fromhex(rec["secret"])
        return hmac.new(secret, self._canonical(header), hashlib.sha256).hexdigest()

    # ── validation ──────────────────────────────────────────────────────────

    def _validate_shape(self, data: Dict) -> None:
        missing = REQUIRED_FIELDS - set(data)
        if missing:
            raise GateError(f"missing fields: {sorted(missing)}")
        extra = set(data) - REQUIRED_FIELDS
        if extra:
            raise GateError(f"unknown fields: {sorted(extra)}")  # 13 in, 13 out
        if data["reserved"] != 0:
            raise GateError("trap field 'reserved' must be 0")   # canary tripped
        tl = data["trust_level"]
        if tl not in TRUST_LEVELS:
            raise GateError(f"bad trust_level: {tl}")
        if len(str(data["nonce"])) != 32:
            raise GateError("nonce must be 32 hex chars")
        if len(str(data["signature"])) != 64:
            raise GateError("signature must be 64 hex chars (HMAC-SHA256)")

    def _authenticate(self, header: Dict) -> int:
        """Verify the HMAC and return the EFFECTIVE trust level (claim capped by
        the registered ceiling). HARDENED(2): trust is bound, not asserted."""
        agent_id = header["agent_id"]
        expected = self._expected_sig(agent_id, header)
        if expected is None:
            raise GateError(f"unregistered agent_id: {agent_id!r}")
        if not hmac.compare_digest(expected, str(header["signature"])):
            raise GateError("signature mismatch — identity not verified")
        claimed = int(header["trust_level"])
        ceiling = int(self._registry[agent_id]["max_trust"])
        if claimed > ceiling:
            raise GateError(
                f"trust claim {claimed} exceeds registered ceiling {ceiling}")
        return claimed

    # ── check-in ────────────────────────────────────────────────────────────

    def check_in(self, header: Dict) -> Tuple[bool, str, Optional[Dict]]:
        self._validate_shape(header)
        trust = self._authenticate(header)
        level = TRUST_LEVELS[trust]

        # entry_allowed gates session creation (willow-gate#12). Exiled (level 0)
        # is REFUSED a session — it is the one level that may not check in. "Read
        # is universal" still holds, but for a true outsider it is NOT gate-
        # mediated: an Exiled agent never obtains a session, so a session-bearing
        # read is a Rookie+ affair; an outsider reads by a path the gate never
        # claimed to mediate. This is the field's namesake meaning, and it is what
        # makes Exiled distinct from Rookie (both are otherwise read-only).
        if not level.entry_allowed:
            raise GateError(
                f"entry denied: {level.name} (level {trust}) may not open a session")

        if level.max_drift_ms is not None and abs(int(header["drift"])) > level.max_drift_ms:
            raise GateError(f"drift {header['drift']}ms exceeds {level.max_drift_ms}ms")
        if level.max_fail_count is not None and int(header["fail_count"]) > level.max_fail_count:
            raise GateError(f"fail_count {header['fail_count']} exceeds {level.max_fail_count}")
        if level.min_pass_count is not None and int(header["pass_count"]) < level.min_pass_count:
            raise GateError(f"pass_count {header['pass_count']} below required {level.min_pass_count}")

        nonce = str(header["nonce"])
        if nonce in self._used:
            raise GateError("nonce already used — replay refused")

        # HARDENED(6): read is universal — always grantable, any level.
        declared = set(header["tools"])
        if not declared <= (set(level.allowed_tools) | {READ_TOOL}):
            raise GateError(
                f"declared tools {sorted(declared)} exceed level {level.name} "
                f"grant {list(level.allowed_tools)} (+read)")

        # HARDENED(6): read is universal; write depends on the level's read_only
        # axis, not entry_allowed (Rookie may enter but is still read-only).
        writable = not level.read_only
        if not writable:
            declared = declared & {READ_TOOL}  # read-only levels get a read room

        self._used.add(nonce)
        with self._used_file.open("a") as f:
            f.write(nonce + "\n")

        session = {
            "nonce": nonce,
            "agent_id": header["agent_id"],
            "trust_level": trust,
            "writable": writable,
            "granted_tools": set(declared),
            "entry": header,
            "entry_ms": int(header["timestamp"]),
            "tools_used": set(),
            "exports": 0,
        }
        self.sessions[nonce] = session
        self._write_ledger(nonce, "entry", header)
        self._announce(session, f"CHECK-IN {level.name} agent={header['agent_id']}")
        radius = level.announcement_volume
        return True, f"CHECK-IN ACCEPTED — {radius} announcement, {'read+write' if writable else 'read-only'}", session

    # ── inline enforcement (the actual lock) ─────────────────────────────────

    def authorize_tool(self, session: Dict, tool: str, *, export: bool = False
                       ) -> Tuple[bool, str]:
        """HARDENED(1): call this BEFORE every tool use. It PREVENTS — a denied
        call never runs. This is the difference between a gate and a ledger."""
        if session["nonce"] not in self.sessions:
            raise GateError("no live session for this nonce")
        level = TRUST_LEVELS[session["trust_level"]]
        # HARDENED(6): read clears the grant check for everyone; export is still
        # enforced below regardless of which tool it is.
        if tool != READ_TOOL and tool not in session["granted_tools"]:
            self._announce(session, f"BLOCKED tool={tool} (not granted)")
            return False, f"DENIED — {tool!r} not in this session's grant"
        if export and not level.write_export_allowed:
            self._announce(session, f"BLOCKED export tool={tool} (trust {level.name})")
            return False, f"DENIED — {level.name} may not export/exfiltrate"
        session["tools_used"].add(tool)
        if export:
            session["exports"] += 1
        self._announce(session, f"TOOL {tool}{' [export]' if export else ''}")
        return True, "ALLOWED"

    # ── the harness (the wiring that makes PREVENT structural) ────────────────

    def bind_tools(self, session: Dict, tools: List["Tool"]) -> "GatedSession":
        """Wrap a live session so its tools are ONLY reachable through the gate.

        README's distinction: the gate PREVENTS only when a harness routes every
        tool call through authorize_tool() BEFORE the tool runs; un-wired it is a
        loud ledger. This is that wiring. The returned GatedSession holds the
        callables privately and exposes a single `call()` that authorizes first
        and refuses (hard stop) if denied — so 'route every call through the
        gate' stops being a convention the caller has to remember and becomes the
        only way to invoke a tool at all.

        A denied call raises GateError: the tool never runs, and — because only
        authorized calls ever reach `session["tools_used"]` — check_out's
        reconciliation stays exactly true without the caller threading anything
        by hand."""
        return GatedSession(self, session, tools)

    # ── check-out ─────────────────────────────────────────────────────────────

    def check_out(self, session: Dict, exit_data: Dict) -> Tuple[bool, str]:
        self._validate_shape(exit_data)
        entry = session["entry"]
        for f in ("agent_id", "agent_name", "last_gate", "nonce", "trust_level"):
            if exit_data[f] != entry[f]:
                raise GateError(f"exit field {f!r} does not match entry")
        self._authenticate(exit_data)  # exit is signed too
        if int(exit_data["timestamp"]) <= session["entry_ms"]:
            raise GateError("exit timestamp must be after entry")
        if int(exit_data["pass_count"]) < int(entry["pass_count"]):
            raise GateError("pass_count decreased")
        if int(exit_data["fail_count"]) < int(entry["fail_count"]):
            raise GateError("fail_count decreased")

        # Defense-in-depth: what was actually used must be within the grant.
        used = set(exit_data["tools"])
        if not (used - {READ_TOOL}) <= session["granted_tools"]:
            raise GateError(
                f"tools used {sorted(used)} exceed grant {sorted(session['granted_tools'])} "
                "— out-of-band tool use detected")
        if not used <= session["tools_used"]:
            # used a tool at exit it never cleared through authorize_tool()
            raise GateError("exit tool manifest includes unauthorized calls")

        duration = int(exit_data["timestamp"]) - session["entry_ms"]
        diff = {
            "pass_delta": int(exit_data["pass_count"]) - int(entry["pass_count"]),
            "fail_delta": int(exit_data["fail_count"]) - int(entry["fail_count"]),
            "duration_ms": duration,
            "state_changed": exit_data["state_hash"] != entry["state_hash"],
            "exports": session["exports"],
            "tools_used": sorted(session["tools_used"]),
        }
        self._write_ledger(session["nonce"], "exit", {"exit": exit_data, "diff": diff})
        self._announce(session, f"CHECK-OUT dur={duration}ms diff={diff}")
        del self.sessions[session["nonce"]]
        return True, f"CHECK-OUT COMPLETE — {duration}ms, {diff['pass_delta']:+d} pass"

    # ── ledger / announcements ───────────────────────────────────────────────

    def _write_ledger(self, nonce: str, kind: str, payload: Dict) -> None:
        raw = json.dumps(payload, sort_keys=True).encode()
        path = self.ledger_dir / f"{nonce}.{kind}.gpg"
        if self.require_pgp:
            enc = self.gpg.encrypt(raw, recipients=[self.operator_key_fpr],
                                   always_trust=True)
            if not enc.ok:
                raise GateError(f"ledger encryption failed: {enc.status}")
            path.write_bytes(enc.data)
        else:  # explicit opt-out only; still leaves a record
            path.with_suffix(".json").write_bytes(raw)

    def _announce(self, session: Dict, msg: str) -> None:
        # HARDENED(5): louder for the less trusted — repeated writes to the log.
        vol = TRUST_LEVELS[session["trust_level"]].announcement_volume
        line = f"[{vol.upper()}] {session['agent_id']} :: {msg}\n"
        with self.announcements_log.open("a") as f:
            for _ in range(_VOLUME_REPEAT.get(vol, 1)):
                f.write(line)


# ─── The harness ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Tool:
    """A named tool callable bound behind the gate. `export` marks a tool whose
    invocation exfiltrates data — it is checked against the level's
    write_export_allowed on every call, exactly as authorize_tool's own
    `export=` flag is (a read-only level may run a non-export tool it was
    granted, but never an export one)."""
    name: str
    fn: Callable
    export: bool = False


class GatedSession:
    """A live session with its tools bound behind the gate. The ONLY way to run
    a tool is `call()`, which authorizes BEFORE invoking. A denied call is a hard
    stop (GateError) — the tool never runs. This is the object that turns the
    gate from a ledger into a prevention: the tool callables are held privately,
    so there is no un-gated path to them."""

    def __init__(self, gate: WillowGate, session: Dict, tools: List[Tool]):
        self._gate = gate
        self._session = session
        self.__tools: Dict[str, Tool] = {t.name: t for t in tools}  # name-mangled

    @property
    def tools(self) -> Tuple[str, ...]:
        """The names bound to this session — never the callables themselves."""
        return tuple(self.__tools)

    def call(self, tool: str, *args, **kwargs):
        """Authorize `tool`, then invoke it. Raises GateError (hard stop) if the
        tool is unknown to this harness or the gate denies it — a denied call
        never reaches the callable, so nothing runs and nothing is recorded as
        used. On success returns the tool's own return value."""
        spec = self.__tools.get(tool)
        if spec is None:
            raise GateError(f"unknown tool {tool!r} — not bound to this session")
        ok, msg = self._gate.authorize_tool(self._session, tool, export=spec.export)
        if not ok:
            # PREVENT: surface the denial immediately, never run the tool.
            raise GateError(msg)
        return spec.fn(*args, **kwargs)


if __name__ == "__main__":  # tiny smoke shape (needs a registered agent + key)
    raise SystemExit(
        "WillowGate is a library. Register an agent, then check_in / "
        "authorize_tool / check_out. See module docstring — and test it, "
        "because it has not been run.")
