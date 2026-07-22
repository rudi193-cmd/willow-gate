"""H1 — inter-agent message integrity for the Grove/dispatch bus.

Grove messages carry a `sender` field but no cryptographic binding: a forged
`sender=hanuman` on the Postgres bus is plausible today. This signs every
message with the sending agent's key and verifies it against the sender's
registered public key before a receiver acts on it.

**Why Ed25519, not the gate's HMAC** (hardening-plan.md H1 caveat, 2026-07-11):
Grove is a shared multi-reader bus — many agents verify each other. HMAC is
symmetric, so any party that can *verify* `sender=X` holds X's secret and can
therefore *forge* X. That is integrity without authenticity, and it collapses
the moment one agent's key is read. Ed25519 signs with a private key and
verifies with a public one: a verifier can check authenticity while holding
zero power to forge. On a shared bus that asymmetry is the whole point.

Key custody follows the gate's existing rules: private keys are 0600 from
birth, live outside any agent-writable store, and rotation is explicit (never
a silent overwrite — a quiet key swap is how an attacker would install their
own). Nonce burn persists across restarts, same as `WillowGate._used`.

Depends only on `cryptography` (already transitively present via the fleet's
Ed25519 use); no new primitive is introduced.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

# Fields covered by the signature. The signed digest is a canonical JSON of
# exactly these keys — everything an action could pivot on (who, where, what,
# when) plus the anti-replay nonce. Envelope metadata (sig, sig_alg) is not
# self-covered, by construction.
SIGNED_FIELDS = ("sender", "channel", "content", "nonce", "signed_at")

# A nonce older than this is refused even if never seen — bounds the burn set
# and stops indefinitely-deferred replays. 24h is generous for a fleet bus.
MAX_AGE_SECONDS = 86_400


class IntegrityError(Exception):
    """Raised on any failure to establish a message's integrity/authenticity."""


@dataclass(frozen=True)
class AgentKeypair:
    agent_id: str
    private_path: Path
    public_pem: str

    def _private(self) -> Ed25519PrivateKey:
        key = load_pem_private_key(self.private_path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise IntegrityError(f"{self.private_path} is not an Ed25519 private key")
        return key


def _canonical_digest(msg: dict) -> bytes:
    """Deterministic bytes over SIGNED_FIELDS. Missing field → hard error, never
    a silent skip (a skipped field is an unsigned field an attacker controls)."""
    try:
        payload = {k: msg[k] for k in SIGNED_FIELDS}
    except KeyError as e:
        raise IntegrityError(f"unsigned: message missing signed field {e}") from None
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def generate_agent_keypair(agent_id: str, *, key_dir: Path) -> AgentKeypair:
    """Create (or load) an agent's Ed25519 keypair. Private key is 0600 from
    birth via os.open — no world-readable window between create and chmod."""
    key_dir = Path(key_dir)
    key_dir.mkdir(parents=True, exist_ok=True)
    priv_path = key_dir / f"{agent_id}.ed25519"
    pub_path = key_dir / f"{agent_id}.ed25519.pub"

    if priv_path.exists():
        priv = load_pem_private_key(priv_path.read_bytes(), password=None)
        if not isinstance(priv, Ed25519PrivateKey):
            raise IntegrityError(f"{priv_path} exists but is not Ed25519")
    else:
        priv = Ed25519PrivateKey.generate()
        pem = priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        fd = os.open(str(priv_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)

    pub_pem = priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()
    pub_path.write_text(pub_pem)
    return AgentKeypair(agent_id=agent_id, private_path=priv_path, public_pem=pub_pem)


def sign_message(msg: dict, keys: AgentKeypair) -> dict:
    """Return a copy of `msg` with a nonce, timestamp, and Ed25519 signature.

    The message's `sender` must match the signing key's agent_id — you cannot
    sign a message that claims to be from someone else (the local half of the
    forged-sender defense; the receiver enforces the other half)."""
    if msg.get("sender") not in (keys.agent_id, None):
        raise IntegrityError(
            f"refusing to sign: sender={msg.get('sender')!r} != key {keys.agent_id!r}")
    out = dict(msg)
    out.setdefault("sender", keys.agent_id)
    out["nonce"] = uuid.uuid4().hex
    out["signed_at"] = int(time.time())
    sig = keys._private().sign(_canonical_digest(out))
    out["sig"] = sig.hex()
    out["sig_alg"] = "ed25519"
    return out


class MessageVerifier:
    """Holds the registry of agent public keys and the persistent nonce-burn
    set. Verifies a message before its receiver is allowed to act on it.

    A verifier can register any number of public keys and check authenticity
    against all of them; it can forge none of them — that is the Ed25519
    guarantee the HMAC design could not give on a shared bus.
    """

    def __init__(self, *, state_dir: Path):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._registry_path = self.state_dir / "agent_keys.json"
        self._used_path = self.state_dir / "used_nonces"
        self._registry: dict[str, str] = {}
        if self._registry_path.exists():
            self._registry = json.loads(self._registry_path.read_text())
        self._used: set[str] = set()
        if self._used_path.exists():
            self._used = set(self._used_path.read_text().split())

    # ── registry ──────────────────────────────────────────────────────────────
    def register_agent(self, agent_id: str, public_pem: str, *, rotate: bool = False):
        """Bind an agent to a public key. A different key for an already-known
        agent requires rotate=True — a silent overwrite is exactly how an
        attacker would install their own key, so it is refused loudly."""
        existing = self._registry.get(agent_id)
        if existing is not None and existing != public_pem and not rotate:
            raise IntegrityError(
                f"key rotation for {agent_id!r} requires rotate=True "
                "(refusing silent overwrite)")
        # Validate it parses as Ed25519 before trusting it.
        key = load_pem_public_key(public_pem.encode())
        if not isinstance(key, Ed25519PublicKey):
            raise IntegrityError(f"public key for {agent_id!r} is not Ed25519")
        self._registry[agent_id] = public_pem
        self._registry_path.write_text(json.dumps(self._registry, indent=2))

    # ── verify ──────────────────────────────────────────────────────────────
    def verify(self, msg: dict) -> bool:
        """True if the message is authentic, unaltered, fresh, and not replayed.
        Raises IntegrityError otherwise — the caller must let it propagate and
        NOT act on the message. Never returns False; either it's good or it
        raises, so a swallowed exception cannot read as 'verified'."""
        if "sig" not in msg or "sender" not in msg:
            raise IntegrityError("unsigned: no signature/sender on message")
        sender = msg["sender"]
        pub_pem = self._registry.get(sender)
        if pub_pem is None:
            raise IntegrityError(f"unknown sender {sender!r}: no registered key")

        nonce = msg.get("nonce", "")
        if not nonce:
            raise IntegrityError("unsigned: no nonce")

        # Authenticity first: a forged or altered message must fail on the
        # signature, whatever else is wrong with it. Only a validly-signed
        # message is worth checking for freshness and replay.
        pub = load_pem_public_key(pub_pem.encode())
        try:
            pub.verify(bytes.fromhex(msg["sig"]), _canonical_digest(msg))
        except (InvalidSignature, ValueError):
            raise IntegrityError("signature: verification failed") from None

        signed_at = msg.get("signed_at", 0)
        if not isinstance(signed_at, int) or abs(int(time.time()) - signed_at) > MAX_AGE_SECONDS:
            raise IntegrityError("stale: signed_at outside the freshness window")

        if nonce in self._used:
            raise IntegrityError(f"replay: nonce {nonce} already seen")

        # Burn the nonce only after the signature checks out — persist before
        # returning so a crash between check and act cannot re-open the replay.
        self._used.add(nonce)
        with self._used_path.open("a") as f:
            f.write(nonce + "\n")
        return True
