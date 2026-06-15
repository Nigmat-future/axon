"""Data models for the discovery engine.

The cornerstone is `Discovery`: it holds a *fingerprint*, never the raw key.
The only place a raw key exists is transiently inside `Discovery.capture()` and
the validator's probe call; it is fingerprinted and dropped immediately. By
construction there is no field on `Discovery` that stores the secret, so it
cannot be logged, serialized, or leaked through the object graph.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum


class SourceKind(str, Enum):
    """Where a credential was found. Drives the consent-gate model."""

    ENV_PROCESS = "env:process"        # live process environment (Stage 1)
    ENV_REGISTRY_USER = "env:registry-user"      # Windows HKCU (Stage 1)
    ENV_REGISTRY_MACHINE = "env:registry-machine"  # Windows HKLM (Stage 1)
    DOTENV = "file:dotenv"             # .env file (Stage 2)
    CONFIG_FILE = "file:config"        # tool config json/yaml (Stage 2)
    CONFIG_SQLITE = "file:sqlite"      # Cursor state.vscdb (Stage 2)
    KEYCHAIN = "os:keychain"           # OS secret store (Stage 3)


class ValidationStatus(str, Enum):
    UNCHECKED = "unchecked"
    AUTHENTICATES = "authenticates"    # 200 — key authenticates (NOT "has quota")
    INVALID = "invalid"                # 401/403 — revoked or wrong
    UNREACHABLE = "unreachable"        # network/DNS/timeout — couldn't tell
    ERROR = "error"                    # unexpected non-2xx/non-auth response


@dataclass(frozen=True)
class KeyFingerprint:
    """A non-reversible identity for a key. Safe to log, display, and persist."""

    last4: str
    sha256_prefix: str  # first 12 hex chars of SHA-256(key)
    length: int

    @classmethod
    def of(cls, api_key: str) -> "KeyFingerprint":
        digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        last4 = api_key[-4:] if len(api_key) >= 4 else "?" * len(api_key)
        return cls(last4=last4, sha256_prefix=digest[:12], length=len(api_key))

    def display(self) -> str:
        """Human-readable fingerprint, e.g. 'sk-..AB12 (51 chars, #1a2b3c4d5e6f)'."""
        return f"..{self.last4} ({self.length} chars, #{self.sha256_prefix})"


@dataclass
class Discovery:
    """One discovered credential — provider, where it came from, and its
    fingerprint. Never holds the raw key value.

    Two discoveries are considered the same credential if they share a provider
    and SHA-256 prefix (e.g. the same key found in both env and a .env file);
    `dedup_key` exposes that identity.
    """

    provider_id: str
    """Resolved provider id (may be 'unknown' if detection failed)."""

    fingerprint: KeyFingerprint
    source: SourceKind
    source_detail: str
    """Human-readable origin, e.g. 'OPENAI_API_KEY' or '~/.aider.conf.yml'."""

    base_url: str | None = None
    """Resolved endpoint (override if present, else the provider default)."""

    detected_via: str = ""
    """Which signal resolved the provider: 'base_url' | 'prefix' | 'env-name'."""

    validation: ValidationStatus = ValidationStatus.UNCHECKED
    validation_detail: str = ""
    """e.g. 'HTTP 200', 'HTTP 401', 'timeout' — never contains the key."""

    notes: list[str] = field(default_factory=list)
    """Advisory flags, e.g. 'apiKeyHelper present (not executed)'."""

    # ---- construction --------------------------------------------------

    @classmethod
    def capture(
        cls,
        *,
        api_key: str,
        provider_id: str,
        source: SourceKind,
        source_detail: str,
        base_url: str | None = None,
        detected_via: str = "",
    ) -> "Discovery":
        """Build a Discovery from a raw key, fingerprinting it immediately.

        The raw `api_key` argument is the only contact this object has with the
        secret, and it is converted to a fingerprint here. The caller is
        responsible for not retaining its own copy.
        """
        return cls(
            provider_id=provider_id,
            fingerprint=KeyFingerprint.of(api_key),
            source=source,
            source_detail=source_detail,
            base_url=base_url,
            detected_via=detected_via,
        )

    @property
    def dedup_key(self) -> tuple[str, str]:
        return (self.provider_id, self.fingerprint.sha256_prefix)
