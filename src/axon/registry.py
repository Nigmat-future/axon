"""Provider registry and credential vault for the serving path (M1).

The discovery CLI keeps only fingerprints (SECURITY.md rule 2). A running
gateway, by contrast, MUST hold raw keys in memory to forward requests — that
is intrinsic to being a proxy, the same as LiteLLM proxy or Bifrost. This module
draws that line explicitly:

  * `build_registry()` reuses the scanners' (Discovery, raw_key) pairs to build
    an in-memory `SecretVault`. The raw keys live here, in this process, and are
    never logged, persisted, or sent anywhere but the provider's own endpoint.
  * The vault is keyed by provider id. The fingerprint-only `Discovery` is kept
    alongside for display (dashboard / `axon serve` startup banner).

Model-name routing: a client may request any model string. We classify it to a
provider by prefix (`gpt-*`/`o*` -> openai, `claude-*` -> anthropic) or an
explicit `provider/model` form, then resolve LiteLLM call params from the vault.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Discovery, SourceKind
from .providers import PROVIDERS_BY_ID
from .scanners import config_files, env


@dataclass
class ProviderCredential:
    """A live, usable credential for one provider. Server-process only."""

    provider_id: str
    api_key: str = field(repr=False)  # raw key — never in repr/logs
    base_url: str | None = None
    discovery: Discovery | None = None  # fingerprint-only metadata for display

    def redacted(self) -> str:
        fp = self.discovery.fingerprint.display() if self.discovery else "(no fp)"
        return f"{self.provider_id} [{fp}]"

    def __repr__(self) -> str:  # never leak the raw key via repr
        return f"ProviderCredential({self.redacted()}, base_url={self.base_url!r})"


@dataclass
class SecretVault:
    """In-memory store of usable provider credentials for the serving path.

    One credential per provider id (the first discovered wins; later duplicates
    are recorded as `shadowed` so the serve banner can warn rather than silently
    dropping a possibly-valid second credential). `__repr__` is redacted so the
    vault never prints raw keys.
    """

    _creds: dict[str, ProviderCredential] = field(default_factory=dict)
    shadowed: list[ProviderCredential] = field(default_factory=list)

    def add(self, cred: ProviderCredential) -> None:
        if cred.provider_id in self._creds:
            # First-wins, but don't lose the fact that another credential exists.
            self.shadowed.append(cred)
            return
        self._creds[cred.provider_id] = cred

    def get(self, provider_id: str) -> ProviderCredential | None:
        return self._creds.get(provider_id)

    def providers(self) -> list[str]:
        return list(self._creds.keys())

    def __contains__(self, provider_id: object) -> bool:
        return provider_id in self._creds

    def __len__(self) -> int:
        return len(self._creds)

    def __repr__(self) -> str:  # never leak keys via repr
        inner = ", ".join(c.redacted() for c in self._creds.values())
        return f"SecretVault({inner})"


# Model-name classification -------------------------------------------------

# Prefix -> provider id for the bare model names clients commonly send.
_MODEL_PREFIX_TO_PROVIDER: tuple[tuple[str, str], ...] = (
    ("claude-", "anthropic"),
    ("gpt-", "openai"),
    ("o1", "openai"),
    ("o3", "openai"),
    ("o4", "openai"),
    ("chatgpt", "openai"),
    ("text-embedding-", "openai"),
)


def classify_model(model: str) -> str | None:
    """Resolve a requested model string to a provider id.

    Accepts an explicit `provider/model` form (the LiteLLM convention) first,
    then falls back to bare-name prefix matching. Returns None if unresolved.
    """
    if "/" in model:
        head = model.split("/", 1)[0].lower()
        if head in PROVIDERS_BY_ID:
            return head
    lower = model.lower()
    for prefix, pid in _MODEL_PREFIX_TO_PROVIDER:
        if lower.startswith(prefix):
            return pid
    return None


def _strip_provider_prefix(model: str) -> str:
    """Return the bare model id, dropping a leading `provider/` if present."""
    if "/" in model:
        head, rest = model.split("/", 1)
        if head.lower() in PROVIDERS_BY_ID:
            return rest
    return model


@dataclass
class LiteLLMTarget:
    """Resolved parameters for a LiteLLM egress call."""

    litellm_model: str               # e.g. "openai/gpt-4o"
    api_key: str = field(repr=False)  # raw key from the vault — never in repr
    api_base: str | None = None
    provider_id: str = ""

    def __repr__(self) -> str:  # never leak the raw key via repr
        return (
            f"LiteLLMTarget(litellm_model={self.litellm_model!r}, "
            f"api_base={self.api_base!r}, provider_id={self.provider_id!r})"
        )


def resolve_target(model: str, vault: SecretVault) -> LiteLLMTarget | None:
    """Map a requested model + vault to LiteLLM call params, or None.

    None means either the provider couldn't be classified or there's no
    credential for it in the vault (the caller turns this into a 404/400).
    """
    provider_id = classify_model(model)
    if provider_id is None:
        return None
    cred = vault.get(provider_id)
    if cred is None:
        return None
    bare = _strip_provider_prefix(model)
    # LiteLLM routes by a `provider/model` string; force the resolved provider
    # so a custom base_url (e.g. an Anthropic-compatible proxy) is honored.
    litellm_model = f"{provider_id}/{bare}"
    return LiteLLMTarget(
        litellm_model=litellm_model,
        api_key=cred.api_key,
        api_base=cred.base_url,
        provider_id=provider_id,
    )


# Registry construction -----------------------------------------------------

# Providers M1 actually serves. Discovered keys for other providers are kept in
# the vault but only these are advertised as first-class in /v1/models.
SERVED_PROVIDERS: tuple[str, ...] = ("openai", "anthropic")

# Concrete, routable model ids advertised per provider in GET /v1/models, so a
# client that lists models and sends one back gets a model resolve_target
# accepts (not the bare provider id, which would 404). Approximate mid-2026
# defaults; clients may also send any other valid model string directly.
DEFAULT_MODELS: dict[str, tuple[str, ...]] = {
    "openai": ("gpt-5.5", "gpt-5.4", "gpt-5.4-nano", "gpt-4o"),
    "anthropic": (
        "claude-opus-4-8",
        "claude-sonnet-4-6",
        "claude-haiku-4-5",
    ),
}


def advertised_models(vault: "SecretVault") -> list[str]:
    """Routable model ids to advertise for the providers present in the vault."""
    out: list[str] = []
    for pid in vault.providers():
        if pid in SERVED_PROVIDERS:
            out.extend(DEFAULT_MODELS.get(pid, ()))
    return out


def build_vault(
    *,
    include_config_files: bool = True,
    served_only: bool = True,
) -> SecretVault:
    """Build a SecretVault from the discovery scanners (serving path).

    Reuses the scanners' (Discovery, raw_key) pairs. Raw keys flow into the
    vault and stay in this process. When `served_only`, only SERVED_PROVIDERS
    are loaded (OpenAI + Anthropic for M1).
    """
    pairs: list[tuple[Discovery, str]] = list(env.scan_pairs())
    if include_config_files:
        pairs.extend(config_files.scan_pairs())

    vault = SecretVault()
    for disc, raw_key in pairs:
        if not raw_key or disc.fingerprint.length == 0:
            continue  # markers (e.g. apiKeyHelper) carry no usable key
        if served_only and disc.provider_id not in SERVED_PROVIDERS:
            continue
        vault.add(
            ProviderCredential(
                provider_id=disc.provider_id,
                api_key=raw_key,
                base_url=disc.base_url,
                discovery=disc,
            )
        )
    return vault


__all__ = [
    "ProviderCredential",
    "SecretVault",
    "LiteLLMTarget",
    "classify_model",
    "resolve_target",
    "build_vault",
    "advertised_models",
    "SERVED_PROVIDERS",
    "DEFAULT_MODELS",
    "SourceKind",
]
