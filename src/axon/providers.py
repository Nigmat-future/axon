"""Provider catalog: the knowledge the discovery engine matches against.

A single source of truth for: which env var names carry a key, which carry a
base-url override, each provider's default endpoint, the key-prefix signature,
and how to validate a key. Mirrors LiteLLM's normalized provider table so
detection coverage stays broad.

Detection precedence (see SECURITY.md): base_url FIRST, key prefix SECOND,
env var name LAST — because aggregators (OpenRouter, DeepSeek, local proxies)
reuse OpenAI-style `sk-` prefixes.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProviderSpec:
    """Static knowledge about one LLM provider."""

    id: str
    """Canonical provider id, e.g. 'openai', 'anthropic', 'deepseek'."""

    display_name: str

    key_env_vars: tuple[str, ...]
    """Env var names that carry this provider's API key, most-specific first."""

    base_url_env_vars: tuple[str, ...] = ()
    """Env var names that override the endpoint (e.g. OPENAI_BASE_URL)."""

    default_base_url: str | None = None
    """First-party API base. None for providers with no fixed default (Azure)."""

    key_prefixes: tuple[str, ...] = ()
    """Distinctive key prefixes, e.g. ('sk-ant-',). Empty if not distinctive."""

    # Validation: most providers expose an OpenAI-style GET {base_url}/models.
    # `validate_path` is appended to the resolved base_url.
    validate_path: str = "/models"

    # Header style for the validation probe. 'bearer' => Authorization: Bearer KEY.
    # 'x-api-key' => x-api-key: KEY (Anthropic). 'google' => ?key=KEY query param.
    auth_style: str = "bearer"

    extra_headers: dict[str, str] = field(default_factory=dict)
    """Static headers required by the validation probe (e.g. anthropic-version)."""


# Ordering matters for prefix matching: list more-specific prefixes (sk-ant-,
# sk-or-, sk-proj-) ahead of the generic sk-. Resolution code sorts by prefix
# length, but keep the catalog readable too.
PROVIDERS: tuple[ProviderSpec, ...] = (
    ProviderSpec(
        id="openrouter",
        display_name="OpenRouter",
        key_env_vars=("OPENROUTER_API_KEY",),
        base_url_env_vars=("OPENROUTER_BASE_URL", "OPENROUTER_API_BASE"),
        default_base_url="https://openrouter.ai/api/v1",
        key_prefixes=("sk-or-",),
    ),
    ProviderSpec(
        id="anthropic",
        display_name="Anthropic (Claude)",
        key_env_vars=("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"),
        base_url_env_vars=("ANTHROPIC_BASE_URL",),
        default_base_url="https://api.anthropic.com/v1",
        key_prefixes=("sk-ant-",),
        auth_style="x-api-key",
        extra_headers={"anthropic-version": "2023-06-01"},
    ),
    ProviderSpec(
        id="deepseek",
        display_name="DeepSeek",
        key_env_vars=("DEEPSEEK_API_KEY",),
        base_url_env_vars=("DEEPSEEK_BASE_URL", "DEEPSEEK_API_BASE"),
        default_base_url="https://api.deepseek.com/v1",
        # DeepSeek reuses sk- prefix; rely on env var name / base_url.
    ),
    ProviderSpec(
        id="gemini",
        display_name="Google Gemini",
        key_env_vars=("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        base_url_env_vars=("GEMINI_BASE_URL",),
        default_base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        # OpenAI-compatible surface; /models works with Bearer auth.
    ),
    ProviderSpec(
        id="mistral",
        display_name="Mistral",
        key_env_vars=("MISTRAL_API_KEY",),
        base_url_env_vars=("MISTRAL_API_BASE", "MISTRAL_BASE_URL"),
        default_base_url="https://api.mistral.ai/v1",
    ),
    ProviderSpec(
        id="groq",
        display_name="Groq",
        key_env_vars=("GROQ_API_KEY",),
        base_url_env_vars=("GROQ_API_BASE", "GROQ_BASE_URL"),
        default_base_url="https://api.groq.com/openai/v1",
        key_prefixes=("gsk_",),
    ),
    ProviderSpec(
        id="xai",
        display_name="xAI (Grok)",
        key_env_vars=("XAI_API_KEY",),
        base_url_env_vars=("XAI_BASE_URL", "XAI_API_BASE"),
        default_base_url="https://api.x.ai/v1",
        key_prefixes=("xai-",),
    ),
    ProviderSpec(
        id="together",
        display_name="Together AI",
        key_env_vars=("TOGETHER_API_KEY", "TOGETHERAI_API_KEY"),
        base_url_env_vars=("TOGETHER_API_BASE", "TOGETHER_BASE_URL"),
        default_base_url="https://api.together.xyz/v1",
    ),
    ProviderSpec(
        id="cohere",
        display_name="Cohere",
        key_env_vars=("COHERE_API_KEY", "CO_API_KEY"),
        base_url_env_vars=("COHERE_BASE_URL",),
        default_base_url="https://api.cohere.ai/compatibility/v1",
    ),
    ProviderSpec(
        id="perplexity",
        display_name="Perplexity",
        key_env_vars=("PERPLEXITY_API_KEY", "PERPLEXITYAI_API_KEY"),
        base_url_env_vars=("PERPLEXITY_API_BASE", "PERPLEXITY_BASE_URL"),
        default_base_url="https://api.perplexity.ai",
    ),
    ProviderSpec(
        id="azure-openai",
        display_name="Azure OpenAI",
        key_env_vars=("AZURE_OPENAI_API_KEY", "AZURE_API_KEY"),
        base_url_env_vars=("AZURE_OPENAI_ENDPOINT", "AZURE_API_BASE"),
        default_base_url=None,  # Azure has no fixed default; endpoint is required.
        auth_style="x-api-key",  # Azure uses 'api-key' header; handled in validator.
    ),
    # OpenAI last: its sk- / sk-proj- prefixes are the generic fallback, so more
    # specific providers above win prefix resolution first.
    ProviderSpec(
        id="openai",
        display_name="OpenAI",
        key_env_vars=("OPENAI_API_KEY",),
        base_url_env_vars=("OPENAI_BASE_URL", "OPENAI_API_BASE"),
        default_base_url="https://api.openai.com/v1",
        key_prefixes=("sk-proj-", "sk-"),
    ),
)

# Lookups -------------------------------------------------------------------

PROVIDERS_BY_ID: dict[str, ProviderSpec] = {p.id: p for p in PROVIDERS}

# Map every key env var name -> provider id (for env scanner detection).
KEY_ENV_TO_PROVIDER: dict[str, str] = {
    var: p.id for p in PROVIDERS for var in p.key_env_vars
}

# Map every base-url env var name -> provider id.
BASEURL_ENV_TO_PROVIDER: dict[str, str] = {
    var: p.id for p in PROVIDERS for var in p.base_url_env_vars
}


def provider_for_key_env(var_name: str) -> ProviderSpec | None:
    """Return the provider whose key env var matches `var_name`, if any."""
    pid = KEY_ENV_TO_PROVIDER.get(var_name)
    return PROVIDERS_BY_ID.get(pid) if pid else None


# Prefixes this weak/ambiguous: matched by many providers (DeepSeek, generic
# OpenAI-compatible proxies all issue bare `sk-` keys). A weak prefix must lose
# to a specific env var name during resolution; only distinctive prefixes win.
_WEAK_PREFIXES = frozenset({"sk-"})


def provider_by_prefix(
    api_key: str, *, distinctive_only: bool = False
) -> ProviderSpec | None:
    """Resolve a provider by distinctive key prefix (longest prefix wins).

    Generic `sk-` (OpenAI) loses to `sk-ant-`, `sk-or-`, `sk-proj-` because those
    are longer. With `distinctive_only=True`, the ambiguous bare `sk-` prefix is
    ignored entirely so a specific env var name (e.g. DEEPSEEK_API_KEY) can win
    instead of every `sk-` key collapsing to OpenAI. Returns None when no
    eligible prefix matches.
    """
    best: ProviderSpec | None = None
    best_len = -1
    for spec in PROVIDERS:
        for prefix in spec.key_prefixes:
            if distinctive_only and prefix in _WEAK_PREFIXES:
                continue
            if api_key.startswith(prefix) and len(prefix) > best_len:
                best, best_len = spec, len(prefix)
    return best
