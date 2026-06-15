"""Provider + endpoint resolution.

Implements the detection precedence from SECURITY.md:

    base_url FIRST, key prefix SECOND, env var name LAST

because aggregators (OpenRouter, DeepSeek, local proxies) reuse OpenAI's `sk-`
prefix. A custom base_url is the strongest signal a key targets an aggregator
rather than the first-party API, so it wins.
"""

from __future__ import annotations

from dataclasses import dataclass

from .providers import (
    PROVIDERS_BY_ID,
    ProviderSpec,
    provider_by_prefix,
    provider_for_key_env,
)


@dataclass
class Resolution:
    provider_id: str
    base_url: str | None
    detected_via: str  # 'base_url' | 'prefix' | 'env-name' | 'unknown'


def _provider_for_base_url(base_url: str) -> ProviderSpec | None:
    """Match a base_url against known providers' default hosts.

    Compares on host substring so that, e.g., 'https://openrouter.ai/api/v1'
    resolves to openrouter even if the path differs. A base_url that matches no
    known host is left for prefix/env-name resolution (it may be a local proxy).
    """
    bl = base_url.lower()
    for spec in PROVIDERS_BY_ID.values():
        if not spec.default_base_url:
            continue
        # Extract the host portion of the known default for a loose contains-match.
        known_host = spec.default_base_url.lower().split("://", 1)[-1].split("/", 1)[0]
        if known_host and known_host in bl:
            return spec
    return None


def resolve(
    *,
    api_key: str,
    base_url: str | None,
    env_var_name: str | None,
) -> Resolution:
    """Resolve (provider_id, base_url, detected_via) from the available signals.

    Precedence is strict: an explicit base_url that matches a known provider
    wins outright. Otherwise we try the key prefix, then the env var name. The
    returned base_url is the explicit override if given, else the resolved
    provider's default (which may be None for Azure-style providers).
    """
    # 1) base_url first.
    if base_url:
        spec = _provider_for_base_url(base_url)
        if spec is not None:
            return Resolution(spec.id, base_url, "base_url")
        # A custom base_url that matches nothing known: keep it, but try other
        # signals to name the provider; fall back to 'unknown' (likely a local
        # or self-hosted OpenAI-compatible proxy).

    # 2) key prefix — but only DISTINCTIVE prefixes when we also have an env var
    #    name to fall back on. The bare `sk-` prefix is ambiguous (DeepSeek and
    #    many OpenAI-compatible proxies issue `sk-` keys), so it must not beat a
    #    specific env var name like DEEPSEEK_API_KEY. With no env name, even the
    #    weak `sk-` prefix is better than nothing.
    spec = provider_by_prefix(api_key, distinctive_only=bool(env_var_name))
    if spec is not None:
        return Resolution(spec.id, base_url or spec.default_base_url, "prefix")

    # 3) env var name.
    if env_var_name:
        spec = provider_for_key_env(env_var_name)
        if spec is not None:
            return Resolution(spec.id, base_url or spec.default_base_url, "env-name")

    # 3b) last resort: a weak prefix when nothing else resolved it.
    spec = provider_by_prefix(api_key, distinctive_only=False)
    if spec is not None:
        return Resolution(spec.id, base_url or spec.default_base_url, "prefix")

    # Unknown provider — typically a custom/self-hosted endpoint.
    return Resolution("unknown", base_url, "unknown" if not base_url else "base_url")
