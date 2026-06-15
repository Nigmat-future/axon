"""Stage 1 scanner: environment variables (zero risk, no consent prompt).

Two sources are read and labeled distinctly:

  * The live process environment (what tools actually inherit right now).
  * On Windows, the *persisted* registry values — HKCU\\Environment (user) and
    the Session Manager key (machine) — which can differ from the live process
    env until a new shell is opened. We read both and tag each by `SourceKind`
    so the dashboard can show, e.g., "set in registry but not active".

A var is treated as a key when its name matches a known provider key var, OR
ends in _API_KEY / _API_TOKEN (generic catch for providers not in the catalog).
The matching sibling base-url var (if any) is paired in to inform resolution.
"""

from __future__ import annotations

import os
import re
import sys

from ..models import Discovery, SourceKind
from ..providers import BASEURL_ENV_TO_PROVIDER, PROVIDERS, provider_for_key_env
from ..resolve import resolve

_GENERIC_KEY_RE = re.compile(r"_API_(KEY|TOKEN)$")

# Base-url env vars grouped by provider, so a key var can find its sibling.
_PROVIDER_BASEURL_VARS: dict[str, tuple[str, ...]] = {
    p.id: p.base_url_env_vars for p in PROVIDERS
}


def _looks_like_key_var(name: str) -> bool:
    if name in {v for p in PROVIDERS for v in p.key_env_vars}:
        return True
    return bool(_GENERIC_KEY_RE.search(name))


def _sibling_base_url(provider_id: str | None, env: dict[str, str]) -> str | None:
    """Find a base-url override for this provider among the given env mapping."""
    if not provider_id:
        return None
    for var in _PROVIDER_BASEURL_VARS.get(provider_id, ()):  # provider-specific
        if env.get(var):
            return env[var]
    return None


def _scan_mapping(
    env: dict[str, str], source: SourceKind
) -> list[tuple[Discovery, str]]:
    """Return (Discovery, raw_key) pairs. The raw key lives only in the pipeline."""
    found: list[tuple[Discovery, str]] = []
    for name, value in env.items():
        if not value or not _looks_like_key_var(name):
            continue
        spec = provider_for_key_env(name)
        provider_hint = spec.id if spec else None
        base_url = _sibling_base_url(provider_hint, env)
        res = resolve(api_key=value, base_url=base_url, env_var_name=name)
        discovery = Discovery.capture(
            api_key=value,
            provider_id=res.provider_id,
            source=source,
            source_detail=name,
            base_url=res.base_url,
            detected_via=res.detected_via,
        )
        found.append((discovery, value))
    return found


def _read_windows_registry_env() -> list[tuple[dict[str, str], SourceKind]]:
    """Read persisted USER and MACHINE env vars from the Windows registry.

    Returns a list of (mapping, source) pairs. Best-effort: any failure (no
    permission for HKLM, missing key) yields an empty mapping for that scope
    rather than raising. Read-only: opened with KEY_READ only.
    """
    if sys.platform != "win32":
        return []

    import winreg  # local import: Windows-only stdlib module

    scopes = [
        (
            winreg.HKEY_CURRENT_USER,
            r"Environment",
            SourceKind.ENV_REGISTRY_USER,
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            SourceKind.ENV_REGISTRY_MACHINE,
        ),
    ]
    results: list[tuple[dict[str, str], SourceKind]] = []
    for root, subkey, source in scopes:
        mapping: dict[str, str] = {}
        try:
            with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as handle:
                i = 0
                while True:
                    try:
                        name, value, _type = winreg.EnumValue(handle, i)
                    except OSError:
                        break  # no more values
                    if isinstance(value, str):
                        mapping[name] = value
                    i += 1
        except OSError:
            # HKLM often requires elevation; treat as simply unavailable.
            mapping = {}
        results.append((mapping, source))
    return results


def scan_pairs() -> list[tuple[Discovery, str]]:
    """Run the Stage 1 scan, returning (Discovery, raw_key) pairs for validation.

    Never prompts; reads only env state. The raw keys are for in-pipeline
    validation and must not be persisted by callers.
    """
    pairs: list[tuple[Discovery, str]] = []

    # Live process environment.
    pairs.extend(_scan_mapping(dict(os.environ), SourceKind.ENV_PROCESS))

    # Persisted Windows registry (user + machine), if applicable.
    for mapping, source in _read_windows_registry_env():
        pairs.extend(_scan_mapping(mapping, source))

    return pairs


def scan() -> list[Discovery]:
    """Run the Stage 1 environment scan, returning fingerprint-only discoveries."""
    return [d for d, _key in scan_pairs()]
