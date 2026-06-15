"""Key validation via a zero-cost probe.

A `GET {base_url}{validate_path}` with the provider's auth header. 200 means
the key *authenticates* — it does NOT prove the account has quota or credit, so
we report `AUTHENTICATES`, never "working". Outbound calls go ONLY to the
provider's own resolved endpoint (SECURITY.md rule 3).

The validator needs the raw key, which the fingerprint-only Discovery does not
hold. So validation takes a (Discovery, raw_key) pairing supplied by the caller
at the moment of probing; the key is used for one request and not stored.
"""

from __future__ import annotations

import httpx

from .models import Discovery, ValidationStatus
from .providers import PROVIDERS_BY_ID

_TIMEOUT = httpx.Timeout(8.0, connect=4.0)


def _auth_headers(provider_id: str, api_key: str) -> dict[str, str]:
    spec = PROVIDERS_BY_ID.get(provider_id)
    style = spec.auth_style if spec else "bearer"
    headers: dict[str, str] = {}
    if spec:
        headers.update(spec.extra_headers)
    if provider_id == "azure-openai":
        headers["api-key"] = api_key
    elif style == "x-api-key":
        headers["x-api-key"] = api_key
    else:  # bearer (default), and google's OpenAI-compat surface accepts it too
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _validate_url(provider_id: str, base_url: str | None) -> str | None:
    spec = PROVIDERS_BY_ID.get(provider_id)
    base = base_url or (spec.default_base_url if spec else None)
    if not base:
        return None
    path = spec.validate_path if spec else "/models"
    return base.rstrip("/") + path


def validate(discovery: Discovery, api_key: str) -> tuple[ValidationStatus, str]:
    """Probe one key. Returns (status, detail). `detail` never contains the key."""
    url = _validate_url(discovery.provider_id, discovery.base_url)
    if not url:
        return ValidationStatus.ERROR, "no endpoint to probe (provider unknown)"

    headers = _auth_headers(discovery.provider_id, api_key)
    try:
        resp = httpx.get(url, headers=headers, timeout=_TIMEOUT, follow_redirects=True)
    except httpx.TimeoutException:
        return ValidationStatus.UNREACHABLE, "timeout"
    except httpx.HTTPError as exc:
        return ValidationStatus.UNREACHABLE, type(exc).__name__

    if resp.status_code == 200:
        return ValidationStatus.AUTHENTICATES, "HTTP 200"
    if resp.status_code in (401, 403):
        return ValidationStatus.INVALID, f"HTTP {resp.status_code}"
    return ValidationStatus.ERROR, f"HTTP {resp.status_code}"
