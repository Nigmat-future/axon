"""Discovery orchestrator: run the staged scanners, dedup, optionally validate.

This is the public entry point the CLI uses. It coordinates the consent model:
Stage 1 (env) always runs; Stage 2 (config files) runs only when enabled, and
the caller is expected to have announced the file list first (see SECURITY.md).

Raw keys live ONLY inside this function's local scope, used to validate and
then dropped. The returned `Discovery` objects are fingerprint-only.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Discovery, ValidationStatus
from .scanners import config_files, env
from .validator import validate as _validate_key


@dataclass
class DiscoveryReport:
    discoveries: list[Discovery]
    scanned_files: list[str]
    stages_run: list[str]


def _dedup_pairs(
    pairs: list[tuple[Discovery, str]],
) -> list[tuple[Discovery, str]]:
    """Collapse the same credential found in multiple places into one.

    Identity is (provider_id, sha256_prefix). The first occurrence wins, but we
    append later sources to its notes so the dashboard can show 'also in: …'.
    """
    by_key: dict[tuple[str, str], tuple[Discovery, str]] = {}
    order: list[tuple[str, str]] = []
    for disc, key in pairs:
        k = disc.dedup_key
        if k not in by_key:
            by_key[k] = (disc, key)
            order.append(k)
        else:
            existing, _ = by_key[k]
            existing.notes.append(
                f"also found in {disc.source.value} ({disc.source_detail})"
            )
    return [by_key[k] for k in order]


def discover(
    *,
    include_config_files: bool = True,
    validate: bool = False,
) -> DiscoveryReport:
    """Run discovery. Returns fingerprint-only results.

    Args:
        include_config_files: run Stage 2 (config files & .env). The caller
            should announce the file list (see `config_files.scanned_files()`)
            before enabling this.
        validate: probe each discovery against its provider endpoint. Adds
            latency and makes outbound calls (only to provider endpoints).
    """
    stages_run = ["env"]
    pairs: list[tuple[Discovery, str]] = list(env.scan_pairs())

    scanned: list[str] = []
    if include_config_files:
        scanned = config_files.scanned_files()
        pairs.extend(config_files.scan_pairs())
        stages_run.append("config_files")

    pairs = _dedup_pairs(pairs)

    if validate:
        for disc, raw_key in pairs:
            if disc.fingerprint.length == 0:
                # Non-key marker (e.g. apiKeyHelper present) — nothing to probe.
                continue
            status, detail = _validate_key(disc, raw_key)
            disc.validation = status
            disc.validation_detail = detail

    discoveries = [disc for disc, _ in pairs]
    # raw keys (the second tuple element) go out of scope here and are dropped.
    return DiscoveryReport(
        discoveries=discoveries,
        scanned_files=scanned,
        stages_run=stages_run,
    )


def summarize_providers(discoveries: list[Discovery]) -> dict[str, int]:
    """Count discoveries per provider id (for a quick summary line)."""
    counts: dict[str, int] = {}
    for d in discoveries:
        counts[d.provider_id] = counts.get(d.provider_id, 0) + 1
    return counts


__all__ = [
    "DiscoveryReport",
    "discover",
    "summarize_providers",
    "ValidationStatus",
]
