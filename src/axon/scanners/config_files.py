"""Stage 2 scanner: config files & .env (low risk; caller announces before read).

Reads a FIXED ALLOWLIST of known credential locations — never a recursive disk
sweep (that is itself a security smell, and slow). All reads are read-only.

Sources covered:
  * .env files in cwd and home (dotenv convention).
  * Tool config files: ~/.claude/settings.json (+ apiKeyHelper note, never run),
    ~/.claude.json, ~/.aider.conf.yml, ~/.continue/config.{json,yaml}.
  * Cursor's globalStorage SQLite (state.vscdb), opened read-only.

Anything that looks like an API key is fingerprinted via Discovery.capture and
the raw value is not retained. File contents are treated as untrusted data.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from collections.abc import Iterator
from pathlib import Path

from ..models import Discovery, SourceKind
from ..resolve import resolve

# A loose key shape used when scanning opaque blobs (SQLite, JSON values):
# common provider key prefixes followed by URL-safe key chars.
_KEY_BLOB_RE = re.compile(r"\b(sk-[A-Za-z0-9_\-]{16,}|gsk_[A-Za-z0-9]{16,}|xai-[A-Za-z0-9]{16,})\b")

_ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$")


def _home() -> Path:
    return Path.home()


def _dedup_paths(paths: Iterator[Path]) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    for p in paths:
        try:
            rp = p.resolve()
        except OSError:
            rp = p
        if rp not in seen:
            seen.add(rp)
            out.append(p)
    return out


def candidate_paths() -> list[Path]:
    """The fixed allowlist of files this scanner may read, those that exist."""
    home = _home()
    cwd = Path.cwd()
    candidates = [
        cwd / ".env",
        home / ".env",
        home / ".claude" / "settings.json",
        home / ".claude.json",
        home / ".aider.conf.yml",
        home / ".aider.conf.yaml",
        home / ".continue" / "config.json",
        home / ".continue" / "config.yaml",
    ]
    # Cursor's SQLite store (Windows path; harmless if absent elsewhere).
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidates.append(
            Path(appdata) / "Cursor" / "User" / "globalStorage" / "state.vscdb"
        )
    existing = (p for p in candidates if p.exists() and p.is_file())
    return _dedup_paths(existing)


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _scan_dotenv(path: Path) -> list[tuple[Discovery, str]]:
    found: list[tuple[Discovery, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return found
    # Build the file's own var mapping first so we can pair key+base_url.
    pairs: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _ENV_LINE_RE.match(line)
        if m:
            pairs[m.group(1)] = _strip_quotes(m.group(2))

    from ..providers import PROVIDERS, provider_for_key_env

    baseurl_vars = {p.id: p.base_url_env_vars for p in PROVIDERS}
    key_vars = {v for p in PROVIDERS for v in p.key_env_vars}
    generic = re.compile(r"_API_(KEY|TOKEN)$")

    for name, value in pairs.items():
        if not value:
            continue
        if name not in key_vars and not generic.search(name):
            continue
        spec = provider_for_key_env(name)
        base_url = None
        if spec:
            for bvar in baseurl_vars.get(spec.id, ()):  # sibling override
                if pairs.get(bvar):
                    base_url = pairs[bvar]
                    break
        res = resolve(api_key=value, base_url=base_url, env_var_name=name)
        discovery = Discovery.capture(
            api_key=value,
            provider_id=res.provider_id,
            source=SourceKind.DOTENV,
            source_detail=str(path),
            base_url=res.base_url,
            detected_via=res.detected_via,
        )
        found.append((discovery, value))
    return found


def _walk_json_for_keys(
    obj: object, path: Path, note_apikeyhelper: bool
) -> list[tuple[Discovery, str]]:
    """Find credentials in a parsed JSON/YAML structure two ways:

    1. By FIELD NAME — a dict field whose name is a known key env var (e.g.
       ANTHROPIC_AUTH_TOKEN, OPENAI_API_KEY) or matches the generic
       *_API_KEY / *_API_TOKEN pattern, with a non-empty string value. A sibling
       base_url field in the same dict is paired in for resolution. This catches
       Claude Code's `env` block and similar tool configs.
    2. By VALUE SHAPE — any string value matching a distinctive key prefix
       (sk-…, gsk_…, xai-…), for keys stored under non-obvious field names.

    Detects an `apiKeyHelper` field (Claude Code) and records its presence as a
    note WITHOUT executing it. Returns (Discovery, raw_key) pairs; the
    apiKeyHelper marker carries an empty raw key (it is not a secret).
    """
    from ..providers import PROVIDERS, provider_for_key_env

    key_field_names = {v for p in PROVIDERS for v in p.key_env_vars}
    baseurl_field_names = {v for p in PROVIDERS for v in p.base_url_env_vars}
    baseurl_vars_by_provider = {p.id: p.base_url_env_vars for p in PROVIDERS}
    generic = re.compile(r"_API_(KEY|TOKEN)$")

    found: list[tuple[Discovery, str]] = []

    def sibling_base_url(d: dict, provider_id: str | None) -> str | None:
        if provider_id:
            for bvar in baseurl_vars_by_provider.get(provider_id, ()):
                v = d.get(bvar)
                if isinstance(v, str) and v:
                    return v
        # Fall back to any recognized base-url field in the same object.
        for name in baseurl_field_names:
            v = d.get(name)
            if isinstance(v, str) and v:
                return v
        return None

    def visit(node: object, key_hint: str | None) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if note_apikeyhelper and k == "apiKeyHelper" and v:
                    found.append(
                        (
                            Discovery(
                                provider_id="anthropic",
                                fingerprint=_marker_fingerprint(),
                                source=SourceKind.CONFIG_FILE,
                                source_detail=f"{path} (apiKeyHelper)",
                                base_url=None,
                                detected_via="config-marker",
                                notes=["apiKeyHelper present - not executed"],
                            ),
                            "",
                        )
                    )
                # Field-name detection (most tool configs store keys this way).
                if (
                    isinstance(k, str)
                    and isinstance(v, str)
                    and v
                    and (k in key_field_names or generic.search(k))
                ):
                    spec = provider_for_key_env(k)
                    base_url = sibling_base_url(node, spec.id if spec else None)
                    res = resolve(api_key=v, base_url=base_url, env_var_name=k)
                    found.append(
                        (
                            Discovery.capture(
                                api_key=v,
                                provider_id=res.provider_id,
                                source=SourceKind.CONFIG_FILE,
                                source_detail=f"{path} (field: {k})",
                                base_url=res.base_url,
                                detected_via=res.detected_via,
                            ),
                            v,
                        )
                    )
                    continue  # don't also value-scan this known field
                visit(v, k if isinstance(k, str) else None)
        elif isinstance(node, list):
            for item in node:
                visit(item, key_hint)
        elif isinstance(node, str):
            for m in _KEY_BLOB_RE.finditer(node):
                token = m.group(0)
                res = resolve(api_key=token, base_url=None, env_var_name=None)
                found.append(
                    (
                        Discovery.capture(
                            api_key=token,
                            provider_id=res.provider_id,
                            source=SourceKind.CONFIG_FILE,
                            source_detail=f"{path}"
                            + (f" (field: {key_hint})" if key_hint else ""),
                            base_url=res.base_url,
                            detected_via=res.detected_via,
                        ),
                        token,
                    )
                )

    visit(obj, None)
    return found


def _marker_fingerprint():
    # A sentinel fingerprint for non-key markers (e.g. apiKeyHelper present).
    from ..models import KeyFingerprint

    return KeyFingerprint(last4="----", sha256_prefix="marker000000", length=0)


def _scan_config_file(path: Path) -> list[tuple[Discovery, str]]:
    name = path.name.lower()
    is_claude = "claude" in str(path).lower()
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    data: object | None = None
    if name.endswith((".json",)) or name == ".claude.json":
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            data = None
    elif name.endswith((".yml", ".yaml")):
        try:
            import yaml

            data = yaml.safe_load(raw)
        except Exception:  # noqa: BLE001 — malformed yaml shouldn't crash a scan
            data = None
    if data is not None:
        return _walk_json_for_keys(data, path, note_apikeyhelper=is_claude)
    # Fallback: scan raw text for key-shaped tokens.
    return _scan_raw_text(raw, path, SourceKind.CONFIG_FILE)


def _scan_raw_text(
    raw: str, path: Path, source: SourceKind
) -> list[tuple[Discovery, str]]:
    found: list[tuple[Discovery, str]] = []
    for m in _KEY_BLOB_RE.finditer(raw):
        token = m.group(0)
        res = resolve(api_key=token, base_url=None, env_var_name=None)
        found.append(
            (
                Discovery.capture(
                    api_key=token,
                    provider_id=res.provider_id,
                    source=source,
                    source_detail=str(path),
                    base_url=res.base_url,
                    detected_via=res.detected_via,
                ),
                token,
            )
        )
    return found


def _scan_sqlite(path: Path) -> list[tuple[Discovery, str]]:
    """Read Cursor's state.vscdb read-only and scan stored values for keys.

    Opened with mode=ro and immutable=1 so a running Cursor's lock can't block
    or be disturbed. Best-effort: any failure yields no discoveries.
    """
    found: list[tuple[Discovery, str]] = []
    uri = f"file:{path}?mode=ro&immutable=1"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=1.0)
    except sqlite3.Error:
        return found
    try:
        cur = conn.cursor()
        # Cursor stores settings as key/value blobs in ItemTable / cursorDiskKV.
        for table in ("ItemTable", "cursorDiskKV"):
            try:
                cur.execute(f"SELECT value FROM {table}")  # noqa: S608 — fixed names
            except sqlite3.Error:
                continue
            for (value,) in cur.fetchall():
                if isinstance(value, (bytes, bytearray)):
                    value = value.decode("utf-8", errors="ignore")
                if isinstance(value, str) and ("sk-" in value or "key" in value.lower()):
                    found.extend(_scan_raw_text(value, path, SourceKind.CONFIG_SQLITE))
    finally:
        conn.close()
    # Dedup within the file (the same key may appear in multiple rows).
    return _dedup_discoveries(found)


def _dedup_discoveries(
    items: list[tuple[Discovery, str]],
) -> list[tuple[Discovery, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[tuple[Discovery, str]] = []
    for d, key in items:
        if d.dedup_key not in seen:
            seen.add(d.dedup_key)
            out.append((d, key))
    return out


def scan_pairs() -> list[tuple[Discovery, str]]:
    """Run the Stage 2 scan, returning (Discovery, raw_key) pairs for validation."""
    pairs: list[tuple[Discovery, str]] = []
    for path in candidate_paths():
        name = path.name.lower()
        if name == ".env":
            pairs.extend(_scan_dotenv(path))
        elif name == "state.vscdb":
            pairs.extend(_scan_sqlite(path))
        else:
            pairs.extend(_scan_config_file(path))
    return pairs


def scan() -> list[Discovery]:
    """Run the Stage 2 config-file scan, returning fingerprint-only discoveries."""
    return [d for d, _key in scan_pairs()]


def scanned_files() -> list[str]:
    """The list of files the scan will read — for the pre-read announcement."""
    return [str(p) for p in candidate_paths()]
