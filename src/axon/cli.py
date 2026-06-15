"""Axon CLI.

`axon scan` runs the discovery engine and prints a table of discovered
providers — by fingerprint only, never key values. Stage 2 (config files) is
announced before reading; `--validate` opts into the zero-cost probe.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__
from .discovery import discover, summarize_providers
from .models import SourceKind, ValidationStatus
from .providers import PROVIDERS_BY_ID

app = typer.Typer(
    add_completion=False,
    help="Axon — local-first LLM router. Discovers API keys you already have.",
)
console = Console()


_STATUS_STYLE = {
    ValidationStatus.AUTHENTICATES: ("green", "✓ authenticates"),
    ValidationStatus.INVALID: ("red", "✗ invalid"),
    ValidationStatus.UNREACHABLE: ("yellow", "? unreachable"),
    ValidationStatus.ERROR: ("yellow", "! error"),
    ValidationStatus.UNCHECKED: ("dim", "– unchecked"),
}

_SOURCE_LABEL = {
    SourceKind.ENV_PROCESS: "env (process)",
    SourceKind.ENV_REGISTRY_USER: "env (registry/user)",
    SourceKind.ENV_REGISTRY_MACHINE: "env (registry/machine)",
    SourceKind.DOTENV: ".env file",
    SourceKind.CONFIG_FILE: "config file",
    SourceKind.CONFIG_SQLITE: "Cursor sqlite",
    SourceKind.KEYCHAIN: "OS keychain",
}


def _provider_name(pid: str) -> str:
    spec = PROVIDERS_BY_ID.get(pid)
    return spec.display_name if spec else pid


@app.command()
def scan(
    validate: bool = typer.Option(
        False,
        "--validate",
        "-v",
        help="Probe each key against its provider endpoint (zero-cost /models). "
        "Makes outbound calls only to provider endpoints.",
    ),
    no_config_files: bool = typer.Option(
        False,
        "--no-config-files",
        help="Skip Stage 2 (config files & .env); scan environment variables only.",
    ),
) -> None:
    """Scan this machine for already-configured LLM API keys."""
    include_config = not no_config_files

    if include_config:
        # Stage 2 consent announcement (SECURITY.md rule 4): name the files first.
        from .scanners.config_files import scanned_files

        files = scanned_files()
        if files:
            console.print(
                "[dim]Stage 2 will read these config files (read-only):[/dim]"
            )
            for f in files:
                console.print(f"  [dim]• {f}[/dim]")
        else:
            console.print("[dim]Stage 2: no known config files found to read.[/dim]")

    with console.status("Scanning…"):
        report = discover(include_config_files=include_config, validate=validate)

    _render(report.discoveries, validated=validate)


def _render(discoveries: list, validated: bool) -> None:
    if not discoveries:
        console.print(
            "\n[yellow]No API keys discovered.[/yellow] "
            "Set e.g. OPENAI_API_KEY / DEEPSEEK_API_KEY in your environment, "
            "or check your tool config files."
        )
        return

    table = Table(title="Discovered providers", title_style="bold", expand=False)
    table.add_column("Provider", style="bold cyan")
    table.add_column("Source")
    table.add_column("Endpoint", style="dim")
    table.add_column("Key", style="dim")
    table.add_column("Via", style="dim")
    if validated:
        table.add_column("Status")

    # Sort: known providers first (alpha), unknown last.
    def sort_key(d):
        return (d.provider_id == "unknown", d.provider_id, d.source.value)

    for d in sorted(discoveries, key=sort_key):
        row = [
            _provider_name(d.provider_id),
            _SOURCE_LABEL.get(d.source, d.source.value),
            d.base_url or "[red]— none —[/red]",
            d.fingerprint.display(),
            d.detected_via,
        ]
        if validated:
            style, label = _STATUS_STYLE[d.validation]
            cell = Text(label, style=style)
            if d.validation_detail and d.validation == ValidationStatus.AUTHENTICATES:
                pass  # keep it clean; detail is HTTP 200
            row.append(cell)
        table.add_row(*row)

    console.print()
    console.print(table)

    # Notes (e.g. apiKeyHelper present, duplicate sources).
    noted = [d for d in discoveries if d.notes]
    if noted:
        console.print("\n[dim]Notes:[/dim]")
        for d in noted:
            for note in d.notes:
                console.print(f"  [dim]• {_provider_name(d.provider_id)}: {note}[/dim]")

    counts = summarize_providers(discoveries)
    summary = ", ".join(
        f"{_provider_name(p)} x{n}" for p, n in sorted(counts.items())
    )
    n = len(discoveries)
    console.print(f"\n[bold]{n}[/bold] discover{'y' if n == 1 else 'ies'}: {summary}")
    if validated:
        live = sum(
            1 for d in discoveries if d.validation == ValidationStatus.AUTHENTICATES
        )
        console.print(
            f"[green]{live}[/green] key(s) authenticate "
            "[dim](authentication only — does not confirm quota/credit)[/dim]"
        )
    else:
        console.print(
            "[dim]Run with --validate to probe which keys authenticate.[/dim]"
        )


@app.command()
def version() -> None:
    """Print the Axon version."""
    console.print(f"axon {__version__}")


_LOCALHOST = {"127.0.0.1", "::1", "localhost"}


@app.command()
def serve(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Bind address. Defaults to localhost. Binding a non-localhost "
        "address requires AXON_API_KEY (the endpoint holds your provider keys).",
    ),
    port: int = typer.Option(4000, "--port", "-p", help="Port to listen on."),
    no_config_files: bool = typer.Option(
        False,
        "--no-config-files",
        help="Build the credential vault from environment variables only.",
    ),
) -> None:
    """Start the dual-ingress gateway (OpenAI + Anthropic compatible).

    Discovers your configured OpenAI/Anthropic keys, holds them in memory, and
    serves POST /v1/chat/completions, GET /v1/models, and POST /v1/messages.
    """
    import os

    import uvicorn

    from .registry import build_vault
    from .server.app import create_app

    # Security gate: a key-holding endpoint must not be exposed unauthenticated.
    is_local = host in _LOCALHOST
    if not is_local and not os.environ.get("AXON_API_KEY"):
        console.print(
            f"[red]Refusing to bind {host} without AXON_API_KEY.[/red]\n"
            "This endpoint holds your provider API keys; an open bind would let "
            "anyone on the network use them. Set AXON_API_KEY to require an "
            "inbound key, or bind 127.0.0.1 (default)."
        )
        raise typer.Exit(code=2)

    vault = build_vault(include_config_files=not no_config_files)
    if len(vault) == 0:
        console.print(
            "[yellow]No OpenAI/Anthropic keys discovered.[/yellow] "
            "Run [bold]axon scan[/bold] to see what's detectable, then set a key "
            "(e.g. OPENAI_API_KEY / ANTHROPIC_API_KEY)."
        )
        raise typer.Exit(code=1)

    console.print(f"[bold]Axon[/bold] serving on http://{host}:{port}")
    from .providers import PROVIDERS_BY_ID

    for pid in vault.providers():
        cred = vault.get(pid)
        fp = cred.discovery.fingerprint.display() if cred.discovery else ""
        spec = PROVIDERS_BY_ID.get(pid)
        default_base = spec.default_base_url if spec else None
        endpoint = cred.base_url or default_base or "(provider default)"
        console.print(f"  [cyan]{pid}[/cyan]  {fp}  -> [dim]{endpoint}[/dim]")
        # Warn loudly: your real key will be sent to this endpoint. A custom or
        # non-https base_url (possibly from an untrusted config file) is exactly
        # how a poisoned config could exfiltrate the key.
        if cred.base_url and default_base and cred.base_url.rstrip("/") != default_base.rstrip("/"):
            console.print(
                f"    [yellow]! custom endpoint for {pid} (not the provider default). "
                f"Your {pid} key will be sent here.[/yellow]"
            )
        if cred.base_url and cred.base_url.lower().startswith("http://"):
            console.print(
                f"    [red]! INSECURE: {pid} endpoint is http:// — the key is sent "
                f"in cleartext.[/red]"
            )
    console.print(
        "  [dim]OpenAI:    POST /v1/chat/completions, GET /v1/models[/dim]\n"
        "  [dim]Anthropic: POST /v1/messages[/dim]"
    )
    # Warn when a second credential for an already-loaded provider was dropped —
    # e.g. a stale env key shadowing a valid config-file key (first-wins order).
    for shadow in vault.shadowed:
        active = vault.get(shadow.provider_id)
        active_src = (
            active.discovery.source.value if active and active.discovery else "?"
        )
        shadow_src = shadow.discovery.source.value if shadow.discovery else "?"
        console.print(
            f"  [yellow]! {shadow.provider_id}: a second credential from "
            f"{shadow_src} was ignored (using the one from {active_src}). "
            f"Run [bold]axon scan[/bold] to compare.[/yellow]"
        )
    if os.environ.get("AXON_API_KEY"):
        console.print("  [dim]Inbound auth: required (AXON_API_KEY set)[/dim]")
    elif is_local:
        console.print("  [dim]Inbound auth: none (localhost only)[/dim]")

    uvicorn.run(create_app(vault), host=host, port=port, log_level="info")


if __name__ == "__main__":
    app()
