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


if __name__ == "__main__":
    app()
