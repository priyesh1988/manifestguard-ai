from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .config import Defaults, load_defaults
from .engine import fix_target, highest_severity, scan_target
from .memory import MemoryStore
from .policy_export import export_builtin_kyverno
from .reporting import findings_to_json, write_report

app = typer.Typer(help="Scan and auto-fix Kubernetes manifests with remediation memory.")
console = Console()


def _defaults(config: Optional[Path]) -> Defaults:
    return load_defaults(config)


def _memory_store(db_path: Optional[Path], defaults: Defaults) -> MemoryStore:
    return MemoryStore(db_path or defaults.db_path)


@app.command()
def scan(
    target: Path,
    fail_on: Optional[str] = typer.Option(None, help="Fail if findings contain this severity or higher."),
    report_json: Optional[Path] = typer.Option(None, help="Optional JSON output path."),
) -> None:
    results = scan_target(target)
    table = Table(title="ManifestGuard Findings")
    table.add_column("File")
    table.add_column("Resource")
    table.add_column("Severity")
    table.add_column("Code")
    table.add_column("Message")
    all_findings = []

    for item in results:
        for finding in item["findings"]:
            all_findings.append(finding)
            table.add_row(
                item["file_path"],
                f"{finding.resource_kind}/{finding.resource_name}",
                finding.severity,
                finding.code,
                finding.message,
            )

    console.print(table)
    if report_json:
        write_report(report_json, {"findings": findings_to_json(all_findings)})

    if fail_on:
        threshold = {"low": 1, "medium": 2, "high": 3, "critical": 4}[fail_on]
        current = highest_severity(all_findings)
        if current and {"low": 1, "medium": 2, "high": 3, "critical": 4}[current] >= threshold:
            raise typer.Exit(code=2)


@app.command()
def fix(
    target: Path,
    write: bool = typer.Option(False, "--write", help="Write fixes back to files."),
    db_path: Optional[Path] = typer.Option(None, help="SQLite path for remediation memory."),
    config: Optional[Path] = typer.Option(None, help="Optional manifestguard config file."),
    report_json: Optional[Path] = typer.Option(None, help="Optional JSON output path."),
) -> None:
    defaults = _defaults(config)
    memory = _memory_store(db_path, defaults)
    try:
        summary = fix_target(target, memory=memory, write=write, defaults=defaults)
    finally:
        memory.close()

    console.print(summary["totals"])
    if report_json:
        write_report(report_json, summary)


@app.command()
def history(
    signature: str = typer.Option(..., help="Issue signature to inspect."),
    db_path: Optional[Path] = typer.Option(None, help="SQLite path for remediation memory."),
    config: Optional[Path] = typer.Option(None, help="Optional manifestguard config file."),
) -> None:
    defaults = _defaults(config)
    memory = _memory_store(db_path, defaults)
    try:
        stats = memory.stats_for_signature(signature)
        preferred = memory.best_patch_for_signature(signature)
    finally:
        memory.close()

    console.print({
        "signature": signature,
        "stats": stats,
        "preferred_patch": preferred,
    })


@app.command('export-kyverno')
def export_kyverno(
    output: Path = typer.Option(Path('dist/kyverno/manifestguard-policies.yaml'), help='Output path for generated policies.'),
) -> None:
    export_builtin_kyverno(output)
    console.print({"exported": str(output)})


@app.command()
def version() -> None:
    console.print({"name": "manifest-guard", "version": "0.2.0"})


if __name__ == "__main__":
    app()
