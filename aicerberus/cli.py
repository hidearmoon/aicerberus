"""AICerberus CLI — `cerberus scan [path]`."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aicerberus import __version__
from aicerberus.engine import ScanEngine
from aicerberus.models import (
    ScanResult,
    Severity,
)
from aicerberus.scanners.sbom import SBOMGenerator

console = Console()
err_console = Console(stderr=True)

SEVERITY_STYLES: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "UNKNOWN": "dim",
}

SEVERITY_ICONS: dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "UNKNOWN": "⚪",
}


def _sev_style(severity: Severity) -> str:
    return SEVERITY_STYLES.get(severity.value, "")


def _sev_icon(severity: Severity) -> str:
    return SEVERITY_ICONS.get(severity.value, "")


def _filter_by_severity(
    result: ScanResult, min_severity: str
) -> ScanResult:
    """Return a new ScanResult filtered to findings at or above min_severity."""
    rank_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    min_rank = rank_map.get(min_severity.upper(), 0)

    filtered = ScanResult(
        target_path=result.target_path,
        scan_errors=result.scan_errors,
    )
    for d in result.dependency_findings:
        filtered_cves = [c for c in d.cves if rank_map.get(c.severity.value, 0) >= min_rank]
        if filtered_cves:
            from aicerberus.models import DependencyFinding
            new_d = DependencyFinding(
                package=d.package,
                version=d.version,
                ecosystem=d.ecosystem,
                source_file=d.source_file,
                cves=filtered_cves,
            )
            filtered.dependency_findings.append(new_d)

    filtered.model_findings = [
        m for m in result.model_findings
        if rank_map.get(m.severity.value, 0) >= min_rank
    ]
    filtered.license_findings = [
        lf for lf in result.license_findings
        if rank_map.get(lf.severity.value, 0) >= min_rank
    ]
    return filtered


# ── Rich output renderers ──────────────────────────────────────────────────────

def _render_table(result: ScanResult, show_fix: bool) -> None:
    """Render scan results as rich tables."""
    # ── Dependency CVE table ──────────────────────────────────────────────────
    if result.dependency_findings:
        table = Table(
            title="[bold]AI/ML Dependency Vulnerabilities[/bold]",
            box=box.ROUNDED,
            show_lines=False,
        )
        table.add_column("Package", style="bold cyan", no_wrap=True)
        table.add_column("Version", style="dim")
        table.add_column("CVE", style="bold")
        table.add_column("Severity")
        table.add_column("CVSS")
        table.add_column("Summary")
        if show_fix:
            table.add_column("Fix")

        for finding in sorted(
            result.dependency_findings, key=lambda x: x.max_severity.rank, reverse=True
        ):
            for cve in sorted(finding.cves, key=lambda c: c.severity.rank, reverse=True):
                style = _sev_style(cve.severity)
                icon = _sev_icon(cve.severity)
                row = [
                    finding.package,
                    finding.version or "unpinned",
                    cve.cve_id,
                    f"[{style}]{icon} {cve.severity.value}[/{style}]",
                    str(cve.cvss_score) if cve.cvss_score else "N/A",
                    (cve.summary or "")[:80],
                ]
                if show_fix:
                    row.append(
                        f"Upgrade to {cve.fixed_version}" if cve.fixed_version else "No fix available"
                    )
                table.add_row(*row)
        console.print(table)
    else:
        console.print("[green]✓ No vulnerable AI/ML dependencies found[/green]")

    # ── Model file table ──────────────────────────────────────────────────────
    if result.model_findings:
        console.print()
        mtable = Table(
            title="[bold]Model File Risks[/bold]",
            box=box.ROUNDED,
            show_lines=False,
        )
        mtable.add_column("File", style="bold cyan")
        mtable.add_column("Format")
        mtable.add_column("Severity")
        mtable.add_column("Risk")
        mtable.add_column("SHA-256 (short)")
        if show_fix:
            mtable.add_column("Recommendation")

        for finding in sorted(result.model_findings, key=lambda x: x.severity.rank, reverse=True):
            style = _sev_style(finding.severity)
            icon = _sev_icon(finding.severity)
            opcodes_note = (
                f"\n[red]⚠ Dangerous opcodes: {', '.join(finding.opcodes_found[:3])}[/red]"
                if finding.opcodes_found else ""
            )
            row = [
                str(finding.path.name) + opcodes_note,
                finding.format,
                f"[{style}]{icon} {finding.severity.value}[/{style}]",
                finding.risk_type.value,
                finding.sha256[:16] + "…",
            ]
            if show_fix:
                row.append(finding.recommendation[:100])
            mtable.add_row(*row)
        console.print(mtable)
    else:
        console.print("[green]✓ No model file risks found[/green]")

    # ── License table ─────────────────────────────────────────────────────────
    if result.license_findings:
        console.print()
        ltable = Table(
            title="[bold]License Compliance Issues[/bold]",
            box=box.ROUNDED,
            show_lines=False,
        )
        ltable.add_column("Package/Model", style="bold cyan")
        ltable.add_column("License")
        ltable.add_column("Severity")
        ltable.add_column("Restriction")
        if show_fix:
            ltable.add_column("Details")

        for finding in sorted(result.license_findings, key=lambda x: x.severity.rank, reverse=True):
            style = _sev_style(finding.severity)
            icon = _sev_icon(finding.severity)
            row = [
                finding.package_or_model,
                finding.license_id,
                f"[{style}]{icon} {finding.severity.value}[/{style}]",
                finding.restriction_type,
            ]
            if show_fix:
                row.append(finding.description[:120])
            ltable.add_row(*row)
        console.print(ltable)
    else:
        console.print("[green]✓ No license compliance issues found[/green]")


def _render_summary(result: ScanResult) -> None:
    """Render a summary panel."""
    total_cves = result.total_vulnerabilities
    total_models = len(result.model_findings)
    total_licenses = len(result.license_findings)
    total = total_cves + total_models + total_licenses

    if total == 0:
        panel_text = "[bold green]✓ No risks detected — project looks clean![/bold green]"
        border_style = "green"
    else:
        sev = result.max_severity
        icon = _sev_icon(sev)
        panel_text = (
            f"{icon} [bold]Overall severity: [{_sev_style(sev)}]{sev.value}[/{_sev_style(sev)}][/bold]\n\n"
            f"  CVEs found:           [bold]{total_cves}[/bold]\n"
            f"  Model file risks:     [bold]{total_models}[/bold]\n"
            f"  License issues:       [bold]{total_licenses}[/bold]"
        )
        border_style = _sev_style(sev).replace("bold ", "")

    console.print(
        Panel(
            panel_text,
            title=f"[bold]AICerberus v{__version__} — Scan Summary[/bold]",
            subtitle=f"Target: {result.target_path}",
            border_style=border_style,
            padding=(1, 2),
        )
    )

    if result.scan_errors:
        console.print()
        for err in result.scan_errors:
            err_console.print(f"[yellow]⚠ Warning: {err}[/yellow]")


# ── CLI definition ─────────────────────────────────────────────────────────────

@click.group()
@click.version_option(__version__, prog_name="cerberus")
def main() -> None:
    """AICerberus — AI supply chain security scanner."""


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--format", "output_format",
    type=click.Choice(["table", "json", "sbom"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    default=None,
    help="Minimum severity level to report.",
)
@click.option("--fix", is_flag=True, default=False, help="Show remediation recommendations.")
@click.option("--skip-deps", is_flag=True, default=False, help="Skip dependency CVE scan.")
@click.option("--skip-models", is_flag=True, default=False, help="Skip model file scan.")
@click.option("--skip-licenses", is_flag=True, default=False, help="Skip license compliance scan.")
@click.option(
    "--hf-token",
    envvar="HF_TOKEN",
    default=None,
    help="HuggingFace API token for private model card lookups.",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Write output to file instead of stdout.",
)
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress progress messages.")
def scan(
    path: Path,
    output_format: str,
    severity: str | None,
    fix: bool,
    skip_deps: bool,
    skip_models: bool,
    skip_licenses: bool,
    hf_token: str | None,
    output: Path | None,
    quiet: bool,
) -> None:
    """Scan PATH for AI/ML supply chain risks.

    PATH defaults to the current directory.

    Exit codes:
      0  — no risks found
      1  — one or more risks found
      2  — scan error
    """
    target = path.resolve()

    # Progress display (suppressed in quiet mode or non-table output)
    progress_msgs: list[str] = []

    def _progress(msg: str) -> None:
        if not quiet and output_format == "table":
            console.print(f"  [dim]{msg}[/dim]")
        progress_msgs.append(msg)

    engine = ScanEngine(hf_api_token=hf_token, progress_callback=_progress)

    if not quiet and output_format == "table":
        console.print(
            Panel(
                f"[bold cyan]AICerberus v{__version__}[/bold cyan]  AI Supply Chain Security Scanner\n"
                f"Target: [bold]{target}[/bold]",
                border_style="cyan",
                padding=(0, 2),
            )
        )
        console.print()

    try:
        result = engine.scan(
            target,
            skip_deps=skip_deps,
            skip_models=skip_models,
            skip_licenses=skip_licenses,
        )
    except Exception as exc:
        err_console.print(f"[bold red]Scan failed: {exc}[/bold red]")
        sys.exit(2)

    # Apply severity filter
    if severity:
        result = _filter_by_severity(result, severity.upper())

    # ── Output ────────────────────────────────────────────────────────────────
    if output_format == "json":
        out_data = _result_to_dict(result)
        text = json.dumps(out_data, indent=2, default=str)
        if output:
            output.write_text(text, encoding="utf-8")
            if not quiet:
                console.print(f"[green]JSON report written to {output}[/green]")
        else:
            click.echo(text)

    elif output_format == "sbom":
        sbom_gen = SBOMGenerator()
        sbom = sbom_gen.generate(result)
        text = json.dumps(sbom, indent=2, default=str)
        if output:
            output.write_text(text, encoding="utf-8")
            if not quiet:
                console.print(f"[green]CycloneDX SBOM written to {output}[/green]")
        else:
            click.echo(text)

    else:  # table
        if not quiet:
            console.print()
        _render_table(result, show_fix=fix)
        if not quiet:
            console.print()
            _render_summary(result)

    sys.exit(result.exit_code)


# ── Helper: convert ScanResult to plain dict ──────────────────────────────────

def _result_to_dict(result: ScanResult) -> dict:
    return {
        "target": str(result.target_path),
        "summary": {
            "total_cves": result.total_vulnerabilities,
            "model_file_risks": len(result.model_findings),
            "license_issues": len(result.license_findings),
            "max_severity": result.max_severity.value,
            "exit_code": result.exit_code,
        },
        "dependency_findings": [
            {
                "package": d.package,
                "version": d.version,
                "source_file": d.source_file,
                "cves": [
                    {
                        "id": c.cve_id,
                        "severity": c.severity.value,
                        "cvss_score": c.cvss_score,
                        "summary": c.summary,
                        "fixed_version": c.fixed_version,
                        "references": c.references,
                    }
                    for c in d.cves
                ],
            }
            for d in result.dependency_findings
        ],
        "model_findings": [
            {
                "path": str(m.path),
                "format": m.format,
                "size_bytes": m.size_bytes,
                "sha256": m.sha256,
                "severity": m.severity.value,
                "risk_type": m.risk_type.value,
                "description": m.description,
                "recommendation": m.recommendation,
                "opcodes_found": m.opcodes_found,
            }
            for m in result.model_findings
        ],
        "license_findings": [
            {
                "package_or_model": lf.package_or_model,
                "license_id": lf.license_id,
                "restriction_type": lf.restriction_type,
                "severity": lf.severity.value,
                "description": lf.description,
                "source": lf.source,
            }
            for lf in result.license_findings
        ],
        "scan_errors": result.scan_errors,
    }


if __name__ == "__main__":
    main()
