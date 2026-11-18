"""
CERT-In Sentinel CLI Application.
"""

import os
import sys
import time
import uuid
from typing import Optional
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from certin_sentinel import __version__
from certin_sentinel.analyzers.auth import AuthLogAnalyzer
from certin_sentinel.analyzers.web import WebLogAnalyzer
from certin_sentinel.core.classifier import IncidentClassifier
from certin_sentinel.core.evidence import EvidenceHasher
from certin_sentinel.core.mitre import MitreMapper
from certin_sentinel.reporters.certin_report import CertInReportGenerator

console = Console()


def print_banner():
    banner = f"""[bold red]  ██████╗███████╗██████╗ ████████╗   ██╗███╗   ██╗[/bold red]
[bold red] ██╔════╝██╔════╝██╔══██╗╚══██╔══╝   ██║████╗  ██║[/bold red]
[bold red] ██║     █████╗  ██████╔╝   ██║█████╗██║██╔██╗ ██║[/bold red]
[bold red] ██║     ██╔══╝  ██╔══██╗   ██║╚════╝██║██║╚██╗██║[/bold red]
[bold red] ╚██████╗███████╗██║  ██║   ██║      ██║██║ ╚████║[/bold red]
[bold red]  ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝      ╚═╝╚═╝  ╚═══╝[/bold red]
[bold yellow]  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     [/bold yellow]
[bold yellow]  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     [/bold yellow]
[bold yellow]  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     [/bold yellow]
[bold yellow]  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     [/bold yellow]
[bold yellow]  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗[/bold yellow]
[bold yellow]  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝[/bold yellow]
[dim cyan]  Sovereign Cyber Incident Triage & CERT-In / DPDP Compliance (v{__version__})[/dim cyan]
[dim white]  GrooveXlabs — Building India's Digital Defense Infrastructure[/dim white]
"""
    console.print(banner)


@click.group()
@click.version_option(version=__version__)
def main():
    """CERT-In Sentinel: Sovereign Cyber Incident Triage & Compliance Reporting Engine."""
    pass


@main.command(name="analyze-auth")
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--threshold", "-t", default=5, help="Failed login threshold for brute force detection.")
@click.option("--output", "-o", "output_file", help="Save findings report to file.")
def analyze_auth_cmd(logfile: str, threshold: int, output_file: Optional[str]):
    """Analyze authentication logs (auth.log, SSH, Windows Security Events)."""
    print_banner()
    console.print(f"[cyan]Analyzing auth log:[/cyan] [bold]{logfile}[/bold]")

    with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    analyzer = AuthLogAnalyzer(brute_force_threshold=threshold)
    findings = analyzer.analyze(lines)

    if not findings:
        console.print(Panel(
            "[bold green]✔ No suspicious authentication activity detected.[/bold green]",
            title="Analysis Complete",
            border_style="green",
        ))
        return

    table = Table(title=f"[bold red]Auth Findings ({len(findings)})[/bold red]", border_style="dim white")
    table.add_column("Type", style="bold white")
    table.add_column("Severity", style="bold red")
    table.add_column("Source IP", style="cyan")
    table.add_column("User", style="yellow")
    table.add_column("Count", style="bold white")
    table.add_column("MITRE Techniques", style="magenta")

    for f_item in findings:
        tech_ids = ", ".join(t.technique_id for t in f_item.matched_techniques) or "—"
        table.add_row(
            f_item.finding_type,
            f_item.severity,
            f_item.source_ip or "—",
            f_item.username or "—",
            str(f_item.count),
            tech_ids,
        )

    console.print(table)

    if output_file:
        _auto_triage_and_report(findings, [], output_file)


@main.command(name="analyze-web")
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--output", "-o", "output_file", help="Save findings report to file.")
def analyze_web_cmd(logfile: str, output_file: Optional[str]):
    """Analyze web server logs (Apache, Nginx access logs)."""
    print_banner()
    console.print(f"[cyan]Analyzing web log:[/cyan] [bold]{logfile}[/bold]")

    with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    analyzer = WebLogAnalyzer()
    findings = analyzer.analyze(lines)

    if not findings:
        console.print(Panel(
            "[bold green]✔ No suspicious web activity detected.[/bold green]",
            title="Analysis Complete",
            border_style="green",
        ))
        return

    table = Table(title=f"[bold red]Web Findings ({len(findings)})[/bold red]", border_style="dim white")
    table.add_column("Type", style="bold white")
    table.add_column("Severity", style="bold red")
    table.add_column("Source IP", style="cyan")
    table.add_column("Count", style="bold white")
    table.add_column("MITRE Techniques", style="magenta")

    for f_item in findings:
        tech_ids = ", ".join(t.technique_id for t in f_item.matched_techniques) or "—"
        table.add_row(
            f_item.finding_type,
            f_item.severity,
            f_item.source_ip or "—",
            str(f_item.count),
            tech_ids,
        )

    console.print(table)

    if output_file:
        _auto_triage_and_report([], findings, output_file)


@main.command(name="triage")
@click.option("--title", "-t", required=True, help="Incident title.")
@click.option("--summary", "-s", required=True, help="Incident description.")
@click.option("--systems", required=True, help="Comma-separated affected systems.")
@click.option("--iocs", default="", help="Comma-separated indicators of compromise.")
@click.option("--org", default="GrooveXlabs", help="Organization name for report header.")
@click.option("--output", "-o", "output_file", default="certin_report.md", help="Output report file path.")
def triage_cmd(title: str, summary: str, systems: str, iocs: str, org: str, output_file: str):
    """Manually triage an incident and generate a CERT-In compliance report."""
    print_banner()

    systems_list = [s.strip() for s in systems.split(",") if s.strip()]
    iocs_list = [i.strip() for i in iocs.split(",") if i.strip()]

    classifier = IncidentClassifier()
    mapper = MitreMapper()

    # Try to map some techniques from keywords in the summary
    techniques = mapper.search_by_keyword(title.split()[0]) if title else []

    incident = classifier.classify(
        incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
        title=title,
        summary=summary,
        affected_systems=systems_list,
        iocs=iocs_list,
        techniques=techniques,
    )

    reporter = CertInReportGenerator()
    report = reporter.generate(incident, organization_name=org)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report)

    console.print(Panel(
        f"[bold green]✔ CERT-In Incident Report Generated[/bold green]\n\n"
        f"[bold]Incident ID:[/bold] {incident.incident_id}\n"
        f"[bold]Category:[/bold] {incident.category.value}\n"
        f"[bold]Severity:[/bold] [bold red]{incident.severity.value}[/bold red]\n"
        f"[bold]DPDP Status:[/bold] {incident.dpdp_classification.value}\n"
        f"[bold]Report File:[/bold] [underline]{output_file}[/underline]\n"
        f"[bold]Reporting Deadline:[/bold] ⏰ 6 hours from detection",
        title="Triage Complete",
        border_style="green",
    ))


@main.command(name="hash-evidence")
@click.argument("filepath", type=click.Path(exists=True))
@click.option("--note", "-n", default=None, help="Analyst note for chain-of-custody record.")
def hash_evidence_cmd(filepath: str, note: Optional[str]):
    """Generate SHA-256 forensic hash for an evidence file."""
    record = EvidenceHasher.hash_file(filepath, analyst_note=note)

    console.print(Panel(
        f"[bold green]✔ Evidence Hashed for Chain-of-Custody[/bold green]\n\n"
        f"[bold]File:[/bold] {record.filepath}\n"
        f"[bold]SHA-256:[/bold] [cyan]{record.sha256_hash}[/cyan]\n"
        f"[bold]Size:[/bold] {record.file_size_bytes:,} bytes\n"
        f"[bold]Timestamp:[/bold] {record.hash_timestamp}\n"
        f"[bold]Note:[/bold] {record.analyst_note or '—'}",
        title="Forensic Evidence Record",
        border_style="yellow",
    ))


@main.command(name="mitre-search")
@click.argument("keyword")
def mitre_search_cmd(keyword: str):
    """Search the MITRE ATT&CK knowledge base by keyword."""
    mapper = MitreMapper()
    results = mapper.search_by_keyword(keyword)

    if not results:
        console.print(f"[dim]No MITRE ATT&CK techniques found for keyword: '{keyword}'[/dim]")
        return

    table = Table(title=f"[bold cyan]MITRE ATT&CK Search: '{keyword}'[/bold cyan]", border_style="dim white")
    table.add_column("ID", style="bold white")
    table.add_column("Name", style="cyan")
    table.add_column("Tactic", style="yellow")
    table.add_column("Severity", style="bold red")

    for t in results:
        table.add_row(t.technique_id, t.name, t.tactic, t.severity)

    console.print(table)


def _auto_triage_and_report(auth_findings, web_findings, output_file: str):
    """Auto-triage findings from analyzers and generate report."""
    all_summaries = []
    all_techniques = []
    all_iocs = []
    max_severity = "MEDIUM"

    for f_item in auth_findings:
        all_summaries.append(f_item.summary)
        all_techniques.extend(f_item.matched_techniques)
        if f_item.source_ip:
            all_iocs.append(f_item.source_ip)
        if f_item.severity in ["HIGH", "CRITICAL"]:
            max_severity = f_item.severity

    for f_item in web_findings:
        all_summaries.append(f_item.summary)
        all_techniques.extend(f_item.matched_techniques)
        if f_item.source_ip:
            all_iocs.append(f_item.source_ip)
        if f_item.severity == "CRITICAL":
            max_severity = "CRITICAL"
        elif f_item.severity == "HIGH" and max_severity != "CRITICAL":
            max_severity = "HIGH"

    classifier = IncidentClassifier()
    combined_summary = "; ".join(all_summaries)
    incident = classifier.classify(
        incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
        title="Automated Security Analysis Findings",
        summary=combined_summary,
        affected_systems=["Analyzed from log files"],
        iocs=list(set(all_iocs)),
        techniques=all_techniques,
    )

    reporter = CertInReportGenerator()
    report = reporter.generate(incident)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report)

    console.print(f"\n[bold green]✔ Report saved to:[/bold green] [underline]{output_file}[/underline]")


if __name__ == "__main__":
    main()
