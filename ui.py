"""Small terminal UI with optional Rich support."""
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    _console = Console()
except ImportError:
    Console = Panel = Table = None
    _console = None


def print_banner():
    title = "SCOPED INFRASTRUCTURE ASSESSMENT  |  MVP 0.1.0"
    if _console:
        _console.print(Panel(title, border_style="cyan"))
    else:
        print("=" * len(title))
        print(title)
        print("=" * len(title))


def print_error(message):
    if _console:
        _console.print(f"[bold red]HATA:[/bold red] {message}")
    else:
        print(f"HATA: {message}")


def print_result(result, result_path):
    open_ports = []
    for host in result.get("hosts", []):
        for port in host.get("ports", []):
            if port.get("state") == "open":
                open_ports.append((port.get("port"), port.get("protocol"), port.get("service") or "unknown",
                                   port.get("product") or "", port.get("version") or ""))
    if _console and Table:
        table = Table(title=f"{result['target']} — {result['status']}")
        for col in ("Port", "Proto", "Service", "Product", "Version"):
            table.add_column(col)
        for row in open_ports:
            table.add_row(*(str(v) for v in row))
        if not open_ports:
            table.add_row("-", "-", "No open ports parsed", "-", "-")
        _console.print(table)
        _console.print(f"JSON report: {result_path}")
    else:
        print(f"\nTarget: {result['target']} | Status: {result['status']}")
        for row in open_ports:
            print(" | ".join(str(v) for v in row))
        if not open_ports:
            print("Açık port parse edilmedi.")
        print(f"JSON rapor: {result_path}")
