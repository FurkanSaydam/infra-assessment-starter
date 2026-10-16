"""MFS Scanner Rich dashboard with plain-terminal fallback."""
import shutil
from datetime import timedelta
try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.layout import Layout
    RICH = True
    CONSOLE = Console()
except ImportError:
    RICH = False
    CONSOLE = None

CYAN = "bright_cyan"
def banner():
    if RICH:
        art = r""" ███╗   ███╗███████╗███████╗
 ████╗ ████║██╔════╝██╔════╝
 ██╔████╔██║█████╗  ███████╗
 ██║╚██╔╝██║██╔══╝  ╚════██║
 ██║ ╚═╝ ██║███████╗███████║
 ╚═╝     ╚═╝╚══════╝╚══════╝"""
        CONSOLE.print(Text(art, style="bold bright_cyan"))
        CONSOLE.print(Text("                         by MFS", style="bright_cyan"))
        CONSOLE.print()
    else:
        print("=" * 60 + "\\nMFS SCANNER — by MFS\\n" + "=" * 60)

def dashboard(targets, states, ports_label, start_time, result_dir):
    elapsed = int(__import__("time").monotonic() - start_time)
    completed = sum(1 for s in states.values() if s["status"] in ("DONE", "ERROR"))
    errors = sum(1 for s in states.values() if s["status"] == "ERROR")
    opened = sum(s.get("open_ports", 0) for s in states.values())
    if not RICH:
        print(f"Targets {completed}/{len(targets)} | Open ports {opened} | Errors {errors} | Elapsed {elapsed}s")
        for ip in targets:
            s = states[ip]
            print(f'{ip:18} {ports_label:14} {s["chunk"]:>5} {s["tool"]:>8} {s["status"]:>10}')
        return
    stats = Table.grid(expand=True)
    stats.add_column(); stats.add_column(); stats.add_column(); stats.add_column(); stats.add_column()
    stats.add_row(
        f"[bold]TARGETS[/bold]\\n[bright_cyan]{len(targets)}[/]",
        f"[bold]FINISHED[/bold]\\n[green]{completed}/{len(targets)}[/]",
        f"[bold]OPEN PORTS[/bold]\\n[yellow]{opened}[/]",
        f"[bold]ERRORS[/bold]\\n[red]{errors}[/]",
        f"[bold]ELAPSED[/bold]\\n{str(timedelta(seconds=elapsed))}")
    table = Table(expand=True, box=None, show_lines=True)
    table.add_column("IP", style="bright_cyan", min_width=16)
    table.add_column("PORT RANGE", style="yellow", min_width=12)
    table.add_column("CHUNK", justify="center", width=8)
    table.add_column("TOOL", style="cyan", width=10)
    table.add_column("PROGRESS", min_width=20)
    table.add_column("STATUS", width=12)
    for ip in targets:
        s = states[ip]
        pct = 100 if s["status"] == "DONE" else (0 if s["status"] in ("WAITING", "ERROR") else None)
        bar = "[green]━━━━━━━━━━ 100%[/]" if pct == 100 else ("[red]FAILED[/]" if s["status"] == "ERROR" else
              "[bright_cyan]Scanning…[/]" if s["status"] == "SCANNING" else "[dim]Waiting[/]")
        table.add_row(ip, ports_label, s["chunk"], s["tool"], bar, s["status"])
    body = Group(Panel(stats, title="MFS SCANNER • LIVE OVERVIEW", border_style="bright_cyan"),
                 Panel(table, title=f"TARGET QUEUE  •  Output: {result_dir}", border_style="grey50"))
    return body

class Dashboard:
    def __init__(self, targets, states, ports_label, start_time, result_dir):
        self.targets, self.states, self.ports_label = targets, states, ports_label
        self.start_time, self.result_dir = start_time, result_dir
        self.live = None
        self._stop = threading.Event()
        self._thread = None
    def __enter__(self):
        if RICH:
            self.live = Live(dashboard(self.targets, self.states, self.ports_label, self.start_time, self.result_dir),
                             console=CONSOLE, refresh_per_second=4, screen=False)
            self.live.start()
            self._thread = threading.Thread(target=self._refresh_loop, daemon=True)
            self._thread.start()
        return self
    def _refresh_loop(self):
        while not self._stop.wait(0.25):
            if self.live:
                self.live.update(dashboard(self.targets, self.states, self.ports_label, self.start_time, self.result_dir))
    def refresh(self):
        if self.live:
            self.live.update(dashboard(self.targets, self.states, self.ports_label, self.start_time, self.result_dir))
    def __exit__(self, *args):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        if self.live:
            self.live.stop()

def print_error(message):
    if RICH: CONSOLE.print(f"[bold red]HATA:[/bold red] {message}")
    else: print(f"HATA: {message}")

def print_result(result, result_path):
    open_ports = [(p.get("port"), p.get("protocol"), p.get("service") or "unknown",
                   p.get("product") or "", p.get("version") or "")
                  for h in result.get("hosts", []) for p in h.get("ports", []) if p.get("state") == "open"]
    if RICH:
        table = Table(title=f'{result.get("target")} — {result.get("status")}', expand=True)
        for col in ("Port", "Proto", "Service", "Product", "Version"): table.add_column(col)
        for row in open_ports: table.add_row(*(str(v) for v in row))
        if not open_ports: table.add_row("-", "-", "No open ports parsed", "-", "-")
        CONSOLE.print(table); CONSOLE.print(f"[green]JSON report:[/] {result_path}")
    else:
        print(f'\\nTarget: {result.get("target")} | Status: {result.get("status")}')
        for row in open_ports: print(" | ".join(str(v) for v in row))
        print(f"JSON report: {result_path}")
