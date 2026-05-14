from os import lstat

from textual.widgets import Static
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.console import Group
from rich.align import Align
from urllib.parse import urlparse
from .subdomain_table import _normalize_status

class DetailPanel(Static):
    def show_detail(self, result):
        if not result:
            self.update("")
            return

        detail_table = Table.grid(padding=(0, 1))
        detail_table.add_column(style="#565F89", justify="right")
        detail_table.add_column(style="#00E0FF")

        subdomain = result.get('subdomain', "")
        ip = result.get('ip_address', "No IP")

        ip_header = Text(f"({ip})", style="italic #00a3ff")

        content = Group(
            Align.center(ip_header),
            Text(""),
            detail_table
        )

        panel = Panel(
            content,
            title=f"[bold #00E0FF]{subdomain}[/]",
            border_style="#FFD700",
            padding=(0, 1)
        )

        def protocol_detail(protocol: str):
            proto = result.get(protocol, {})
            latency = proto.get("latency")
            redir = proto.get("redir")
            status = proto.get("status")
            size = proto.get("size")
            tech = proto.get("tech")
            server = proto.get("server", "Unknown")
            title = proto.get("title", '-')

            status = _normalize_status(status)
            redir = _format_redirect(redir, subdomain)

            detail_table.add_row("", "")
            detail_table.add_row("[bold]HTTP", "")
            detail_table.add_row("  Status:", str(status))
            detail_table.add_row("  Server:", server)
            detail_table.add_row("  Latency:", f"{latency}ms" if latency is not None else "N/A")
            detail_table.add_row("  Size:", f"{size}B" if size is not None else "0")
            detail_table.add_row("  Redirect to:", f"{redir}")
            detail_table.add_row("  Title:", title)
            detail_table.add_row(
                "  Tech:", ","
                           " ".join(t.split(':')[0].split(' ')[0] for t in tech[:5]))

        protocol_detail('http')
        protocol_detail('https')

        score = result.get("honeypot_score")
        if score is None:
            score = result.get("is_honeypot", 0)
            if isinstance(score, bool):
                score = 1.0 if score else 0.0
        label = result.get("honeypot_label", "")

        filled = int(score * 10)
        bar_char = ["░"] * 10

        for i in range(filled):
            if i < 2.5:
                bar_char[i] = "[#00E0FF]█[/]"
            elif i < 5:
                bar_char[i] = "[#00C8FF]█[/]"
            elif i < 7.5:
                bar_char[i] = "[#00A3FF]█[/]"
            else:
                bar_char[i] = "[#0077BB]█[/]"

        bar = "".join(bar_char)

        if score >= 0.75:
            text_color = "#F7768E"
        elif score >= 0.5:
            text_color = "#FFD700"
        else:
            text_color = "#565F89"

        detail_table.add_row("", "")
        detail_table.add_row("[bold #00A3FF]Analysis[/]", "")

        detail_table.add_row("Honeypot:", f"{bar} [{text_color}] {score * 100:.0f}%[/]")

        detail_table.add_row("Label:", f"[{text_color} bold]{label}[/]")
        if result.get("wildcard"):
            detail_table.add_row("Wildcard:", "[#00E0FF]Detected[/]")
        else:
            detail_table.add_row("Wildcard:", "")

        self.update(panel)

def _format_redirect(url: str, current_subdomain: str = "") -> str:
    if not url or url in ["-", None, "None", ""]:
        return "-"
    parsed = urlparse(url)

    if current_subdomain and parsed.netloc == current_subdomain.lower():
        return "[bold #9ECE6A]HTTPS Upgrade[/]"

    if parsed.netloc:
        return parsed.netloc
    if parsed.path:
        return parsed.path
    return "-"