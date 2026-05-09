from textual.layouts import grid
from textual.widgets import Static
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

class DetailPanel(Static):
    def show_detail(self, result):
        if not result:
            self.update("")
            return

        detail_table = Table.grid(padding=(0, 1))
        detail_table.add_column(style="cyan", justify="right")
        detail_table.add_column()

        detail_table.add_row("Subdomain: ", result.get("subdomain", ""))
        detail_table.add_row("IP: ", result.get("ip_address", "No IP"))

        http = result.get("http", {})
        https = result.get("https", {})

        detail_table.add_row("", "")
        detail_table.add_row("[bold]HTTP", "")
        detail_table.add_row("  Status:", str(http.get("status", "-")))
        detail_table.add_row("  Server:", http.get("server", "Unknown"))
        detail_table.add_row("  Latency:", f"{http.get('latency', 0)}ms")
        detail_table.add_row("  Title:", http.get("title", "-"))

        detail_table.add_row("", "")
        detail_table.add_row("[bold]HTTPS", "")
        detail_table.add_row("  Status:", str(https.get("status", "-")))
        detail_table.add_row("  Server:", https.get("server", "Unknown"))
        detail_table.add_row("  Latency:", f"{https.get('latency', 0)}ms")
        detail_table.add_row("  Title:", https.get("title", "-"))

        if result.get("is_honeypot"):
            detail_table.add_row("", "")
            score = result.get("honeypot_score", 0)
            label = result.get("honeypot_label", "")
            detail_table.add_row(
                "🍯 Honeypot:",
                f"[yellow]{score * 100:.1f}% ({label})[/]"
            )

        panel = Panel(detail_table, title="Details", border_style="cyan")
        self.update(panel)