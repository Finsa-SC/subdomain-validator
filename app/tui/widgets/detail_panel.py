from textual.widgets import Static
from rich.panel import Panel
from rich.table import Table
from .subdomain_table import _normalize_status

class DetailPanel(Static):
    def show_detail(self, result):
        if not result:
            self.update("")
            return

        detail_table = Table.grid(padding=(0, 1))
        detail_table.add_column(style="#565F89", justify="right")
        detail_table.add_column(style="#00E0FF")

        detail_table.add_row("IP: ", result.get("ip_address", "No IP"))

        http = result.get("http", {})
        https = result.get("https", {})
        h_lat = http.get("latency")
        s_lat = https.get("latency")
        h_st = _normalize_status(http.get("status"))
        s_st = _normalize_status(https.get("status"))

        detail_table.add_row("", "")
        detail_table.add_row("[bold]HTTP", "")
        detail_table.add_row("  Status:", str(h_st))
        detail_table.add_row("  Server:", http.get("server", "Unknown"))
        detail_table.add_row("  Latency:", f"{h_lat}ms" if h_lat is not None else "N/A")
        detail_table.add_row("  Title:", http.get("title", "-"))

        detail_table.add_row("", "")
        detail_table.add_row("[bold]HTTPS", "")
        detail_table.add_row("  Status:", str(s_st))
        detail_table.add_row("  Server:", https.get("server", "Unknown"))
        detail_table.add_row("  Latency:", f"{s_lat}ms" if s_lat is not None else "N/A")
        detail_table.add_row("  Title:", https.get("title", "-"))


        if result.get("is_honeypot"):
            detail_table.add_row("", "")
            score = result.get("honeypot_score", 0)
            label = result.get("honeypot_label", "")
            detail_table.add_row(
                "🍯 Honeypot:",
                f"[yellow]{score * 100:.1f}% ({label})[/]"
            )

        panel = Panel(
            detail_table,
            title=f"[bold #00E0FF]{result.get('subdomain', '')}[/]",
            border_style="#FFD700")
        self.update(panel)