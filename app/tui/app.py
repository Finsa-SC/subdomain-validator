from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Input
from textual.containers import Container, Vertical
from textual.binding import Binding


class SubdomainScannerApp(App):
    """Subdomain Scanner TUI"""

    CSS = """
    Screen {
        layout: vertical;
    }

    #filter-bar {
        height: 3;
        border: solid green;
    }

    #main-table {
        height: 1fr;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("slash", "focus_filter", "Filter", key_display="/"),
        Binding("f1", "help", "Help"),
        Binding("e", "export", "Export"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(
            placeholder="Filter: status:200, server:nginx, honeypot:true",
            id="filter-bar"
        )
        yield DataTable(id="main-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"

        # Add columns
        table.add_column("St", width=4)
        table.add_column("Subdomain", width=40)
        table.add_column("IP", width=16)
        table.add_column("Server", width=12)
        table.add_column("Status", width=10)

        # Sample data
        table.add_row("✅", "www.example.com", "93.184.216.34", "nginx", "200/200")
        table.add_row("⚠️", "admin.example.com", "93.184.216.35", "nginx", "200/200")
        table.add_row("🚫", "old.example.com", "93.184.216.36", "Apache", "403/403")

    def action_focus_filter(self) -> None:
        self.query_one(Input).focus()

    def action_help(self) -> None:
        self.notify("Help: Press Q to quit, / to filter, E to export")

    def action_export(self) -> None:
        self.notify("Export feature coming soon!")


if __name__ == "__main__":
    app = SubdomainScannerApp()
    app.run()



