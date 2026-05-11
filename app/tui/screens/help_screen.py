from textual.screen import ModalScreen
from textual.widgets import Static
from textual.binding import Binding
from rich.panel import Panel
from rich.table import Table

class HelpScreen(ModalScreen):
    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("f1", "dismis", "Close")
    ]

    def compose(self):
        help_table = Table.grid(padding=(0, 2))
        help_table.add_column(style="cyan", justify="right")
        help_table.add_column()

        help_table.add_row("[bold]Navigation", "")
        help_table.add_row("↑/↓", "Navigate list")
        help_table.add_row("Enter", "Show details")
        help_table.add_row("Tab", "Switch panel")
        help_table.add_row("Esc", "Close detail")

        help_table.add_row("", "")
        help_table.add_row("[bold]Filtering", "")
        help_table.add_row("/", "Focus filter")
        help_table.add_row("status:200", "Filter by status code")
        help_table.add_row("server:nginx", "Filter by server")
        help_table.add_row("honeypot:true", "Show honeypots only")
        help_table.add_row("NOT status:404", "Exclude 404s")

        help_table.add_row("", "")
        help_table.add_row("[bold]Actions", "")
        help_table.add_row("E", "Export selected")
        help_table.add_row("Shift+E", "Export all")
        help_table.add_row("C", "Copy to clipboard")
        help_table.add_row("O", "Open in browser")
        help_table.add_row("F", "Fullscreen detail")

        help_table.add_row("", "")
        help_table.add_row("[bold]Other", "")
        help_table.add_row("R", "Refresh scan")
        help_table.add_row("Q", "Quit")

        panel = Panel(help_table, title="Keyboard Shortcuts", border_style="green")
        yield Static(panel, id="help-content")

    def action_dismiss(self):
        self.app.pop_screen()