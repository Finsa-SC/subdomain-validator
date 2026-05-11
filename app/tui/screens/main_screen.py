from textual.app import ComposeResult
from textual.events import Event
from textual.screen import Screen
from textual.widgets import Static, Input
from textual.containers import Container, Horizontal, Vertical
from textual.binding import Binding
from ..widgets.subdomain_table import SubdomainTable
from ..widgets.detail_panel import DetailPanel
from ..widgets.stats_bar import StatsBar
from ..filter_parser import FilterParser
import threading

class MainScreen(Screen):
    BINDINGS = [
        Binding("slash", "focus_filter", "Filter", key_display="/"),
        Binding("d", "show_details", "Details"),
        Binding("f", "toggle_fullscreen", "Fullscreen"),
        Binding("e", "export_selected", "Export"),
        Binding("shift+e", "export_all", "Export All"),
        Binding("c", "copy_subdomain", "Copy"),
        Binding("b", "open_browser", "Open"),
        Binding("r", "refresh", "Refresh"),
        Binding("escape", "close_detail", "Close"),
        Binding("f1", "show_help", "Help"),
    ]

    def __init__(self, config, domain_or_file):
        super().__init__()
        self.config = config
        self.domain_or_file = domain_or_file
        self.parser = FilterParser()
        self.results = []
        self.filtered_results = []
        self.detail_visible = False
        self.detail_fullscreen = False
        self._rendered_count = 0

    def compose(self):
        yield Input(
            placeholder="Filter: status:200, server:nginx, NOT status:404",
            id="filter-input"
        )
        with Container(id="main-container"):
            yield SubdomainTable(id="subdomain-table")
            yield DetailPanel(id="detail-panel")
        yield StatsBar(id="stats-bar")

    def on_mount(self):
        self.start_scan()
        self.query_one("#subdomain-table", SubdomainTable).focus()

    def start_scan(self):
        from core import check_subdomain_tui

        def scan_worker():
            check_subdomain_tui(
                self.domain_or_file,
                callback=self.on_subdomain_found
            )

        thread = threading.Thread(target=scan_worker, daemon=True)
        thread.start()

    def on_subdomain_found(self, results):
        def update_ui():
            self.results.append(results)
            with open("/tmp/debug.log", "a") as f:
                f.write(f"[ui] update_ui called, subdomain={results.get('subdomain')}, total={len(self.results)}\n")
            self.apply_filter()
            self.update_stats()
        self.app.call_from_thread(update_ui)

    def on_input_submitted(self, event: Input.Submitted):
        if event.input.id == "filter-input":
            self.apply_filter()

    def apply_filter(self):
        filter_input = self.query_one("#filter-input", Input)
        query = filter_input.value
        table = self.query_one("#subdomain-table", SubdomainTable)

        if not query.strip():
            new_result = self.results[self._rendered_count:]
            for r in new_result:
                table.append_row(r)
            self._rendered_count = len(self.results)
            self.filtered_results = self.results.copy()
        else:
            self._rendered_count = 0
            self.filtered_results = self.parser.parse(query, self.results)
            table.update_data(self.filtered_results)

    def update_stats(self):
        status_bar = self.query_one("#status-bar", StatsBar)
        status_bar.update_stats(
            total=len(self.results),
            filtered=len(self.filtered_results),
            live=sum(1 for r in self.results if r.get("is_live")),
            honeypots=sum(1 for r in self.results if r.get("is_honeypot"))
        )

    def action_focus_filter(self):
        self.query_one("#filter-input", Input).focus()

    def action_show_details(self):
        table = self.query_one("#subdomain-table", SubdomainTable)
        selected = table.get_selected_row()

        if selected:
            detail = self.query_one("#detail-panel", DetailPanel)
            detail.show_detail(selected)
            detail.add_class("visible")
            self.detail_visible = True

    def action_close_detail(self):
        if self.detail_visible:
            detail = self.query_one("#detail-panel", DetailPanel)
            detail.remove_class("visible")
            self.detail_visible = False

    def action_toggle_fullscreen(self):
        if self.detail_visible:
            self.detail_fullscreen = not self.detail_fullscreen
            self.notify("Fullscreen mode coming soon!")

    def action_export_selected(self):
        table = self.query_one("#subdomain-table", SubdomainTable)
        selected = table.get_selected_row()
        if selected:
            self.notify(f"Exported: {selected['subdomain']}")

    def action_export_all(self):
        self.notify(f"Exported: {len(self.filtered_results)} results")

    def action_copy_subdomain(self):
        table = self.query_one("#subdomain-table", SubdomainTable)
        selected = table.get_selected_row()
        if selected:
            try:
                import pyperclip
                pyperclip.copy(selected['subdomain'])
                self.notify(f"Copied: {selected['subdomain']}")
            except:
                self.notify("Clipboard not available", severity="error")

    def action_open_browser(self):
        table = self.query_one("#subdomain-table", SubdomainTable)
        selected = table.get_selected_row()
        if selected and selected.get("is_live"):
            import webbrowser
            url = f"https://{selected['subdomain']}"
            webbrowser.open(url)
            self.notify(f"Opened: {url}")
        else:
            self.notify(f"Not a live host", severity="warning")

    def action_refresh(self):
        self.notify("Refresh not implemented yet", severity="warning")

    def action_show_help(self):
        from .help_screen import HelpScreen
        self.app.push_screen(HelpScreen())

    def on_key(self, event):
        if event.key == "escape":
            filter_input = self.query_one("#filter-input", Input)
            table = self.query_one("#subdomain-table", SubdomainTable)
            if filter_input.has_focus:
                table.focus()
                event.stop()
