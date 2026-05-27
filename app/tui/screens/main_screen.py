import os
from textual.screen import Screen
from textual.widgets import Input
from textual.containers import Container
from textual.binding import Binding
from ..widgets.subdomain_table import SubdomainTable
from ..widgets.detail_panel import DetailPanel
from ..widgets.stats_bar import StatsBar
from ..filter_parser import FilterParser
import threading
from utils import do_screenshot, get_logger

log = get_logger('main_screen')

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
        Binding("s", "screenshot", "Screenshot"),
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
        initial_query = self.config.query if self.config.query else ""
        yield Input(
            value=initial_query,
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
            subdomain = results.get("subdomain", "")
            if subdomain:
                import tldextract
                from utils import load_result_from_cache

                root = tldextract.extract(subdomain)
                domain_root = f"{root.domain}{root.suffix}"

                cached_data = load_result_from_cache(domain_root)
                if subdomain in cached_data:
                    cached_result = cached_data[subdomain]
                    results.update({
                        k: v for k, v in cached_result.items()
                        if k in ["deep_scan", "honeypot_score", "honeypot_label", "honeypot_findings"]
                    })

            self.results.append(results)
            self.apply_filter()
            self.update_stats()
        self.app.call_from_thread(update_ui)

    def on_input_submitted(self, event: Input.Submitted):
        if event.input.id == "filter-input":
            self.apply_filter()

            table = self.query_one("#subdomain-table", SubdomainTable)
            table.focus()

    def apply_filter(self):
        filter_input = self.query_one("#filter-input", Input)
        query = filter_input.value
        table = self.query_one("#subdomain-table", SubdomainTable)

        if not query.strip():
            self.filtered_results = list(self.results)
        else:
            self.filtered_results = self.parser.parse(query, self.results)
        table.update_data(self.filtered_results)
        self.update_stats()

    def update_stats(self):
        misconfigured_codes = (526, 527, 530)

        status_bar = self.query_one("#stats-bar", StatsBar)
        status_bar.update_stats(
            total=len(self.results),
            filtered=len(self.filtered_results),
            live=sum(1 for r in self.results if r.get("is_live")),
            misconfigured=sum(1 for r in self.results if
                           r.get('http', {}).get('status') in misconfigured_codes or
                           r.get('https', {}).get('status') in misconfigured_codes),
            honeypots=sum(1 for r in self.results if r.get("is_honeypot")),
            wildcard=sum(1 for r in self.results if r.get('wildcard'))
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
        table = self.query_one("#subdomain-table", SubdomainTable)
        selected = table.get_selected_row()
        if selected:
            from .fullscreen import FullscreenDetail
            self.app.push_screen(FullscreenDetail(selected))
        else:
            self.notify("Select a subdomain first", severity="warning")

    def action_export_selected(self):
        table = self.query_one("#subdomain-table", SubdomainTable)
        selected = table.get_selected_row()
        if selected:
            self.notify(f"Exported: {selected['subdomain']}")

    def action_export_all(self):
        self.notify(f"Exported: {len(self.filtered_results)} results")

    def action_screenshot(self):
        table = self.query_one("#subdomain-table", SubdomainTable)
        selected = table.get_selected_row()

        if not selected:
            self.notify(
                "Select a subdomain first",
                severity="warning"
            )
            return

        do_screenshot(
            app=self.app,
            result=selected,
            notify=self.notify
        )

    def action_copy_subdomain(self):
        table = self.query_one("#subdomain-table", SubdomainTable)
        selected = table.get_selected_row()
        if selected:
            try:
                import pyperclip
                pyperclip.copy(selected['subdomain'])
                self.notify(f"Copied: {selected['subdomain']}")
            except:
                log.error(f"Clipboard not available")
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
        import sys
        from core import app_state

        app_state.stop()
        if hasattr(app_state, 'executor') and app_state.executor:
            app_state.executor.shutdown(wait=False, cancel_futures=True)

        current_filter = self.query_one("#filter-input", Input).value
        args = sys.argv[:]

        boolean_flags_to_purge = {
            '-L', '--live',
            '-A', '--available',
            '-w', '--no-wildcard',
            '--honeypot'    
        }

        value_flags_to_purge = {
            '--ip',
            '--port'
        }

        for i in range(len(args) - 1, -1, -1):
            arg = args[i]

            if arg in boolean_flags_to_purge:
                args.pop(i)
            else:
                for v_flag in value_flags_to_purge:
                    if arg == v_flag:
                        args.pop(i)
                        if i < len(args):
                            args.pop(i)
                        break
                    elif arg.startswith(f"{v_flag}="):
                        args.pop(i)
                        break

        for flag in ('-q', '--query'):
            if flag in args:
                idx = args.index(flag)
                args.pop(idx)
                if idx < len(args):
                    args.pop(idx)

        if current_filter.strip():
            args.extend(['-q', current_filter.strip()])

        if '--refresh' not in args:
            args.append('--fresh')

        os.execv(sys.executable, [sys.executable] + args)

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

    def get_selected_data(self):
        table = self.query_one("#subdomain-table", SubdomainTable)
        return table.get_selected_row()

    def get_all_subdomain(self) -> list[str]:
        if self.filtered_results:
            return [str(item['subdomain']) for item in self.filtered_results if 'subdomain' in item]
        return []