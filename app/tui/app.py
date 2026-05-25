import sys
from Tools.scripts.mailerdaemon import emparse_list

from textual.app import App
from textual.binding import Binding

from .screens.action_modal import ActionModal
from .screens.multi_action_model import MultiActionModal
from .screens.main_screen import MainScreen
from core import app_state

class SubdomainScannerTUI(App):
    CSS_PATH = "styles.css"

    BINDINGS = [
        Binding("q", "force_quit", "Quit", priority=True),
        Binding("a", "open_action_menu", priority=True),
        Binding("A", "open_multi_action", "Multi Action"),
        Binding("b", "open_browser", "Open Browser"),
        Binding("ctrl+c", "force_quit", "Quit", show=False),
    ]

    def __init__(self, config, domain_or_file):
        super().__init__()
        self.scan_config = config
        self.domain_or_file = domain_or_file

    def on_mount(self) -> None:
        self.push_screen(MainScreen(self.scan_config, self.domain_or_file))

    def action_force_quit(self):
        app_state.stop()
        if hasattr(app_state, 'executor') and app_state.executor is not None:
            app_state.executor.shutdown(wait=False, cancel_futures=True)
        self.exit()
        sys.exit(0)

    def action_open_action_menu(self):
        active_screen = self.screen
        selected = None

        if active_screen.__class__.__name__ == "FullScreenDetail" and hasattr(active_screen, "result"):
            selected = active_screen.result
        elif hasattr(active_screen, "get_selected_data"):
            selected = active_screen.get_selected_data()
        else:
            for screen in self.screen_stack:
                if screen.__class__.__name__ == "MainScreen" and hasattr(screen, "get_selected_data"):
                    selected = screen.get_selected_data()
                    break

        if selected:
            self.push_screen(ActionModal(selected))
        else:
            self.notify("Please select a subdomain first", severity='warning')

    def action_open_multi_action(self):
        active_screen = self.screen
        if hasattr(active_screen, "get_all_subdomain"):
            all_targets = active_screen.get_all_subdomain()
            if all_targets:
                self.app.push_screen(MultiActionModal(all_targets))
            else:
                self.notify("No subdomain available for mass action", severity='warning')
        else:
            self.notify("Multi-action not available on this screen", severity='error')

    def action_open_browser(self):
        active_screen = self.screen
        selected = None

        if active_screen.__class__.__name__ == "FullScreenDetail" and hasattr(active_screen, "result"):
            selected = active_screen.result
        elif hasattr(active_screen, "get_selected_data"):
            selected = active_screen.get_selected_data()
        else:
            for screen in self.screen_stack:
                if screen.__class__.__name__ == "MainScreen" and hasattr(screen, "get_selected_data"):
                    selected = screen.get_selected_data()
                    break

        if not selected:
            self.notify("Select a subdomain first", severity="warning")
            return

        import webbrowser
        proto = "https" if selected.get("https", {}).get("status") == 200 else "http"
        url = f"{proto}://{selected['subdomain']}"
        webbrowser.open(url)
        self.notify(f"Opened: {url}")

def run_tui(config, domain_or_file):
    app = SubdomainScannerTUI(config, domain_or_file)
    app.run()