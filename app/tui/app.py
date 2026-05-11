from textual.app import App, ComposeResult
from textual.binding import Binding
from .screens.main_screen import MainScreen

class SubdomainScannerTUI(App):
    CSS_PATH = "styles.css"

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("ctrl+c", "quit", "Quit", show=False)
    ]

    def __init__(self, config, domain_or_file):
        super().__init__()
        self.scan_config = config
        self.domain_or_file = domain_or_file

    def on_mount(self) -> None:
        self.push_screen(MainScreen(self.scan_config, self.domain_or_file))

def run_tui(config, domain_or_file):
    app = SubdomainScannerTUI(config, domain_or_file)
    app.run()
