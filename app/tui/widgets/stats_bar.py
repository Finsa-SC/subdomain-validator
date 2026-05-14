from textual.containers import Horizontal
from textual.widgets import Static, Button
from rich.text import Text
from utils import get_logger

log = get_logger("stats_bar")

class StatsBar(Static):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.percentage = False
        self.last_data = {"total": 0, "filtered": 0, "live": 0, "honeypots": 0, "wildcard": 0}

    def compose(self):
        with Horizontal():
            yield Button("%", id="btn-toggle-stats")
            yield Static("", id="stats-text")

    def update_stats(self, total, filtered, live, honeypots, wildcard):
        self.last_data = {
            "total": total, "filtered": filtered,
            "live": live, "honeypots": honeypots,
            "wildcard": wildcard
        }
        self.call_after_refresh(self.render_content)

    def render_content(self):
        text = Text()
        data = self.last_data

        def get_percentage(value):
            if not self.percentage or data['total'] == 0: return ""
            return f" ({(value/data['total']*100):.1f}%)"

        text.append("📊 ", style="bold")
        text.append(f"Total: {data['total']}{get_percentage(data['total'])}", style="#00A3FF")
        if data['filtered']:
            text.append(" | ", style="dim")
            text.append(f"Shown: {data['filtered']}{get_percentage(data['filtered'])}", style="bold #00E0FF")
        if data['live']:
            text.append(" | ", style="dim")
            text.append(f"Live: {data['live']}{get_percentage(data['live'])}", style="#73DACA")
        if data['honeypots']:
            text.append(" | ", style="dim")
            text.append(f"Honeypots: {data['honeypots']}{get_percentage(data['honeypots'])}", style="#ea5400")
        if data['wildcard']:
            text.append(" | ", style="dim")
            text.append(f"Wildcard: {data['wildcard']}{get_percentage(data['wildcard'])}", style="#b50ad8")

        try:
            self.query_one("#stats-text", Static).update(text)
        except Exception as e:
            log.error(f'stats_bar error occurred: {e}')

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == 'btn-toggle-stats':
            self.percentage = not self.percentage
            event.button.label = '123' if self.percentage else '%'
            self.render_content()