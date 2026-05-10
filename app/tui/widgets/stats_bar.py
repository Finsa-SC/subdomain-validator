from textual.widgets import Static
from rich.text import Text

class StatsBar(Static):
    def update_stats(self, total, filtered, live, honeypots):
        text = Text()
        text.append("📊 ", style="bold")
        text.append(f"Total: {total}", style="#00A3FF")
        text.append(" | ", style="dim")
        text.append(f"Shown: {filtered}", style="bold #00E0FF")
        text.append(" | ", style="dim")
        text.append(f"Live: {live}", style="#73DACA")
        text.append(" | ", style="dim")
        text.append(f"Honeypots: {honeypots}", style="#BB9AF7")

        self.update(text)
