from textual.widgets import DataTable
from rich.text import Text
from models import BATCH_SIZE, DISPLAY_COLUMNS
from utils import format_size, format_redirect

_FORMATTERS = {
    "http.size":    format_size,
    "https.size":   format_size,
    "http.latency":  lambda v: f"{v}ms" if v else "-",
    "https.latency": lambda v: f"{v}ms" if v else "-",
    "http.redir":   lambda v: format_redirect(v) if v else "-",
    "https.redir":  lambda v: format_redirect(v) if v else "-",
}

def _get_nested(data: dict, key: str):
    parts = key.split(".")
    val = data

    for part in parts:
        if not isinstance(val, dict):
            return None
        val = val.get(part)
    return val

class SubdomainTable(DataTable):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.result_mapping = []
        self._is_scanning = False
        self._pending_rows = []
        self._columns = DISPLAY_COLUMNS

    def on_mount(self):
        self.cursor_type = "row"
        self.zebra_stripes = True
        for col in self._columns:
            self.add_column(col['header'], width=col.get('width', 12))

    def start_scan_mode(self):
        self._is_scanning = True
        self._pending_rows = []

    def stop_scan_mode(self):
        self._is_scanning = False
        self._flush_pending()

    def update_data(self, results):
        saved_subdomain = self._get_cursor_subdomain()

        with self.prevent(DataTable.RowHighlighted):
            self.clear()
            self.result_mapping = list(results)

            for result in results:
                self.add_row(*self._build_row(result))

        self._restore_cursor(saved_subdomain)

    def append_scan_result(self, result):
        self._pending_rows.append(result)
        if len(self._pending_rows) >= BATCH_SIZE:
            self._flush_pending()

    def flush_all_pending(self):
        self._flush_pending()

    def _flush_pending(self):
        if not self._pending_rows:
            return

        rows = self._pending_rows
        self._pending_rows = []

        with self.prevent(DataTable.RowHighlighted):
            for result in rows:
                self.result_mapping.append(result)
                self.add_row(*self._build_row(result))

    def _build_row(self, result) -> tuple:
        cells = []
        for col in self._columns:
            key = col['key']
            width = col.get('width', 12)

            if key == 'icon':
                cells.append(self.get_status_icon(result))
                continue

            if key == 'status' or key == 'http.status/https.status':
                h = normalize_status(result.get('http', {}).get('status'))
                s = normalize_status(result.get('https', {}).get('status'))
                cells.append(f"{h}/{s}")
                continue

            raw = _get_nested(result, key)

            formatter  = _FORMATTERS.get(key)
            if formatter and raw not in ("", None):
                try:
                    raw_original = _get_nested(result, key)
                    formatted = formatter(raw_original)
                    cells.append(self.truncate(formatted, width - 2))
                except:
                    cells.append(self.truncate(str(raw) if raw is not None else ""))
            else:
                cells.append(self.truncate(str(raw), width - 2) if raw is not None else "")

        return tuple(cells)

    def _get_cursor_subdomain(self) -> str | None:
        if self.cursor_row is not None and self.cursor_row < len(self.result_mapping):
            return self.result_mapping[self.cursor_row].get('subdomain')
        return None

    def _restore_cursor(self, subdomain: str | None):
        if subdomain is None:
            return

        for i, r in enumerate(self.result_mapping):
            if r.get('subdomain') == subdomain:
                self.move_cursor(row=i, animate=False)
                return

    def append_row(self, result):
        self.append_scan_result(result)

    @staticmethod
    def get_status_icon(result):
        if result.get("wildcard"):
            return Text("◈", style="#00E0FF")

        score = result.get("honeypot_score", 0)
        if score > 0.5:
            color = "#F7768E" if score >= 0.75 else "#FFD700"
            return Text("🍯", style=color)

        h_status = result.get("http", {}).get("status")
        s_status = result.get("https", {}).get("status")

        if h_status == 200 or s_status == 200:
            return Text("◈", style="#73DACA")
        elif h_status in [401, 402, 403] or s_status in [401, 402, 403]:
            return Text("◈", style="#F7768E")
        elif h_status in [301, 302, 307] or s_status in [301, 302, 307]:
            return Text("◈", style="#BB9AF7")
        else:
            return Text("◈", style="#565F89")

    @staticmethod
    def truncate(text, max_len):
        text = str(text) if text is not None else ""
        if max_len >= len(text):
            return text
        return text[:max_len-3] + "..."

    def get_selected_row(self):
        if self.cursor_row is not None and self.cursor_row < len(self.rows):
            return self.result_mapping[self.cursor_row]
        return None


def normalize_status(status):
    if isinstance(status, int):
        return status
    return "-"