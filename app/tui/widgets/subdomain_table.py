from textual.widgets import DataTable
from rich.text import Text

class SubdomainTable(DataTable):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.result_mapping = []
    def on_mount(self):
        self.cursor_type = "row"
        self.zebra_stripes = True

        self.add_column("St", width=4)
        self.add_column("Subdomain", width=40)
        self.add_column("IP", width=16)
        self.add_column("Server", width=12)
        self.add_column("Status", width=10)

    def update_data(self, results):
        current_row = self.cursor_row
        self.clear()
        self.result_mapping = list(results)

        for r in results:
            icon = self.get_status_icon(r)
            subdomain = self.truncate(r.get("subdomain", ""), 38)
            ip = r.get("ip_address", "No IP")
            server = self.truncate(r.get("server", "Unknown"), 10)

            h_status = normalize_status(r.get("http", {}).get("status"))
            s_status = normalize_status(r.get("https", {}).get("status"))
            status = f"{h_status}/{s_status}"

            self.add_row(icon, subdomain, ip, server, status)

        if current_row is not None and current_row < len(self.result_mapping):
            self.move_cursor(row=current_row)

    def append_row(self, r):
        self.result_mapping.append(r)
        icon = self.get_status_icon(r)
        subdomain = self.truncate(r.get("subdomain", ""), 38)
        ip = r.get("ip_address", "No IP")
        server = self.truncate(r.get("server", "Unknown"), 10)
        h_status = normalize_status(r.get("http", {}).get("status"))
        s_status = normalize_status(r.get("https", {}).get("status"))

        self.add_row(icon, subdomain, ip, server, f"{h_status}/{s_status}")

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