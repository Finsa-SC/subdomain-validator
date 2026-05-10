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
        self.clear()
        self.result_mapping = list(results)

        for r in results:
            icon = self.get_status_icon(r)
            subdomain = self.truncate(r.get("subdomain", ""), 38)
            ip = r.get("ip_address", "No IP")
            server = self.truncate(r.get("server", "Unknown"), 10)

            h_status = r.get("http", {}).get("status", "-")
            s_status = r.get("https", {}).get("status", "-")
            status = f"{h_status}/{s_status}"

            self.add_row(icon, subdomain, ip, server, status)

    @staticmethod
    def get_status_icon(result):
        h_status = result.get("http", {}).get("status")
        s_status = result.get("https", {}).get("status")

        if result.get("is_honeypot"):
            return Text("⚠️", style="bold yellow")
        if h_status == 200 or s_status == 200:
            return Text("✅", style="green")
        elif h_status == 403 or s_status == 403:
            return Text("🚫", style="red")
        elif h_status in [301, 302, 307] or s_status in [301, 302, 307]:
            return Text("↻", style="yellow")
        else:
            return Text("❌", style="dim")

    @staticmethod
    def truncate(text, max_len):
        if max_len >= len(text):
            return text
        return text[:max_len-3] + "..."

    def get_selected_row(self):
        if self.cursor_row is not None and self.cursor_row < len(self.rows):
            return self.result_mapping[self.cursor_row]
        return None
