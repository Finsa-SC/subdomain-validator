import token

from textual import work
from textual.screen import ModalScreen
from textual.widgets import Input
from textual.screen import Screen
from textual.widgets import Static
from textual.containers import ScrollableContainer, Center, Vertical
from textual.binding import Binding
from textual.app import ComposeResult
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from utils import do_screenshot, parse_port, scan_port, get_logger

log = get_logger("fullscreen")

class FullscreenDetail(Screen):
    BINDINGS = [
        Binding("f", "dismiss_screen", "Close Fullscreen"),
        Binding("escape", "dismiss_screen", "Close"),
        Binding("q", "dismiss_screen", "Close"),
        Binding("s", "screenshot", "Screenshot"),
        Binding("p", "scan_port", "Scan Ports"),
        Binding("x", "deep_scan", "Deep Scan")
    ]

    def __init__(self, result: dict):
        super().__init__()
        self.result = result

    def compose(self) -> ComposeResult:
        yield ScrollableContainer(
            Static(id="fullscreen-content"),
            id="fullscreen-scroll"
        )

    def on_mount(self):
        self.query_one("#fullscreen-content", Static).update(
            self._build_content()
        )
        self.refresh()

    def _build_content(self):
        r = self.result
        http = r.get("http", {})
        https = r.get("https", {})
        subdomain = r.get("subdomain", "")
        ip = r.get("ip_address", "No IP")

        sections = []

        # Header identity
        sections.append(self._header_identity(r))

        # General
        sections.append(Rule(title="[bold #00A3FF]General[/]", style="#1A1B26"))
        gen = _make_table()
        gen.add_row("Subdomain", subdomain)
        gen.add_row("IP Address", ip)
        gen.add_row("Wildcard", "[#00E0FF]Detected[/]" if r.get('wildcard') else "[#565F89]No[/]")
        gen.add_row("Timestamp", r.get("timestamp", "-") or "-")
        gen.add_row("Sign", r.get("signing", "[ ]"))
        sections.append(gen)

        # Protocol
        protocol_section = self._protocol_comparison(http, https)
        sections.append(protocol_section)

        # Ports
        if 'ports' in r:
            sections.append(Rule(title="[bold #00A3FF]Ports[/]", style="#1A1B26"))
            port_table = _make_table()
            ports = r.get("ports") or {}

            open_ports = {port: status for port, status in ports.items() if status == 'open'}
            if open_ports:
                for port, status in sorted(open_ports.items()):
                    status_text = f"[#73DACA]{status}[/]"
                    port_table.add_row(f"{port}/tcp", status_text)
                sections.append(port_table)
            else:
                sections.append(Text("  No open ports detected", style="#565F89"))

        # Deep Scan Results
        deep_data = r.get("deep_scan")
        if deep_data:
                sections.append(Rule(title="[bold #00A3FF]Deep Scan[/]", style="#1A1B26"))
                deep_table = _make_table()

                for key, info in deep_data.items():
                    status = info["status"].value  # "pending", "running", etc.
                    label = info["label"]

                    # Styling depends on status
                    if status == "running":
                        status_str = f"[#BB9AF7]↻ {status}...[/]"
                    elif status == "done":
                        status_str = f"[#73DACA]✓ {status}[/]"
                    elif status == "error":
                        status_str = f"[#F7768E]✗ {status}[/]"
                    else:
                        status_str = f"[#565F89]{status}[/]"

                    deep_table.add_row(label, status_str)

                    if status == "done" and info["data"]:
                        d = info["data"]
                        if key == "favicon" and d.get("hash"):
                            deep_table.add_row("", f"  [#00A3FF]Hash:[/] {d['hash']}")
                        elif key == "tech_version" and d.get("summary"):
                            for t, v in d["summary"].items():
                                deep_table.add_row("", f"  [#00A3FF]{t}:[/] {v}")

                sections.append(deep_table)

        # Cookies
        sections.append(_section_rule("Cookies"))
        cookies = _parse_cookies(http, https)
        if cookies:
            cookies_table = _make_table()
            for name, val in cookies.items():
                cookies_table.add_row(name, val[:60])
            sections.append(cookies_table)
        else:
            sections.append(Text("  No cookies detected", style="#565F89"))

        # Tech detection
        sections.append(Rule(title="[bold #00A3FF]Technology[/]", style="#1A1B26"))
        tech = list(set((http.get("tech") or []) + (https.get("tech") or [])))
        tech_table = _make_table()
        if tech:
            for item in tech:
                tech_table.add_row("Detected", item)
            sections.append(tech_table)
        else:
            sections.append(Text("  No tech detected", style="#565F89"))

        # Honeypot
        sections.append(Rule(title="[bold #00A3FF]Security Analysis[/]", style="#1A1B26"))
        sections.append(self._honeypot_analysis(r))

        # Headers http
        sections.append(Rule(title="[bold #00A3FF]HTTP Headers[/]", style="#1A1B26"))
        h_header = http.get("raw_header") or {}
        if h_header:
            ht2 = _make_table()
            for k, v in h_header.items():
                ht2.add_row(str(k), str(v)[:80])
            sections.append(ht2)
        else:
            sections.append(Text("  No headers captured", style="#565F89"))

        # Headers https
        sections.append(Rule(title="[bold #00A3FF]HTTPS Headers[/]", style="#1A1B26"))
        s_header = https.get("raw_header") or {}
        if s_header:
            st2 = _make_table()
            for key, val in s_header.items():
                st2.add_row(str(key), str(val)[:80])
            sections.append(st2)
        else:
            sections.append(Text("  No headers captured", style="#565F89"))

        from rich.console import Group as RichGroup
        return Panel(
            RichGroup(*sections),
            title=f"[bold #FFD700]FinSky Detail View[/]",
            border_style="#FFD700",
            padding=(1, 2)
        )

    @staticmethod
    def _header_identity(result: dict) -> Panel:
        subdomain = result.get("subdomain", "")
        ip = result.get("ip_address", "No IP")
        is_live = result.get("is_live", False)
        wildcard = result.get("wildcard", False)
        score = result.get("honeypot_score", 0)
        label = result.get("honeypot_label", "Unlikely")

        status_color = "#73DACA" if is_live else "#565F89"
        status_text = "● Live" if is_live else "● Offline"

        identity = Table.grid(expand=True)
        identity.add_column(justify="left", ratio=1)
        identity.add_column(justify="right", vertical='top')
        sub_display = f"[bold #00E0FF underline]{subdomain}[/]"
        status_display = f"[{status_color}]{status_text}[/]"

        identity.add_row(sub_display, status_display)

        badges = []
        if wildcard:
            badges += "  [#00E0FF]◈ Wildcard[/]"
        if score > 0:
            badges += f"  [#BB9AF7]🍯 {score * 100:.0f}% {label}[/]"

        extra_info = " ".join(badges)
        identity.add_row(f"[italic #00A3FF]{ip}[/]", extra_info)

        return Panel(
            identity,
            border_style="#00A3FF",
            padding=(1, 2),
            title="[#565F89]Target Identity[/]",
            title_align="left"
        )
    @staticmethod
    def _protocol_comparison(http: dict, https: dict) -> Table:
        def _create_proto_table(target_data):
            table = Table.grid(padding=(0, 1), expand=True)
            table.add_column(style="#565F89", justify="left", width=10)
            table.add_column(style="#00E0FF", justify="right")

            status = _format_status_colored(target_data.get("status"))
            table.add_row("Status", status)
            table.add_row("Server", (target_data.get("server") or "-")[:18])
            table.add_row("Latency", f"{target_data.get('latency')}ms" if target_data.get("latency") else "N/A")
            table.add_row("Size", f"{target_data.get('size', 0):,} B")
            table.add_row("Title", (target_data.get("title") or "-")[:18])
            table.add_row("Tech", ", ".join(target_data.get("tech", [])[:2]) or "-")
            return table

        # HTTP Panel
        http_panel = Panel(
            _create_proto_table(http),
            title="[bold #FFD700]HTTP[/]",
            border_style="#00A3FF",
            expand=True
        )

        # HTTPS Panel
        https_panel = Panel(
            _create_proto_table(https),
            title="[bold #FFD700]HTTPS[/]",
            border_style="#00A3FF",
            expand=True
        )

        layout_grid = Table.grid(padding=(0, 2), expand=True)
        layout_grid.add_column(ratio=1)
        layout_grid.add_column(ratio=1)
        layout_grid.add_row(http_panel, https_panel)

        return layout_grid

    @staticmethod
    def _honeypot_analysis(result: dict):
        score = result.get("honeypot_score", 0)
        label = result.get("honeypot_label", "Unlikely")

        filled = int(score * 10)
        bar = ""
        for i in range(10):
            if i < filled:
                if i < 3:
                    bar += "[#00E0FF]█[/]"
                elif i < 6:
                    bar += "[#00C8FF]█[/]"
                else:
                    bar += "[#00A3FF]█[/]"
            else:
                bar += "[#1A1B26]░[/]"

        text_color = "#F7768E" if score >= 0.75 else "#FFD700" if score >= 0.5 else "#565F89"

        honey_table = _make_table()
        honey_table.add_row("Score", f"{bar} [{text_color}]{score * 100:.0f}%[/]")
        honey_table.add_row("Label", f"[{text_color} bold]{label}[/]")

        findings = result.get("honeypot_findings", [])
        if findings:
            honey_table.add_row("", "")
            for f in findings:
                honey_table.add_row("[#565F89]Finding[/]", f[:70])

        return honey_table

    def action_screenshot(self):
        def refresh():
            self.query_one(
                "#fullscreen-content",
                Static
            ).update(self._build_content())

        do_screenshot(
            app=self.app,
            result=self.result,
            notify=self.notify,
            callback=refresh
        )

    @work(thread=True)
    def _run_port_scan_worker(self, value):
        ports = parse_port(value)
        self.notify(f"Scanning {len(ports)} ports...")
        result = scan_port(
            self.result["subdomain"],
            ports
        )
        self.result["ports"] = result
        self.app.call_from_thread(self._refresh_detail)

    def action_scan_port(self):
        def handle_input(value):
            if not value:
                return
            self._run_port_scan_worker(value)
        self.app.push_screen(PortInputModal(), callback=handle_input)

    @work(thread=True)
    def action_deep_scan(self):
        from analysis import run_deep_scan
        def on_module_done(key, states):
            if key == 'tech_version':
                self._merge_deep_tech_to_protocols()
            self.app.call_from_thread(self._refresh_detail)
        self.notify("Starting Deep Scan...", title="Deep Scanning")

        run_deep_scan(self.result, on_module_done)

    def _merge_deep_tech_to_protocols(self):
        deep_data = self.result.get("deep_scan", {})
        tech_module = deep_data.get('tech_version', {})

        status_obj = tech_module.get("status")
        if status_obj and status_obj.value == 'done':
            data_content = tech_module.get('data')
            if data_content and 'summary' in data_content:
                new_tech_list = []
                for tech_name, version in data_content['summary'].items():
                    if version and version != 0:
                        new_tech_list.append(f"{tech_name}: {version}")
                    else:
                        new_tech_list.append(tech_name)

                for proto in ('http', 'https'):
                    if proto not in self.result:
                        continue
                    current_tech = self.result[proto].get('tech') or []
                    combined = list(set(current_tech + new_tech_list))
                    final_list = []
                    for item in combined:
                        is_redundant = False
                        clean_item = item.lower().replace(" ", "")
                        merk_item = clean_item.split(':')[0].split('/')[0].strip()

                        for other in combined:
                            if item == other: continue

                            clean_other = other.lower().replace(" ", "")
                            merk_other = clean_other.split(':')[0].split('/')[0].strip()

                            if merk_item == merk_other:
                                if (':' not in item and '/' not in item) and (':' in other or '/' in other):
                                    is_redundant = True
                                    break

                                if len(other) > len(item):
                                    is_redundant = True
                                    break
                        if not is_redundant:
                            final_list.append(item)
                    self.result[proto]['tech'] = sorted(final_list)

    def _refresh_detail(self):
        try:
            widget = self.query_one("#fullscreen-content", Static)
            widget.update(self._build_content())
        except Exception as e:
            log.error(f"fullscreen error: {e}")
            pass

    def action_dismiss_screen(self):
            self.app.pop_screen()

#Helper
def _make_table():
    table = Table.grid(padding=(0, 2))
    table.add_column(style="#565F89", justify="right", min_width=14)
    table.add_column(style="#00E0FF", min_width=40)
    return table

def _section_rule(title: str):
    return Rule(title=f"[bold #00A3FF]{title}[/]", style="#1A1B26")

def _format_status_colored(status: int):
    if status == 200:
        return f"[#73DACA]{status} OK[/]"
    elif status in [401, 402, 403]:
        return f"[#F7768E]{status} Forbidden[/]"
    elif status in [301, 302, 307, 308]:
        return f"[#BB9AF7]{status} Redirect[/]"
    elif status == "-":
        return f"[#565F89]-[/]"
    else:
        return f"[#FFD700]{status}[/]"

def _parse_cookies(http: dict, https: dict) -> dict:
    cookies = {}

    for proto in (http, https):
        header = proto.get("raw_header") or {}
        for k, v in header.items():
            if k.lower() == 'set-cookie':
                parts = str(v).split(";")[0]
                if '=' in parts:
                    name, _, val = parts.partition('=')
                    cookies[name.strip()] = val.strip()

    return cookies

class PortInputModal(ModalScreen):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel")
    ]
    def compose(self) -> ComposeResult:
        with Center():
            with Vertical(id="port-modal"):
                yield Static("Enter ports", id="title")
                yield Input(
                    placeholder="80,443,8000-8100",
                    id="port-input"
                )

    def on_mount(self):
        self.query_one(Input).focus()

    def on_input_submitted(self, event: Input.Submitted):
        self.dismiss(event.value)
    def action_cancel(self):
        self.dismiss(None)