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
from ..widgets.subdomain_table import _normalize_status
from ..widgets.detail_panel import _format_redirect
from utils import do_screenshot, parse_port, scan_port


class FullscreenDetail(Screen):
    BINDINGS = [
        Binding("f", "dismiss_screen", "Close Fullscreen"),
        Binding("escape", "dismiss_screen", "Close"),
        Binding("q", "dismiss_screen", "Close"),
        Binding("s", "screenshot", "Screenshot"),
        Binding("p", "scan_port", "Scan Ports")
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
        signing = r.get("signing", "[ ]")
        is_live = r.get("is_live", False)
        wildcard = r.get("wildcard", False)
        score = r.get("honeypot_score", 0)
        label = r.get("honeypot_label", "Unlikely")

        status_color = "#73DACA" if is_live else "#565F89"
        identity = Table.grid(padding=(0, 2))
        identity.add_column(justify="center")
        identity.add_row(f"[bold #00E0FF]{subdomain}[/]")
        identity.add_row(f"[italic #00A3FF]{ip}[/]")
        identity.add_row(
            f"[{status_color}]{'● Live' if is_live else '● Offline'}[/]"
            + ("  [#00E0FF]◈ Wildcard[/]" if wildcard else "")
            + (f"  [#BB9AF7]🍯 {score * 100:.0f}% {label}[/]" if score > 0 else "")
        )
        sections.append(Panel(identity, border_style="#00A3FF", padding=(0, 1)))

        # General
        sections.append(_section_rule("General"))
        gen = _make_table()
        gen.add_row("Subdomain", subdomain)
        gen.add_row("IP Address", ip)
        gen.add_row("Wildcard", "[#00E0FF]Detected[/]" if wildcard else "[#565F89]No[/]")
        gen.add_row("Timestamp", r.get("timestamp", "-") or "-")
        gen.add_row("Sign", signing)
        sections.append(gen)

        # HTTP
        sections.append(_section_rule("HTTP"))
        ht = _make_table()
        h_st = _normalize_status(http.get("status"))
        ht.add_row("Status", _status_colored(h_st))
        ht.add_row("Server", http.get("server", "-") or "-")
        ht.add_row("Latency", f"{http.get('latency')}ms" if http.get("latency") else "N/A")
        ht.add_row("Size", f"{http.get('size', 0):,} bytes")
        ht.add_row("Title", http.get("title", "-") or "-")
        ht.add_row("Redirect", _format_redirect(http.get("redir"), subdomain))
        ht.add_row("Body Hash", http.get("body_hash", "-") or "-")
        sections.append(ht)

        # HTTPS
        sections.append(_section_rule("HTTPS"))
        st = _make_table()
        s_st = _normalize_status(https.get("status"))
        st.add_row("Status", _status_colored(s_st))
        st.add_row("Server", https.get("server", "-") or "-")
        st.add_row("Latency", f"{https.get('latency')}ms" if https.get("latency") else "N/A")
        st.add_row("Size", f"{https.get('size', 0):,} bytes")
        st.add_row("Title", https.get("title", "-") or "-")
        st.add_row("Redirect", _format_redirect(https.get("redir"), subdomain))
        st.add_row("Body Hash", https.get("body_hash", "-") or "-")
        sections.append(st)

        # Ports
        ports = r.get("ports")
        if ports:
            sections.append(_section_rule("Ports"))
            port_table = _make_table()
            for port, status in sorted(ports.items()):
                if status == "open":
                    status_text = f"[#73DACA]{status}[/]"
                else:
                    status_text = f"[#FFD700]{status}[/]"

                port_table.add_row(f"{port}/tcp", status_text)
            sections.append(port_table)

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
        sections.append(_section_rule("Tech Detection"))
        tech = list(set((http.get("tech") or []) + (https.get("tech") or [])))
        if tech:
            tech_table = _make_table()
            for item in tech:
                tech_table.add_row("Detected", item)
            sections.append(tech_table)
        else:
            sections.append(Text("  No tech detected", style="#565F89"))

        # Honeypot
        sections.append(_section_rule("Honeypot Analysis"))
        honeypot_table = _make_table()
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
        honeypot_table.add_row("Score", f"{bar} [{text_color}]{score * 100:.0f}%[/]")
        honeypot_table.add_row("Label", f"[{text_color} bold]{label}[/]")

        findings = r.get("honeypot_findings", [])
        if findings:
            honeypot_table.add_row("", "")
            for f in findings:
                honeypot_table.add_row("[#565F89]Finding[/]", f[:70])
        sections.append(honeypot_table)

        # Headers
        sections.append(_section_rule("HTTP Header"))
        h_header = http.get("raw_header") or {}
        if h_header:
            ht2 = _make_table()
            for k, v in h_header.items():
                ht2.add_row(str(k), str(v)[:80])
                sections.append(ht2)
        else:
            sections.append(Text("  No headers captured", style="#565F89"))

        sections.append(_section_rule("HTTPS Header"))
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

    def action_screenshot(self):
        def refresh():
            self.query_one(
                "#fullscreen-conten",
                Static
            ).update(self._build_content())

        do_screenshot(
            app=self.app,
            result=self.result,
            notify=self.notify,
            callback=refresh
        )

    def action_scan_port(self):
        def handle_input(value):
            if not value:
                return
            ports = parse_port(value)
            self.notify(f"Scanning {len(ports)} ports...")
            result = scan_port(
                self.result["subdomain"],
                ports
            )
            self.result["ports"] = result

            self.query_one(
                "#fullscreen-content",
                Static
            ).update(self._build_content())

        self.app.push_screen(
            PortInputModal(),
            callback=handle_input
        )

    def action_dismiss_screen(self):
            self.app.pop_screen()

#Helper
def _make_table():
    t = Table.grid(padding=(0, 2))
    t.add_column(style="#565F89", justify="right", min_width=14)
    t.add_column(style="#00E0FF", min_width=40)
    return t

def _section_rule(title: str):
    return Rule(title=f"[bold #00A3FF]{title}[/]", style="#1A1B26")

def _status_colored(status: int):
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
            if k.lower() == 'set-cookies':
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