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
from tldextract import tldextract

from utils import do_screenshot, parse_port, scan_port, get_logger, load_result_from_cache
from ..widgets import format_redirect

log = get_logger("fullscreen")

def _get_status_value(status_field) -> str:
    if hasattr(status_field, "value"):
        return status_field.value
    return str(status_field)

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
        deep_data = r.get('deep_scan', {})

        sections = []

        # Header identity
        sections.append(self._header_identity(r))
        
        # Protocol
        sections.append(Rule(title="[bold #00A3FF]PROTOCOL[/]", style="#1A1B26", align='left'))
        protocol_section = self._protocol_comparison(r)
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

        # Honeypot
        sections.append(Rule(title="[bold #00A3FF]HONEYPOT ANALYSIS[/]", style="#1A1B26", align='left'))
        sections.append(self._honeypot_analysis(r))

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

        def formatting_status(status: str) -> str:
            if status == "running":
                return f"[#BB9AF7]↻ {status}...[/]"
            elif status == "done":
                return f"[#73DACA]✓ {status}[/]"
            elif status == "error":
                return f"[#F7768E]✗ {status}[/]"
            else:
                return f"[#565F89]{status}[/]"

## Deep Scan Results
        # Favicon
        if 'favicon' in deep_data:
            sections.append(Rule(title="[bold #00A3FF]FAVICON IDENTIFICATION[/]", style="#1A1B26", align='left'))
            fav_info = deep_data.get("favicon")
            status = _get_status_value(fav_info['status'])

            status_str = formatting_status(status)

            fav_table = _make_table()
            fav_table.add_row("Favicon Scan", status_str)

            deep_table = _make_table()
            if status == "done" and fav_info["data"]:
                d = fav_info["data"]
                if d.get("hash_mmh3"):
                    deep_table.add_row("", f"  [#00A3FF]MMH3:[/] {d['hash_mmh3']}")
                if d.get('matched'):
                    deep_table.add_row("", f"  [#73DACA]Tech:[/] [bold]{d['matched']}[/]")
                if d.get("shodan_query"):
                    deep_table.add_row("", f"  [#565F89]Scan:[/] {d['shodan_query']}")
            sections.append(fav_table)

        # Page Recon Results
        if 'page_recon' in deep_data:
            sections.append(Rule(title="[bold #00A3FF]PAGE RECON[/]", style="#1A1B26", align='left'))
            pr_info = deep_data.get("page_recon")
            pr_status = _get_status_value(pr_info['status'])
            pr_status_str = formatting_status(pr_status)

            pr_table = _make_table()
            pr_table.add_row("Page Recon", pr_status_str)

            if pr_status == "done" and pr_info.get("data"):
                d = pr_info["data"]

                total_urls = d.get("total_urls", 0)
                pr_table.add_row("Total URLs", f"[#00E0FF]{total_urls}[/] found")

                # All extracted URLs
                all_urls = d.get("urls", [])
                internal_urls = [u for u in all_urls if u.get("internal")]
                if internal_urls:
                    pr_table.add_row("", "")
                    pr_table.add_row("[#565F89]Internal URLs[/]", "")
                    for entry in internal_urls[:30]:
                        pr_table.add_row("", f"[#00E0FF]{entry.get('url', '')}[/]")
                    if len(internal_urls) > 30:
                        pr_table.add_row("", f"[#565F89]  +{len(internal_urls) - 30} more...[/]")

                external_urls = [u for u in all_urls if not u.get("internal")]
                if external_urls:
                    pr_table.add_row("", "")
                    pr_table.add_row("[#565F89]External URLs[/]", "")
                    for entry in external_urls[:10]:
                        pr_table.add_row("", f"[#565F89]{entry.get('url', '')}[/]")
                    if len(external_urls) > 10:
                        pr_table.add_row("", f"[#565F89]  +{len(external_urls) - 10} more...[/]")

                pr_table.add_row("", "")

                # Login
                login = d.get("login", {})
                if login.get("detected"):
                    login_paths = login.get("paths", [])
                    pr_table.add_row(
                        "Login Page",
                        f"[#73DACA]✓ Detected[/] [#565F89]({login.get('signal_count', 0)} signals)[/]"
                    )
                    for url in login_paths[:5]:
                        pr_table.add_row("", f"  [#565F89]↳[/] [#73DACA]{url}[/]")
                else:
                    pr_table.add_row("Login Page", "[#565F89]Not detected[/]")

                # Register
                register = d.get("register", {})
                if register.get("detected"):
                    register_paths = register.get("paths", [])
                    pr_table.add_row(
                        "Register Page",
                        f"[#73DACA]✓ Detected[/] [#565F89]({register.get('signal_count', 0)} signals)[/]"
                    )
                    for url in register_paths[:5]:
                        pr_table.add_row("", f"  [#565F89]↳[/] [#73DACA]{url}[/]")
                else:
                    pr_table.add_row("Register Page", "[#565F89]Not detected[/]")

                # Admin
                admin = d.get("admin", {})
                if admin.get("detected"):
                    admin_paths = admin.get("paths", [])
                    pr_table.add_row(
                        "Admin Panel",
                        f"[#F7768E]⚠ Detected[/] [#565F89]({admin.get('signal_count', 0)} signals)[/]"
                    )
                    for url in admin_paths[:5]:
                        pr_table.add_row("", f"  [#565F89]↳[/] [#F7768E]{url}[/]")
                else:
                    pr_table.add_row("Admin Panel", "[#565F89]Not detected[/]")

                sections.append(pr_table)

                # Interesting URLs section
                interesting = d.get("interesting", [])
                if interesting:
                    sections.append(Rule(title="[bold #00A3FF]INTERESTING URLS[/]", style="#1A1B26", align='left'))
                    category_colors = {
                        "api": "#BB9AF7",
                        "auth": "#73DACA",
                        "register": "#73DACA",
                        "admin": "#F7768E",
                        "file": "#FFD700",
                        "sensitive": "#F7768E",
                        "page": "#565F89",
                    }
                    url_table = _make_table()
                    for entry in interesting[:30]:
                        cat = entry.get("category", "page")
                        color = category_colors.get(cat, "#565F89")
                        url_table.add_row(
                            f"[{color}]{cat}[/]",
                            f"[#00E0FF]{entry.get('url', '')}[/]"
                        )
                    if len(interesting) > 30:
                        url_table.add_row(
                            "[#565F89]...[/]",
                            f"[#565F89]+{len(interesting) - 30} more[/]"
                        )
                    sections.append(url_table)

            else:
                sections.append(pr_table)

        # Headers http
        sections.append(Rule(title="[bold #00A3FF]HTTP Headers[/]", style="#1A1B26", align='left'))
        h_header = http.get("raw_header") or {}
        if h_header:
            ht2 = _make_table()
            for k, v in h_header.items():
                ht2.add_row(str(k), str(v)[:80])
            sections.append(ht2)
        else:
            sections.append(Text("  No headers captured", style="#565F89"))

        # Headers https
        sections.append(Rule(title="[bold #00A3FF]HTTPS Headers[/]", style="#1A1B26", align='left'))
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

        status_color = "#73DACA" if is_live else "#565F89"
        status_text = "● Live" if is_live else "● Offline"

        identity = Table.grid(expand=True)
        identity.add_column(justify="left", ratio=1)
        identity.add_column(justify="right", vertical='top')
        sub_display = f"[bold #00E0FF underline]{subdomain}[/]"
        status_display = f"[{status_color}]{status_text}[/]"

        identity.add_row(sub_display, status_display)
        identity.add_row(f"[italic #00A3FF]{ip}[/]", "")

        if wildcard:
            identity.add_row("[#00E0FF]◈ Wildcard Detected[/]", "")

        return Panel(
            identity,
            border_style="#00A3FF",
            padding=(1, 2),
            title="[#565F89]Target Identity[/]",
            title_align="left"
        )
    @staticmethod
    def _protocol_comparison(data:dict) -> Table:
        http = data.get('http', {})
        https = data.get('https', {})
        redir = format_redirect(http.get('redir'), data.get('subdomain'))
        is_upgrade = 'upgrade' in redir.lower()

        def _create_proto_table(target_data, is_http: bool = False):

            table = Table.grid(padding=(0, 1), expand=True)
            table.add_column(style="#565F89", justify="left", width=10)
            table.add_column(style="#00E0FF", justify="right")

            status = target_data.get("status")
            status_str = _format_status_colored(status)
            if is_http and status in (301, 302, 307, 308):
                if is_upgrade:
                    res_status = f"[#9ECE6A]{str(status)}[/] {redir}"
                else:
                    res_status = f"{status_str} -> {redir}"
            else:
                res_status = status_str
            table.add_row("Status", res_status)
            table.add_row("Server", (target_data.get("server") or "-")[:18])
            table.add_row("Latency", f"{target_data.get('latency')}ms" if target_data.get("latency") else "N/A")
            table.add_row("Size", f"{target_data.get('size', 0):,} B")
            table.add_row("Title", (target_data.get("title") or "-")[:30])
            table.add_row("Tech", ", ".join(target_data.get("tech", [])[:4]) or "-")
            return table

        layout_grid = Table.grid(padding=(0, 0), expand=True)
        layout_grid.add_column(ratio=1)
        layout_grid.add_column(width=5, justify='center', min_width=5)
        layout_grid.add_column(ratio=1)

        if is_upgrade:
            arrow = Text.from_markup("\n\n\n[#73DACA]➤[/]", justify="center")
            h_border, s_border = "#565F89", "#73DACA"
        else:
            arrow = Text("")
            h_border, s_border = "#00A3FF", "#00A3FF"

        layout_grid.add_row(
            Panel(_create_proto_table(http, True), title="[bold #FFD700]HTTP[/]", border_style=h_border, expand=True),
            arrow,
            Panel(_create_proto_table(https), title="[bold #FFD700]HTTPS[/]", border_style=s_border, expand=True)
        )
        return layout_grid

    @staticmethod
    def _honeypot_analysis(result: dict):
        score = result.get("honeypot_score", 0)
        label = result.get("honeypot_label", "Unlikely")
        findings = result.get("honeypot_findings", [])

        width = 30
        filled = int(score * width)
        bar = ""
        for i in range(width):
            if i < filled:
                color = "#00E0FF" if i < (width * 0.5) else "#00A3FF"
                bar += f"[{color}]█[/]"
            else:
                bar += "[#292a3a]█[/]"

        text_color = "#F7768E" if score >= 0.75 else "#FFD700" if score >= 0.5 else "#73DACA"

        analysis = Table.grid(padding=(0, 1))
        analysis.add_column()
        analysis.add_row(bar)
        analysis.add_row(f"[bold {text_color}]{score * 100:.0f}% ―  {label}[/]")

        if findings:
            for f in findings:

                analysis.add_row(f"[#BB9AF7]● [/] [{text_color}]{f[:80]}[/]")
        else:
            analysis.add_row(" [#565F89]○ No suspicious bait detected[/]")

        return analysis
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
            self.app.call_from_thread(self._refresh_detail)

            subdomain = self.result.get("subdomain", "")
            root = tldextract.extract(subdomain)
            domain_root = f"{root.domain}{root.suffix}"
            cached_data = load_result_from_cache(domain_root)
            if subdomain in cached_data:
                cached_result = cached_data[subdomain]
                if "deep_scan" in cached_result:
                    self.result['deep_scan'] = cached_result['deep_scan']

            self.app.call_from_thread(self._refresh_detail)

            if key == 'tech_version':
                self._merge_deep_tech_to_protocols()
                self.app.call_from_thread(self._refresh_detail)
        self.notify("Starting Deep Scan...", title="Deep Scanning")

        run_deep_scan(self.result, on_module_done)

    def _merge_deep_tech_to_protocols(self):
        deep_data = self.result.get("deep_scan", {})
        tech_module = deep_data.get('tech_version', {})

        status_obj = tech_module.get("status")
        if _get_status_value(status_obj) == 'done':
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
    return Rule(title=f"[bold #00A3FF]{title}[/]", style="#1A1B26", align='left')

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