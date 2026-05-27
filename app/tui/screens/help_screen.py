from textual.screen import ModalScreen
from textual.widgets import Static, ScrollableContainer
from textual.binding import Binding
from textual.app import ComposeResult
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.text import Text
from rich.console import Group


class HelpScreen(ModalScreen):
    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("f1", "dismiss", "Close"),
        Binding("q", "dismiss", "Close"),
    ]

    def compose(self) -> ComposeResult:
        yield ScrollableContainer(
            Static(self._build_help(), id="help-content"),
            id="help-scroll"
        )

    def _build_help(self):
        sections = []

        # ── Navigation ──────────────────────────────────────────
        nav = Table.grid(padding=(0, 2))
        nav.add_column(style="#00E0FF", justify="right", min_width=16)
        nav.add_column(style="#C0CAF5")
        nav.add_row("↑ / ↓", "Navigate table rows")
        nav.add_row("Enter / D", "Open side detail panel")
        nav.add_row("F", "Toggle fullscreen detail view")
        nav.add_row("Escape", "Close detail panel / unfocus filter bar")
        nav.add_row("Tab", "Switch focus between panels")
        sections.append(Rule(title="[bold #FFD700]Navigation[/]", style="#1A1B26", align="left"))
        sections.append(nav)

        # ── Fullscreen-only ──────────────────────────────────────
        fs = Table.grid(padding=(0, 2))
        fs.add_column(style="#00E0FF", justify="right", min_width=16)
        fs.add_column(style="#C0CAF5")
        fs.add_row("S", "Screenshot the live page (Playwright headless Chromium)")
        fs.add_row("X", "Run deep scan on current subdomain")
        fs.add_row("P", "Port scan — prompts for port range (e.g. 80,443,8000-8100)")
        fs.add_row("F / Escape / Q", "Close fullscreen and return to table")
        sections.append(Rule(title="[bold #FFD700]Fullscreen Only[/]", style="#1A1B26", align="left"))
        sections.append(fs)

        # ── Actions ─────────────────────────────────────────────
        act = Table.grid(padding=(0, 2))
        act.add_column(style="#00E0FF", justify="right", min_width=16)
        act.add_column(style="#C0CAF5")
        act.add_row("A", "Open action menu — launch external tool on selected subdomain")
        act.add_row("Shift+A", "Open bulk action menu — run tool against all filtered results")
        act.add_row("B", "Open selected subdomain in browser")
        act.add_row("C", "Copy subdomain to clipboard")
        act.add_row("S", "Screenshot selected subdomain (main table)")
        act.add_row("E", "Export selected result")
        act.add_row("Shift+E", "Export all filtered results")
        act.add_row("R", "Refresh — restart scan (preserves current filter)")
        act.add_row("Q", "Quit")
        sections.append(Rule(title="[bold #FFD700]Actions[/]", style="#1A1B26", align="left"))
        sections.append(act)

        # ── Filter syntax ────────────────────────────────────────
        fil = Table.grid(padding=(0, 2))
        fil.add_column(style="#00E0FF", justify="right", min_width=22)
        fil.add_column(style="#C0CAF5")

        fil.add_row("/ (slash)", "Focus the filter bar")
        fil.add_row("", "")

        filter_rows = [
            ("status:200",           "Exact HTTP status code"),
            ("status:live",          "200 or any redirect"),
            ("status:available",     "Any valid HTTP response"),
            ("status:forbidden",     "401 / 402 / 403"),
            ("status:redirect",      "301 / 302 / 307 / 308"),
            ("status:misconfigured", "526 / 527 / 530 (Cloudflare errors)"),
            ("server:nginx",         "Match server header value"),
            ("tech:php",             "Match detected technology"),
            ("title:admin",          "Match page title"),
            ("subdomain:*.dev.*",    "Glob match on subdomain name"),
            ("ip:1.2.3.*",           "Match IP (supports * wildcard)"),
            ("ip:proxy",             "Show only CDN / proxy IPs"),
            ("honeypot:true",        "Show suspected honeypots (score ≥ 50%)"),
            ("honeypot:confirmed",   "Match by confidence label"),
            ("wildcard:true",        "Show / hide wildcard matches"),
            ("size:500-5000",        "Filter by response body size (bytes)"),
            ("latency:100-500",      "Filter by response latency (ms)"),
            ("port:443",             "Filter by open port"),
            ("has:login",            "Deep scan — login form detected"),
            ("has:register",         "Deep scan — registration page detected"),
            ("has:admin",            "Deep scan — admin panel detected"),
            ("has:credentials",      "Deep scan — hardcoded secrets found in JS"),
            ("has:js",               "Deep scan — JavaScript files were scanned"),
            ("NOT status:404",       "Negate any filter"),
        ]
        for query, desc in filter_rows:
            fil.add_row(query, desc)

        sections.append(Rule(title="[bold #FFD700]Filter Query Syntax[/]", style="#1A1B26", align="left"))
        sections.append(fil)

        # ── External Tools ───────────────────────────────────────
        tools = Table.grid(padding=(0, 2))
        tools.add_column(style="#BB9AF7", justify="right", min_width=16)
        tools.add_column(style="#C0CAF5")
        tool_rows = [
            ("Nmap",          "Fast port discovery / full service enumeration"),
            ("FFuf",          "Directory fuzzing / JSON payload fuzzing"),
            ("SQLMap",        "SQL injection testing"),
            ("Nuclei",        "Vulnerability template scanning"),
            ("Nikto",         "Web server vulnerability scanning"),
            ("WafW00f",       "WAF fingerprinting (supports bulk mode)"),
            ("WhatWeb",       "Web technology fingerprinting (supports bulk mode)"),
            ("theHarvester",  "OSINT — emails, subdomains, names"),
            ("Whois",         "Domain ownership lookup"),
            ("Dig",           "DNS record inspection"),
            ("Curl",          "HTTP header inspection"),
            ("Searchsploit",  "Exploit DB search (auto-matched to detected tech)"),
        ]
        for tool, desc in tool_rows:
            tools.add_row(tool, desc)

        sections.append(Rule(title="[bold #FFD700]External Tools  (A / Shift+A)[/]", style="#1A1B26", align="left"))
        sections.append(tools)

        # ── Deep Scan ────────────────────────────────────────────
        ds = Table.grid(padding=(0, 2))
        ds.add_column(style="#F7768E", justify="right", min_width=16)
        ds.add_column(style="#C0CAF5")
        ds.add_row("Favicon Hash",   "MMH3 hash → known tech / honeypot DB + Shodan query")
        ds.add_row("Tech Version",   "Header + HTML body → precise version fingerprinting")
        ds.add_row("Page Recon",     "URL crawl, login/admin/register detection, JS secret scanning")
        ds.add_row("", "")
        ds.add_row(
            Text("⚠ Warning", style="bold #F7768E"),
            Text("Deep scan sends many extra requests per subdomain", style="#F7768E")
        )
        sections.append(Rule(title="[bold #FFD700]Deep Scan  (X in fullscreen  /  --deep-scan)[/]", style="#1A1B26", align="left"))
        sections.append(ds)

        # ── Misc ─────────────────────────────────────────────────
        misc = Table.grid(padding=(0, 2))
        misc.add_column(style="#00E0FF", justify="right", min_width=16)
        misc.add_column(style="#C0CAF5")
        misc.add_row("F1", "Show this help screen")
        misc.add_row("% button", "Toggle percentage display in stats bar")
        sections.append(Rule(title="[bold #FFD700]Other[/]", style="#1A1B26", align="left"))
        sections.append(misc)

        from rich.console import Group as RichGroup
        return Panel(
            RichGroup(*sections),
            title="[bold #FFD700]  Keyboard Reference  [/]",
            subtitle="[#565F89]ESC / F1 / Q  →  close[/]",
            border_style="#00A3FF",
            padding=(1, 2),
        )

    def action_dismiss(self):
        self.app.pop_screen()
