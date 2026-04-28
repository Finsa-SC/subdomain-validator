from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse
from utils import is_cloudflare
from models import scan_config, TITLE_IGNORE

# ANSI Colors (Soft/Standard)
RESET = "\033[0m"
LIME = "\033[38;5;112m"
YELLOW = "\033[33m"
WHITE = "\033[37m"
CYAN   = "\033[36m"
DIM = "\033[2m"

def colorize(text: Any, color_code: str):
    return f"{color_code}{text}{RESET}"

def print_legend():
    print(f"""
        [ LEGEND ]
        {colorize("[*]", LIME)} : Host is UP (HTTP/HTTPS 200)
        {colorize("[!]", YELLOW)} : Access Forbidden (403)
        {colorize("[?]", CYAN)} : Wildcard Subdomain Detected
        {colorize("[-]", WHITE)} : Host is Down / Other Status
        """)

def sign(http_status, https_status, is_wildcard) -> str:
    config = scan_config.current
    if is_wildcard:
        return colorize("[?]", CYAN if config.color else WHITE)
    elif http_status == 200 or https_status == 200:
        return colorize("[*]", LIME if config.color else WHITE)
    elif http_status == 403 or https_status == 403:
        return colorize("[!]", YELLOW if config.color else WHITE)
    else:
        return colorize("[-]", WHITE)

def show_verbose(http_status, https_status, show_redir=False, http_redir=None, https_redir=None, is_verbose: bool = False) -> str:
    status = []
    if is_verbose:
        if http_status == 200 and https_status != 200:
            status.append("HTTP ONLY")
        if https_status == 200 and http_status != 200:
            status.append("HTTPS ONLY")
        if https_status == 200 and http_status == 200:
            status.append("HTTP and HTTPS")
        if http_status == 403:
            status.append("HTTP FORBIDDEN")
        if https_status == 403:
            status.append("HTTPS FORBIDDEN")
        if show_redir:
            if http_redir and http_redir not in ["-", "None"]:
                status.append(f"HTTP REDIR: {clean_redirect(http_redir)}")
            if https_redir and https_redir not in ["-", "None"]:
                status.append(f"HTTPS REDIR: {clean_redirect(https_redir)}")

    else:
        status.append("(OK)" if http_status == 200 or https_status == 200 else "[!Forbidden]" if http_status == 403 or https_status == 403 else "")
    if status:
        return f"[ {', '.join(status)} ]"
    return ""

def show_output(data: Mapping[str, Any], honeypotAnalyze):
    config = scan_config.current

    http = data.get("http", {})
    https = data.get("https", {})

    ##Value
    ip_address = data.get("ip_address")
    is_wildcard = data.get("wildcard")
    sub = data.get("subdomain")
    h_status = http.get("status")
    s_status = https.get("status")
    h_latency = http.get("latency")
    s_latency = https.get("latency")
    h_redir = http.get("redir")
    s_redir = https.get("redir")
    h_title = http.get("title")
    s_title = https.get("title")
    h_tech = http.get("tech")
    s_tech = https.get("tech")
    h_server = http.get("server")
    s_server = https.get("server")

    server = s_server if s_server and "unknown" not in s_server.lower() else h_server or "Unknown"

    ##Config
    show_redir = config.redirect
    show_title = config.show_title
    is_verbose = config.verbose
    show_tech = config.show_tech
    show_honeypot = config.honeypot
    show_available = config.available

    # Set Color
    if not config.color:
        color = WHITE
    elif is_wildcard:
        color = CYAN
    elif 200 in [h_status, s_status]:
        color = LIME
    elif 403 in [h_status, s_status]:
        color = YELLOW
    else:
        color = WHITE

    h_out = h_status if isinstance(h_status, int) else "-"
    s_out = s_status if isinstance(s_status, int) else "-"

    status = show_verbose(h_status, s_status, show_redir, h_redir, s_redir, is_verbose)

    output_buffer = []
    output_line = (f"{sub: <40} | {ip_address: <15} | {server: <15} | "
              f"HTTP: {str(h_out): <3} ({f'{h_latency}ms)' if h_latency else 'N/A)': <7} | "
              f"HTTPS: {str(s_out): <3} ({f'{s_latency}ms)' if s_latency else 'N/A)': <7} {status}")

    output_buffer.append(f"{data.get('signing')} {colorize(output_line, color)}")

    if show_title:
        titles = get_title(h_title, s_title)
        output_buffer.extend([colorize(t, color) for t in titles])
    if show_tech:
        tech = get_tech(h_tech, s_tech)
        output_buffer.extend([colorize(t, color) for t in tech])
    if show_honeypot:
        honeypot, suggested_color = get_honeypot(data, config, honeypotAnalyze)
        if honeypot != "-":
            output_buffer.extend([colorize(t, suggested_color if suggested_color else color) for t in honeypot])

    if server is not None:
        if (200 in [h_status, s_status]) or not show_available:
            print("\n".join(output_buffer))
            return 200 in [h_status, s_status], ip_address
    return False, "No IP"


print_ip = []
def show_quiet(is_okay: int, sub: str = None, ip: str= None, show_ip: bool = False):
    if is_okay:
        if show_ip:
            is_reverse = is_cloudflare(ip)
            if ip not in print_ip and not is_reverse:
                print(ip)
                print_ip.append(ip)
        else:
            print(sub)

def get_title(http_title: str, https_title: str):
    def is_valid(title: str):
        if not title or not isinstance(title, str):
            return False
        for ignore_title in TITLE_IGNORE:
            if ignore_title in title.lower().strip():
                return False
        return True

    h = http_title if is_valid(http_title) else None
    s = https_title if is_valid(https_title) else None
    lines = []

    if h == s and h:
        lines.append(f"        |_title: [{h}]")
    else:
        if h:
            lines.append(f"        |_http title : [{h}]")
        if s:
            lines.append(f"        |_https title: {s}")
    return lines

def get_tech(http_header, https_header):
    target_headers = ["X-Powered-By", "X-Generator", "Server"]
    lines = []

    def get_tech_list(header):
        found = []
        for h in target_headers:
            val = header.get(h)
            if val and val.strip() not in ["-", "None", ""]:
                found.append(val)
        return ", ".join(found) if found else None

    h_tech = get_tech_list(http_header)
    s_tech = get_tech_list(https_header)

    if h_tech == s_tech and h_tech:
        lines.append(f"        |_Tech      : {h_tech}")
    else:
        if h_tech:
            lines.append(f"        |_http Tech : {h_tech}")
        if s_tech:
            lines.append(f"        |_https Tech: {s_tech}")
    return lines

def clean_redirect(url, max_len: int = 30):
    if not url or url in ["-", "None"]:
        return None
    parsed = urlparse(url)
    target = parsed.netloc if parsed.netloc else parsed.path

    if not parsed.netloc and parsed.path:
        target = parsed.path

    if len(target) > max_len:
        return target[:max_len-3] + "..."
    return target

def get_banner():
    base_path = Path(__file__).resolve().parent.parent.parent
    banner_path = base_path / "assets" / "banner.txt"
    try:
        with open(banner_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        print("-----( Subdomain Validator )-----")

def get_honeypot(data, config, honeypotAnalyze):
    honeypot = honeypotAnalyze(data, config)
    score, label, findings = honeypot.run_all()
    if score == 0.0: return "-", None

    suggested_color = WHITE
    if score >= 0.8:
        suggested_color = "\033[31;1m"
    elif score >= 0.4:
        suggested_color = "\033[38;5;208m"

    bars_lenght = 10
    filled_len = int(round(bars_lenght * score))
    bar = "█" * filled_len + "░" * (bars_lenght - filled_len)
    score_pct = f"{score * 100:.1f}%"
    finding_pct = ", ".join(findings) if findings else "No specific patterns"
    return [f"        |_Honeypot: {bar} {score_pct} [{label}]",
            f"        |_[ Findings: {finding_pct} ]"], suggested_color