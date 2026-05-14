##Module Function
from .request import send_request, send_request_with_error
from models import get_config
from utils import get_logger, scan_port

##Module Package
import hashlib
import html as html_module
import re
import socket
import random
import time

log = get_logger("validate")

def _detech_tech(header: dict) -> list[str]:
    patterns = {
        "PHP": r"PHP\/([\d.]+)",
        "Nginx": r"nginx\/([\d.]+)",
        "Apache": r"Apache\/([\d.]+)",
        "OpenSSL": r"OpenSSL\/([\w\d.]+)",
        "LiteSpeed": r"LiteSpeed",
        "Express": r"Express",
        "ASP.NET": r"ASP\.NET",
        "Cloudflare": r"cloudflare",
    }

    if not header:
        return []

    detected = []
    header_str = "\n".join(
        f"{k}: {v}" for k, v in header.items()
    )

    for name, pattern in patterns.items():
        match = re.search(pattern, header_str, re.IGNORECASE)
        if match:
            if match.lastindex:
                version = match.group(1)
                detected.append(f"{name}/{version}")
            else:
                detected.append(name)

    return sorted(list(set(detected)))

def _extract_title(res) -> str:
    try:
        res.encoding = res.charset_encoding or "utf-8"
        match = re.search(f"<title>(.*?)</title>", res.text, re.IGNORECASE | re.DOTALL)
        if match:
            title = html_module.unescape(match.group(1).strip())
            return title.replace("\n", " ").replace("\r", "")
        return "-"
    except Exception:
        return "-"

def parse_response(res, error: str | None) -> dict:
    if res is None:
        return {"status": error or "CONN_ERR"}

    try:
        body_hash = (
            hashlib.md5(res.content).hexdigest()
            if res.content
            else "d41d8cd98f00b204e9800998ecf8427e"
        )
        raw_headers = dict(res.headers)

        return {
            "status": res.status_code,
            "title": _extract_title(res),
            "server": res.headers.get("Server", "Unknown"),
            "location": res.headers.get("Location", "-"),
            "latency": int(res.elapsed.total_seconds() * 1000),
            "size": len(res.content),
            "timestamp": res.headers.get("Date"),
            "raw_header": raw_headers,
            "body_hash": body_hash,
            "header_keys": list(res.headers.keys()),
            "tech": _detech_tech(raw_headers),
        }
    except Exception as e:
        log.error(f"Parse_response error: {e}")
        return {"status": "CONN_ERR"}

def validate_subdomain(sub, wildcard_baseline):
    config = get_config()

    if config.delay > 0:
        humane_sleep(config.delay)

    try:
        try:
            ip_address = socket.gethostbyname(sub)
        except socket.gaierror:
            ip_address = "No IP"

        custom_dns = config.dns

        http_res, http_err = send_request_with_error("http", sub, config.timeout, custom_dns)
        https_res, https_err = send_request_with_error("https", sub, config.timeout, custom_dns)

        h = parse_response(http_res, http_err)
        s = parse_response(https_res, https_err)

        http_status = h.get("status")
        http_title = h.get("title", "")
        http_size = h.get("size", 0) or 0
        https_status = s.get("status")
        https_title = s.get("title", "")
        https_size = s.get("size", 0) or 0
        timestamp = h.get("timestamp") or s.get("timestamp")

        ##Validate Wildcard
        baselines = wildcard_baseline
        http_wildcard = False
        https_wildcard = False

        http_size_val = len(http_size) if isinstance(http_size, bytes) else http_size
        https_size_val = len(https_size) if isinstance(https_size, bytes) else https_size
        if baselines["http"]:
            if (baselines["http"]["status"] == 200 and
                baselines["http"]["size"] ==  http_size_val and
                baselines["http"]["title"] == http_title):
                http_wildcard = True
        if baselines["https"]:
            if (baselines["https"]["status"] == 200 and
                baselines["https"]["size"] == https_size_val and
                baselines["https"]["title"] == https_title):
                https_wildcard = True
        if (http_wildcard or https_wildcard) and config.no_wildcard:
            data = {"subdomain": sub, "signing": "[W]", "status": "Filtered (Wildcard)"}
            return False, ip_address, data

        is_any_wildcard = http_wildcard or https_wildcard
        signing = sign(http_status, https_status, is_any_wildcard)

        data = {
            "timestamp": timestamp,
            "subdomain": sub,
            "ip_address": ip_address,
            "http": {
                "status": http_status,
                "title": http_title,
                "server": h.get("server", "Unknown"),
                "size": http_size,
                "latency": h.get("latency"),
                "redir": h.get("location", "-"),
                "tech": h.get("tech", []),
                "raw_header": h.get("raw_header", {}),
                "body_hash": h.get("body_hash"),
                "header_keys": h.get("header_keys", []),
            },
            "https": {
                "status": https_status,
                "title": https_title,
                "server": s.get("server", "Unknown"),
                "size": https_size,
                "latency": s.get("latency"),
                "redir": s.get("location", "-"),
                "tech": s.get("tech", []),
                "raw_header": s.get("raw_header", {}),
                "body_hash": s.get("body_hash"),
                "header_keys": s.get("header_keys", []),
            },
            "signing": signing,
            "wildcard": is_any_wildcard,
        }

        if config.port:
            ports = scan_port(sub, config.port)
            if ports:
                data["ports"] = ports

        if config.screenshot:
            from utils import take_screenshot, can_screenshot
            ok, reason = can_screenshot(data)
            if ok:
                success, path_or_err = take_screenshot(data)
                if success:
                    data["screenshot"] = path_or_err

        status_ok = 200 in [http_status, https_status]

        return status_ok, ip_address, data
    except Exception as e:
        log.error(f"Error: {sub} -> {e}")
        return False, "No IP", None

def humane_sleep(base_delay: float):
    config = get_config()

    if config.delay > 0:
        jitter = base_delay * 0.25
        actual_delay = random.uniform(base_delay - jitter, base_delay + jitter)
        time.sleep(actual_delay)
    else:
        time.sleep(random.uniform(0.1, 0.5))

def sign(http_status, https_status, is_wildcard) -> str:
    if is_wildcard:
        return "[?]"
    elif http_status == 200 or https_status == 200:
        return "[*]"
    elif http_status == 403 or https_status == 403:
        return "[!]"
    else:
        return "[-]"