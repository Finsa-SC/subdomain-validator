##Module Function
from .request import send_request
from analysis import HoneypotAnalyzer
from models import get_config
from utils import get_logger

##Module Package
import socket
import random
import time

log = get_logger("validate")

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

        dict_http = send_request("http", sub, config.timeout, custom_dns)
        dict_https = send_request("https", sub, config.timeout, custom_dns)

        h = dict_http if dict_http else {}
        s = dict_https if dict_https else {}

        timestamp = h.get("timestamp") or s.get("timestamp")

        http_status = h.get("status")
        http_server = h.get("server", "Unknown")
        http_latency = h.get("latency")
        http_size = h.get("size", b"")
        http_redir = h.get("location", "-")
        http_title = h.get("title", "")
        http_header = h.get("header") if h.get("header") is not None else {}
        http_keys = h.get("header") or []
        http_hash = h.get("body_hash")

        https_status = s.get("status")
        https_server = s.get("server", "Unknown")
        https_latency = s.get("latency")
        https_size = s.get("size", b"")
        https_redir = s.get("location", "-")
        https_title = s.get("title", "")
        https_header = s.get("header") if s.get("header") is not None else {}
        https_keys = s.get("header") or []
        https_hash = s.get("body_hash")

        ##Size filtering
        if size_filtering(http_size, https_size):
            return None, None, None

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
            return None, None, None

        is_any_wildcard = http_wildcard or https_wildcard
        signing = sign(http_status, https_status, is_any_wildcard)

        data = {
            "timestamp": timestamp,
            "subdomain": sub,
            "ip_address": ip_address,
            "http": {
                "status": http_status,
                "title": http_title,
                "server": http_server,
                "size": http_size if http_size else 0,
                "latency": http_latency,
                "redir": http_redir,
                "tech": http_header,
                "body_hash": http_hash,
                "header_keys": http_keys
            },
            "https": {
                "status": https_status,
                "title": https_title,
                "server": https_server,
                "size": https_size if https_size else 0,
                "latency": https_latency,
                "redir": https_redir,
                "tech": https_header,
                "body_hash": https_hash,
                "header_keys": https_keys
            },
            "signing": signing,
            "wildcard": is_any_wildcard
        }

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

def size_filtering(http_size: int = 0, https_size: int = 0) -> bool:
    config = get_config()

    max_size = config.max_size
    min_size = config.min_size

    if isinstance(http_size, bytes):
        http_size = len(http_size)
    if isinstance(https_size, bytes):
        https_size = len(https_size)

    if min_size is not None and min_size > -1:
        if (http_size <= 0 or http_size < min_size) and (https_size <= 0 or https_size < min_size):
            return True
    if max_size is not None and max_size > 0:
        if (http_size <= 0 or http_size > max_size) and (https_size <= 0 or https_size > max_size):
            return True
    return False

def sign(http_status, https_status, is_wildcard) -> str:
    if is_wildcard:
        return "[?]"
    elif http_status == 200 or https_status == 200:
        return "[*]"
    elif http_status == 403 or https_status == 403:
        return "[!]"
    else:
        return "[-]"