##Module Function
from utils import sign, show_output, show_quiet, ReconStats
from .request import send_request
from .honeypot import HoneypotAnalyzer
from models import scan_config

##Module Package
import socket
import requests
import random
import time

stats = ReconStats()

def validate_subdomain(sub, wildcard_baseline):
    config = scan_config.current

    if config.delay > 0:
        humane_sleep(config.delay)

    try:
        try:
            ip_address = socket.gethostbyname(sub)
        except socket.gaierror:
            ip_address = "No IP"

        dict_http = send_request("http", sub, config.timeout)
        dict_https = send_request("https", sub, config.timeout)

        h = dict_http if dict_http else {}
        s = dict_https if dict_https else {}

        timestamp = h.get("timestamp") or s.get("timestamp")

        http_status = h.get("status")
        http_server = h.get("http_server", "Unknown")
        http_latency = h.get("latency")
        http_size = h.get("length", b"")
        http_redir = h.get("location", "-")
        http_title = h.get("title", "")
        http_header = h.get("header") if h.get("header") is not None else {}
        http_keys = h.get("header") or []
        http_hash = h.get("body_hash")

        https_status = s.get("https_status")
        https_server = s.get("server", "Unknown")
        https_latency = s.get("latency")
        https_size = s.get("length", b"")
        https_redir = s.get("location", "-")
        https_title = s.get("title", "")
        https_header = s.get("header") if s.get("header") is not None else {}
        https_keys = s.get("header") or []
        https_hash = s.get("body_hash")


        ##Validate Wildcard
        baselines = wildcard_baseline
        http_wildcard = False
        https_wildcard = False
        if baselines["http"]:
            if baselines["http"]["status"] == 200 and baselines["http"]["size"] == len(http_size) if isinstance(http_size, bytes) else http_size and baselines["http"]["title"] == http_title:
                http_wildcard = True
        if baselines["https"]:
            if baselines["https"]["status"] == 200 and baselines["https"]["size"] == len(https_size) if isinstance(https_size, bytes) else https_size and baselines["https"]["title"] == https_title:
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
        if config.quiet:
            show_quiet(is_okay=status_ok, sub=sub, ip=ip_address, show_ip=config.quiet_ip)
        else:
            show_output(data, HoneypotAnalyzer)
        stats.log(http_status, https_status)
        return status_ok, ip_address, data

    except requests.exceptions.RequestException:
        return False, "No IP", None
    except Exception as e:
        print(f"Error: {sub} -> {e}")
        return False, "No IP", None

def humane_sleep(base_delay: float):
    config = scan_config.current

    if config.delay > 0:
        jitter = base_delay * 0.5
        actual_delay = random.uniform(base_delay - jitter, base_delay + jitter)
        time.sleep(actual_delay)
    else:
        time.sleep(random.uniform(0.1, 0.5))