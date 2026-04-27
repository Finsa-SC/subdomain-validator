##Module Function
from utils import sign, show_output, show_quiet, save_file_healthy, save_file_problem, check_result_dir, save_file_as_json, ReconStats, print_legend
from .request import send_request, get_html_title
from .honeypot import HoneypotAnalyzer
from models import scan_config
from sources import get_subdomain

##Module Package
from time import sleep
from concurrent.futures import ThreadPoolExecutor
import os
import tldextract
import socket
import requests

stats = ReconStats()

def validate_subdomain(sub, wildcard_baseline):
    config = scan_config.current
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


def check_subdomain(domain: str):
    config = scan_config.current
    healthy_ip = set()
    problem_ip = set()

    subdomain = []
    if os.path.isfile(domain):
        if not config.quiet:
            print("validate as file")
        with open(domain, "r")as f:
            subdomain = [line.strip() for line in f.read().splitlines() if line.strip()]
    elif "." in domain and not domain.endswith(".txt"):
        if not config.quiet:
            print(f"Search for subdomain for {domain}")
        subdomain = get_subdomain(domain, config.all_resource, config.source)
    else:
        print("[x] Invalid domain or file path!")
        exit(0)

    if not subdomain:
        print("[x] No subdomain found!")
        exit(0)

    if not config.quiet:
        print(print_legend())
        print(f"[+] Found {len(subdomain)} potential hosts, starting validation\n")

    wildcard_baseline = check_wildcard(get_domain_root(subdomain[0]))
    try:
        with ThreadPoolExecutor(max_workers=config.thread) as executor:
            futures = []
            for s in subdomain:
                futures.append(executor.submit(validate_subdomain, s, wildcard_baseline))

                if config.delay > 0:
                    sleep(config.delay)

        sub_list = []
        for future in futures:
            is_ok, ip, dict_sub = future.result()
            if ip != "No IP":
                if is_ok:
                    healthy_ip.add(ip)
                else:
                    problem_ip.add(ip)
            if dict_sub:
                sub_list.append(dict_sub)

        if config.save_file_plain:
            root = get_domain_root(subdomain[0])
            check_result_dir()
            save_file_healthy(root, healthy_ip)
            save_file_problem(root, problem_ip)
        if config.save_file_json:
            check_result_dir()
            root = get_domain_root(subdomain[0])
            save_file_as_json(root, sub_list)

        if not config.quiet:
            stats.summary()

    except KeyboardInterrupt:
        print("\n[!]Process stop by user...")
        exit(0)


def get_domain_root(full_domain: str):
    root = tldextract.extract(full_domain)
    return f"{root.domain}.{root.suffix}"

#=======================================================================================================
###UPDATE
#=======================================================================================================
def check_wildcard(domain: str):
    wild_sub = f"{os.urandom(2).hex()}.{domain}"
    baselines = {"http": None, "https": None}
    try:
        res = requests.get(f"http://{wild_sub}", timeout=5, allow_redirects=False)
        wild_status = res.status_code
        wild_size = len(res.content)
        wild_title = get_html_title(res)
        baselines["http"] = {"title": wild_title, "status": wild_status, "size": wild_size}
    except Exception as e:
        #print(f"[x] HTTP Wildcard check failed: {e}")
        ...

    try:
        res = requests.get(f"https://{wild_sub}", allow_redirects=False, timeout=5, verify=False)
        wild_status = res.status_code
        wild_size = len(res.content)
        wild_title = get_html_title(res)
        baselines["https"] = {"title": wild_title, "status": wild_status, "size": wild_size}
    except Exception as e:
        #print(f"[x] HTTPS Wildcard check failed: {e}")
        ...
    return baselines