from typing import Any

from models import get_config
from sources import get_subdomain
from utils import save_file_healthy, save_file_problem, save_file_as_json, print_legend
from concurrent.futures import ThreadPoolExecutor
from .validate import validate_subdomain, stats
from .request import send_request

from datetime import datetime
import time
import tldextract
import os

def check_subdomain(domain: str):
    config = get_config()
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

                if config.delay:
                    time.sleep(0.1)

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
            save_file_healthy(root, healthy_ip)
            save_file_problem(root, problem_ip)
        if config.save_file_json:
            root = get_domain_root(subdomain[0])
            metadata = create_metadata(root)
            save_file_as_json(root, sub_list, metadata)

        if not config.quiet:
            stats.summary()

    except KeyboardInterrupt:
        print("\n[!]Process stop by user...")
        exit(0)

def check_wildcard(domain: str):
    config = get_config()
    wild_sub = f"{os.urandom(2).hex()}.{domain}"
    baselines = {"http": None, "https": None}

    res_http = send_request(proto="http", sub=wild_sub, time_out=config.timeout)
    if res_http.get("status") not in ["CONN_ERR", "SSL_ERR"]:
        baselines["http"] = {
            "title": res_http.get("title"),
            "status": res_http.get("status"),
            "size": res_http.get("size")
        }

    res_https = send_request(proto="https", sub=wild_sub, time_out=config.timeout)
    if res_https.get("status") not in ["CONN_ERR", "SSL_ERR"]:
        baselines["https"] = {
            "title": res_https.get("title"),
            "status": res_https.get("status"),
            "size": res_https.get("size")
        }
    return baselines

def get_domain_root(full_domain: str):
    root = tldextract.extract(full_domain)
    return f"{root.domain}.{root.suffix}"

def create_metadata(domain: str) -> dict[str, Any]:
    config = get_config()
    metadata = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "domain": domain,
        "thread_used": config.thread,
    }
    return metadata