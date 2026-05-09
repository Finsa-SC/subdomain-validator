import time
from typing import Any
from datetime import datetime
import tldextract
import os
import itertools

from models import get_config
from sources import get_subdomain
from utils import save_file_healthy, save_file_problem, save_file_as_json, print_legend
from concurrent.futures import ThreadPoolExecutor, as_completed, FIRST_COMPLETED, wait
from .validate import validate_subdomain, stats
from .request import send_request


def check_subdomain(domain: str):
    config = get_config()
    sub_list = []
    healthy_ip = set()
    problem_ip = set()

    if os.path.isfile(domain):
        if not config.quiet:
            print("validate as file")

        def _file_gen():
            with open(domain, "r") as file:
                for line in file:
                    s = line.strip()
                    if s and not s.startswith("#"):
                        yield s

        subdomain_iter = _file_gen()
    elif "." in domain and not domain.endswith(".txt"):
        if not config.quiet:
            print(f"Search for subdomain for {domain}")
        subdomain_iter = iter(get_subdomain(domain, config.all_resource, config.source))
    else:
        print("[x] Invalid domain or file path!")
        exit(0)

    first_sub = next(subdomain_iter, None)
    if not first_sub:
        print(f"[x] No subdomain found!!")
        exit(0)

    domain_root = get_domain_root(first_sub)
    wildcard_baseline = check_wildcard(domain_root)
    subdomain_iter = itertools.chain([first_sub], subdomain_iter)

    if not config.quiet:
        print(print_legend())

    try:
        with ThreadPoolExecutor(max_workers=config.thread) as executor:
            futures = {
                executor.submit(validate_subdomain, sub, wildcard_baseline): sub
                for sub in itertools.islice(subdomain_iter, config.thread * 4)
            }

            while futures:
                done, _ = wait(futures.keys(), return_when=FIRST_COMPLETED)

                for future in done:
                    try:
                        is_ok, ip, dict_sub = future.result()
                        if ip and ip != "No IP":
                            if is_ok:
                                healthy_ip.add(ip)
                            else:
                                problem_ip.add(ip)
                        if dict_sub:
                            sub_list.append(dict_sub)
                    except Exception as e:
                        print(f"[x] Error: {e}")

                    del futures[future]

                    next_sub = next(subdomain_iter, None)
                    if next_sub:
                        new_f = executor.submit(validate_subdomain, next_sub, wildcard_baseline)
                        futures[new_f] = next_sub

                        if config.delay:
                            time.sleep(config.delay)

        if config.save_file_plain:
            save_file_healthy(domain_root, healthy_ip)
            save_file_problem(domain_root, problem_ip)
        if config.save_file_json:
            metadata = create_metadata(domain_root)
            save_file_as_json(domain_root, sub_list, metadata)

        if not config.quiet:
            stats.summary()
            print(f"[+] Found {len(sub_list)} potential hosts, starting validation\n")

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
