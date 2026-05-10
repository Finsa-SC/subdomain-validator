import time
from typing import Any
from datetime import datetime
import tldextract
import os
import itertools
from rich.console import Console

from models import get_config
from sources import get_subdomain
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait
from .validate import validate_subdomain
from .request import send_request

def check_subdomain_tui(domain: str, callback):
    config = get_config()

    if os.path.isfile(domain):
        def _file_gen():
            with open(domain, "r") as file:
                for line in file:
                    s = line.strip()
                    if s and not s.startswith("#"):
                        yield s
        subdomain_iter = _file_gen()
    elif "." in domain and not domain.endswith(".txt"):
        subdomain_iter = iter(get_subdomain(domain, config.all_resource, config.source))
    else:
        return

    first_sub = next(subdomain_iter, None)
    if not first_sub:
        return

    domain_root = get_domain_root(first_sub)
    wildcard_baseline = check_wildcard(domain_root)
    subdomain_iter = itertools.chain([first_sub], subdomain_iter)

    counting = CountTime()
    counting.start()

    console = Console()
    console.print()

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

                        if dict_sub:
                            dict_sub["is_live"] = is_ok

                            dict_sub["server"] = (
                                dict_sub.get("https", {}).get("server") or
                                dict_sub.get("http", {}).get("server") or
                                "Unknown"
                            )

                            from analysis import HoneypotAnalyzer

                            analyzer = HoneypotAnalyzer(dict_sub, config)
                            score, label, findings = analyzer.run_all()
                            dict_sub["is_honeypot"] = score > 0.5
                            dict_sub["honeypot_score"] = score
                            dict_sub["honeypot_label"] = label
                            dict_sub["honeypot_findings"] = findings

                        callback(dict_sub)
                    except Exception:
                        pass

                    del futures[future]

                    next_sub = next(subdomain_iter, None)
                    if next_sub:
                        new_f = executor.submit(validate_subdomain, next_sub, wildcard_baseline)
                        futures[new_f] = next_sub

                    if config.delay:
                        time.sleep(config.delay)

        counting.end()
        console.print()

    except KeyboardInterrupt:
        pass

def check_wildcard(domain: str):
    config = get_config()
    wild_sub = f"{os.urandom(2).hex()}.{domain}"
    baselines = {"http": None, "https": None}

    with ThreadPoolExecutor(max_workers=2) as ex:
        http_future = ex.submit(send_request, "http", wild_sub, config.timeout)
        https_future = ex.submit(send_request, "https", wild_sub, config.timeout)

        res_http = http_future.result()
        res_https = https_future.result()

    if res_http.get("status") not in ["CONN_ERR", "SSL_ERR"]:
        baselines["http"] = {
            "title": res_http.get("title"),
            "status": res_http.get("status"),
            "size": res_http.get("size")
        }

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

class CountTime:
    def __init__(self):
        self.start_time = None
        self.end_time = None

    def start(self):
        self.start_time = datetime.now()

    def end(self):
        self.end_time = datetime.now()

    def get_elapsed(self):
        if self.start_time is None:
            return 0
        end = self.end_time if self.end_time else datetime.now()
        return (end - self.start_time).total_seconds()

    @property
    def total(self):
        return (self.end_time - self.start_time).total_seconds()