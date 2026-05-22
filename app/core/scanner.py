import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any
import tldextract
import os
from rich.console import Console

from models import get_config
from sources import get_subdomain
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait

from utils.writer import is_cached_valid, get_scanned_from_cache, clear_cache
from .validate import validate_subdomain
from .request import send_subdomain_request
from .state import app_state
from utils import get_logger, save_result_to_cache, load_result_from_cache
from datetime import datetime

log = get_logger("Scanner")
DEBUG = os.getenv("DEBUG", 'false') == 'true'

class SubdomainScanner:
    def __init__(self, domain: str, callback):
        self.domain = domain
        self.callback = callback
        self.config = get_config()
        self.domain_root = None
        self.subdomain_iter = None
        self.scanned_subs = set()

    def __enter__(self):
        log.info(f"Scanning started at: {datetime.now()} for {self.domain}")
    def __exit__(self, exc_type, exc_val, exc_tb):
        log.info(f"Scanner session ended at: {datetime.now()} for {self.domain}")
        if exc_type is KeyboardInterrupt:
            log.warning(f"Scan interupted by user for {self.domain}")
            app_state.stop()
            return True
        if exc_type:
            log.error(f"Scanner error: {exc_val}")
            app_state.stop()
            return True

    def _setup_file_iter(self):
        file_path = Path(self.config.domain_list)

        if not file_path.is_file():
            log.error(f"Mode -dL Active: No such file: {file_path}")
            return False

        try:
            with open(file_path, 'r') as f:
                first_line = f.readline().strip()
            self.domain_root = get_domain_root(first_line) if '.' in first_line else first_line
        except:
            self.domain_root = "file_scan_target"

        def _file_gen():
            with open(file_path, 'r') as file:
                for line in file:
                    s = line.strip()
                    if s and not s.startswith("#"):
                        yield s
        self.subdomain_iter = iter(_file_gen())
        return True

    def _setup_api_iter(self):
        self.domain_root = get_domain_root(self.domain) if '.' in self.domain else self.domain
        try:
            sub_list = get_subdomain(
                domain=self.domain,
                use_all=self.config.all_resource,
                selected_source=self.config.source,
                fresh=self.config.fresh
            )
            if not sub_list:
                log.error(f"Mode -d Active: get_subdomain found nothing for {self.domain_root}")
                return True
            self.subdomain_iter = iter(sub_list)
            return True
        except Exception as e:
            log.error(f"Failed to get subdomain from API/Sources: {e}")
            return False

    def _load_from_cache(self):
        if not is_cached_valid(self.domain_root, self.config.fresh):
            return False

        all_cached = load_result_from_cache(self.domain_root)
        if not all_cached:
            if DEBUG:
                log.debug("Cache file exists but empty, forcing fresh scan")
            return False

        log.info(f"Scanning started at: {datetime.now()} for {self.domain_root} (from cache)")
        if DEBUG:
            log.debug(f"Loading {len(all_cached)} results from cache")

        for result in  all_cached.values():
            self.callback(result)

        log.info(f"Scanner session ended at: {datetime.now()} for {self.domain_root}")
        return True

    def _setup_scanned_subs(self):
        if self.config.fresh:
            clear_cache(domain=self.domain_root)
            self.scanned_subs = set()
        else:
            self.scanned_subs = get_scanned_from_cache(self.domain_root)
            if self.scanned_subs and DEBUG:
                log.info(f"Resume: Found {len(self.scanned_subs)} previously scanned subdomains")

    def _process_result(self, future_result):
        from analysis import HoneypotAnalyzer

        is_ok, ip, dict_sub = future_result.result()
        if not dict_sub:
            return

        subdomain = dict_sub.get("subdomain", "")
        if subdomain in self.scanned_subs:
            if DEBUG:
                log.debug(f"Skipping already scanned: {subdomain}")
            return

        dict_sub["is_live"] = is_ok
        dict_sub['server'] = (
            dict_sub.get("http", {}).get("server") or
            dict_sub.get("https", {}).get("server") or
            'Unknown'
        )

        analyzer = HoneypotAnalyzer(dict_sub, self.config)
        score, label, findings = analyzer.run_all()
        dict_sub["is_honeypot"] = score > 0.5
        dict_sub["honeypot_score"] = score
        dict_sub["honeypot_label"] = label
        dict_sub["honeypot_findings"] = findings

        self.callback(dict_sub)
        save_result_to_cache(self.domain_root, subdomain, dict_sub)
        self.scanned_subs.add(subdomain)

    def _next_unseen_sub(self):
        while True:
            sub = next(self.subdomain_iter, None)
            if sub is None:
                return None
            if sub not in self.scanned_subs:
                return sub
            if DEBUG:
                log.debug(f"Resume Skip: {sub}")

    def _run_scan(self):
        wildcard_baseline = check_wildcard(self.domain_root)
        console = Console()
        console.print()

        with ThreadPoolExecutor(max_workers=self.config.thread) as ex:
            app_state.executor = ex
            futures = {}

            slots_to_fill = self.config.thread * 4
            while slots_to_fill > 0:
                sub = self._next_unseen_sub()
                if not sub:
                    break
                futures[ex.submit(validate_subdomain, sub, wildcard_baseline)] = sub
                slots_to_fill -= 1

            while futures:
                if not app_state.is_running:
                    break

                done, _ = wait(futures.keys(), return_when=FIRST_COMPLETED)

                for future in done:
                    if not app_state.is_running:
                        break
                    try:
                        self._process_result(future)
                    except Exception as e:
                        log.error(f"Error processing future result: {e}")

                    del futures[future]

                    if app_state.is_running:
                        next_sub = self._next_unseen_sub()
                        if next_sub:
                            futures[ex.submit(validate_subdomain, next_sub, wildcard_baseline)] = next_sub

                if self.config.delay:
                    time.sleep(self.config.delay)
        console.print()

    def run(self):
        if self.config.domain_list and self.config.domain_list.strip():
            if not self._setup_file_iter():
                return
        else:
            self.domain_root = get_domain_root(self.domain) if '.' in self.domain else self.domain
            if not self._setup_api_iter():
                return

        if self._load_from_cache():
            return

        self._setup_scanned_subs()

        with self:
            try:
                self._run_scan()
            except KeyboardInterrupt:
                log.warning("Scan interrupted - partial results saved to cache")

def check_subdomain_tui(domain: str, callback):
    scanner = SubdomainScanner(domain, callback)
    scanner.run()

def check_wildcard(domain: str):
    config = get_config()
    wild_sub = f"{os.urandom(2).hex()}.{domain}"
    baselines = {"http": None, "https": None}

    with ThreadPoolExecutor(max_workers=2) as ex:
        http_future = ex.submit(send_subdomain_request, "http", wild_sub, config.timeout, None, False, True)
        https_future = ex.submit(send_subdomain_request, "https", wild_sub, config.timeout, None, False, True)

        res_http, err_http = http_future.result()
        res_https, err_https = https_future.result()

    from .validate import parse_response
    h = parse_response(res_http, None)
    s = parse_response(res_https, None)

    if h.get("status") not in ["CONN_ERR", "SSL_ERR"]:
        baselines["http"] = {
            "title": h.get("title"),
            "status": h.get("status"),
            "size": h.get("size")
        }

    if s.get("status") not in ["CONN_ERR", "SSL_ERR"]:
        baselines["https"] = {
            "title": s.get("title"),
            "status": s.get("status"),
            "size": s.get("size")
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