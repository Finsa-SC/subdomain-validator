import hashlib, ipaddress, time, subprocess, platform, shutil, json, threading, os
from pathlib import Path
from dotenv import load_dotenv

from models import PROXY_IPS
from .logger import get_logger

load_dotenv()
DEBUG = os.getenv("debug", "false") == 'true'
log = get_logger("writer")
def check_results_dir():
    Path("results").mkdir(parents=True, exist_ok=True)

def is_proxy(ip: str):
    if not ip or ip == "No IP":
        return False
    ip_obj = ipaddress.ip_address(ip)
    for network in PROXY_IPS:
        if ip_obj in ipaddress.ip_network(network):
            return True
    return False

def save_file_healthy(domain: str, ip_sets: set[str]):
    check_results_dir()
    file_name = Path("results") / f"{domain}_healthy_ip.txt"
    with open(file_name, "w") as file:
        for ip in ip_sets:
            if not is_proxy(ip):
                file.write(f"{ip}\n")
    log.info(f"Saved Healthy: {file_name}")

def save_file_problem(domain: str, ip_sets: set[str]):
    check_results_dir()
    file_name = Path("results") / f"{domain}_problem_ip.txt"
    with open(file_name, "w") as file:
        for ip in ip_sets:
            if not is_proxy(ip):
                file.write(f"{ip}\n")
    log.info(f"Saved Problem {file_name}")

def save_file_as_json(domain: str , all_results, scan_metadata):
    check_results_dir()
    file_name = Path("results") / f"{domain}.json"

    smart_structure = {
        "metadata": scan_metadata,
        "summary": {
            "total_found": len(all_results),
            "unique_active": 0,
            "honeypots": 0,
            "wildcard_ignored": 0,
            "others": 0
        },
        "findings": {
            "unique_active": {},
            "honeypots": [],
            "wildcard_sample": [],
            "others": {}
        }
    }

    for item in all_results:
        h_raw = item.get("http", {})
        s_raw = item.get("https", {})

        fp_raw = f"{h_raw.get('status')}-{s_raw.get('status')}-{h_raw.get('server')}-{h_raw.get('body_hash')}"
        fp_hash = hashlib.md5(fp_raw.encode()).hexdigest()

        item = clean_item(item)
        h = item.get("http", {})
        s = item.get("https", {})

        ##Skip junk data
        if not h.get("status") and not s.get("status"):
            continue

        ##Skip cloudflare
        if is_proxy(item.get("ip_address")):
            continue

        ##Get wildcard
        if item.get("wildcard"):
            smart_structure["summary"]["wildcard_ignored"] += 1
            if len(smart_structure["findings"]["wildcard_sample"]) <= 1:
                smart_structure["findings"]["wildcard_sample"].append(item)
            continue

        ##Get honeypot
        if item.get("honeypot_score", 0) > 0.7:
            smart_structure["summary"]["honeypots"] += 1
            smart_structure["findings"]["honeypots"].append(item)
            continue


        is_active = h.get("status") in (200, 301, 302) or s.get("status") in (200, 301, 302)

        if is_active:
            target = smart_structure["findings"]["unique_active"]
            if fp_hash not in target:
                target[fp_hash] = {
                    "total": 0,
                    "sample": item
                }
            target[fp_hash]["total"] += 1
        else:
            target = smart_structure["findings"]["others"]
            if fp_hash not in target:
                target[fp_hash] = {
                    "total": 0,
                    "sample": item
                }
            target[fp_hash]["total"] += 1

    smart_structure["summary"]["unique_active"] = len(smart_structure["findings"]["unique_active"])
    smart_structure["summary"]["others"] = len(smart_structure["findings"]["others"])

    with open(file_name, 'w') as f:
        json.dump(
            smart_structure,
            f,
            indent=4,
            default=lambda o: dict(o) if hasattr(o, "items") else str(o)
        )
    log.info(f"Saved JSON {file_name}")

def clean_item(item):
    keep_fields = {"status", "title", "server", "size", "redir", "latency", "tech", "body_hash"}
    for proto in ("http", "https"):
        if proto in item:
            item[proto] = {k: v for k, v in item[proto].items() if k in keep_fields}
    item.pop("signing", None)
    item.pop("timestamp", None)
    item.pop("honeypot_findings", None)
    return item

def copy_to_clipboard(text: str):
    system = platform.system()
    try:
        if system == 'Windows':
            subprocess.run(["clip"], input=text.encode(), check=True)
        elif system == 'Darwin':
            subprocess.run(["pbcopy"], input=text.encode(), check=True)
        elif system == 'Linux':
            if shutil.which("xclip"):
                subprocess.run(['xclip', '-selection', 'clipboard'], input=text.encode(), check=True)
            elif shutil.which("xsel"):
                subprocess.run(['xsel', "--clipboard", "--input"], input=text.encode(), check=True)
    except Exception as e:
        log.error(f"Clipboard copy failed: {e}")

def schedule_cleanup(file_path: str, delay: float | int = 300.0):
    def cleanup():
        time.sleep(delay)
        try:
            path_obj = Path(file_path)
            if path_obj.exists():
                path_obj.unlink()

                if DEBUG:
                    log.debug(f"Cleaned up temp file: {file_path}")
        except Exception as e:
                log.error(f"Failed to clean up temp file {file_path}: {e}")

    thread = threading.Thread(target=cleanup, daemon=True)
    thread.start()

def get_cache_file(domain: str) -> Path:
    cache_file = Path("results") / "cache"
    cache_file.mkdir(parents=True, exist_ok=True)
    return cache_file / f"{domain}_result.json"

def load_result_from_cache(domain: str) -> dict:
    cache_file = get_cache_file(domain)
    if cache_file.exists():
        try:
            with open(cache_file, 'r') as file:
                return json.load(file)
        except Exception as e:
            log.error(f"Failed to read cache file: {e}")
    return {}

def save_result_to_cache(domain: str, subdomain: str, results: dict):
    cache_file = get_cache_file(domain)
    try:
        result = load_result_from_cache(domain)
        result[subdomain] = results
        with open(cache_file, 'w') as file:
            json.dump(result, file, indent=2, default=lambda o: dict(o) if hasattr(o, "items") else str(o))
    except Exception as e:
        log.error(f"Failed to save result to cache: {e}")

def update_result_in_cache(domain: str, subdomain: str, update: dict):
    cache_file = get_cache_file(domain)
    try:
        results = load_result_from_cache(domain)
        if subdomain in results:
            results[subdomain].update(update)
            with open(cache_file, 'w') as file:
                json.dump(results, file, indent=2, default=lambda o: dict(o) if hasattr(o, 'items') else str(o))
    except Exception as e:
        log.error(f"Failed to update cache: {e}")

def get_cache_age_hour(domain: str) -> float | None:
    cache_file = get_cache_file(domain)
    if not cache_file.exists():
        return None

    file_mtime = cache_file.stat().st_mtime
    age_second = time.time() - file_mtime
    age_hour = age_second / 3600
    return age_hour

def is_cached_valid(domain: str, fresh: bool) -> bool:
    if fresh:
        log.info(f"Fresh scan requested, ignoring cache for {domain}")
        return False

    age = get_cache_age_hour(domain)
    if age is None:
        log.error(f"No cached found for {domain}")
        return False

    if age <= 2.0:
        if DEBUG:
            log.debug(f"Cache valid: {age:.1f} hours old, using cached results")
        return True
    else:
        if DEBUG:
            log.debug(f"Cache expired: {age:.1f} hours old (> 2h), performing fresh scan")
        return False

def get_scanned_from_cache(domain: str) -> set[str]:
    cached_data = load_result_from_cache(domain)
    return set(cached_data.keys())

def clear_cache(domain: str):
    cache_file = get_cache_file(domain)
    try:
        if cache_file.exists():
            cache_file.unlink()
        if DEBUG:
            log.debug(f"Cache cleared for {domain}")
    except Exception as e:
        log.error(f"Failed to clear cache: {e}")