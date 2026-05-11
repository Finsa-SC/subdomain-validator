from models import CLOUDFLARE_IPS
from .logger import get_logger
import hashlib
import ipaddress
import json
from pathlib import Path

log = get_logger("writer")
def check_results_dir():
    Path("results").mkdir(parents=True, exist_ok=True)

def is_cloudflare(ip):
    if not ip or ip == "No IP":
        return False
    ip_obj = ipaddress.ip_address(ip)
    for network in CLOUDFLARE_IPS:
        if ip_obj in ipaddress.ip_network(network):
            return True
    return False

def save_file_healthy(domain: str, ip_sets: set[str]):
    check_results_dir()
    file_name = Path("results") / f"{domain}_healthy_ip.txt"
    with open(file_name, "w") as file:
        for ip in ip_sets:
            if not is_cloudflare(ip):
                file.write(f"{ip}\n")
    log.error(f"Saved Healthy: {file_name}")

def save_file_problem(domain: str, ip_sets: set[str]):
    check_results_dir()
    file_name = Path("results") / f"{domain}_problem_ip.txt"
    with open(file_name, "w") as file:
        for ip in ip_sets:
            if not is_cloudflare(ip):
                file.write(f"{ip}\n")
    log.error(f"Saved Problem {file_name}")

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
        if is_cloudflare(item.get("ip_address")):
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
    log.error(f"Saved JSON {file_name}")

def clean_item(item):
    keep_fields = {"status", "title", "server", "size", "redir"}
    for proto in ("http", "https"):
        if proto in item:
            item[proto] = {k: v for k, v in item[proto].items() if k in keep_fields}
    item.pop("signing", None)
    item.pop("timestamp", None)
    return item