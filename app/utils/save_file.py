from models import CLOUDFLARE_IPS

import ipaddress
import os
import json
from pathlib import Path

def check_result_dir():
    Path("result").mkdir(parents=True, exist_ok=True)

def is_cloudflare(ip):
    if not ip and ip != "No IP":
        return False
    ip_obj = ipaddress.ip_address(ip)
    for network in CLOUDFLARE_IPS:
        if ip_obj in ipaddress.ip_network(network):
            return True
    return False

def save_file_healthy(domain: str, ip_sets: set[str]):
    check_result_dir()
    file_name = Path("result") / f"{domain}_healthy_ip.txt"
    with open(file_name, "w") as file:
        for ip in ip_sets:
            if not is_cloudflare(ip):
                file.write(f"{ip}\n")
    print(f"Success save healthy ip as {file_name}")

def save_file_problem(domain: str, ip_sets: set[str]):
    check_result_dir()
    file_name = Path("results") / f"{domain}_problem_ip.txt"
    with open(file_name, "w") as file:
        for ip in ip_sets:
            if not is_cloudflare(ip):
                file.write(f"{ip}\n")
    print(f"Success save problem ip as {file_name}")

def save_file_as_json(domain: str , all_result, scan_metadata):
    check_result_dir()
    file_name = Path("results") / f"{domain}.json"

    smart_structure = {
        "metadata": scan_metadata,
        "summary": {
            "total_found": len(all_result),
            "unique_active": 0,
            "honeypots": 0,
            "wildcard": 0
        },
        "findings": {
            "active_host": [],
            "honeypots": [],
            "groups": {}
        }
    }

    seen_fingerprint = {}
