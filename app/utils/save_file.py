from models import CLOUDFLARE_IPS

import ipaddress
import os
import json

def check_result_dir():
    if not os.path.exists("results"):
        os.makedirs("results")

def is_cloudflare(ip):
    if not ip and ip != "No IP":
        return False
    ip_obj = ipaddress.ip_address(ip)
    for network in CLOUDFLARE_IPS:
        if ip_obj in ipaddress.ip_network(network):
            return True
    return False

def save_file_healthy(domain: str, ip_sets: set[str]):
    file_name = f"results/{domain}_healthy_ip.txt"
    with open(file_name, "w") as file:
        for ip in ip_sets:
            if not is_cloudflare(ip):
                file.write(f"{ip}\n")
    print(f"Success save healthy ip as {file_name}")

def save_file_problem(domain: str, ip_sets: set[str]):
    file_name = f"results/{domain}_problem_ip.txt"
    with open(file_name, "w") as file:
        for ip in ip_sets:
            if not is_cloudflare(ip):
                file.write(f"{ip}\n")
    print(f"Success save problem ip as {file_name}")

def save_file_as_json(domain: str ,dict_sub):
    file_name = f"results/{domain}.json"
    with open(file_name, "w")as file:
        json.dump(dict_sub, file, indent=4)
    print(f"Success save JSON result as {file_name}")
