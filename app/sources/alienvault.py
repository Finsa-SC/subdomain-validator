# ===================================================
### API KEY is needed for This request
# ===================================================

from utils import get_logger
import requests

def fetch_alienvault(domain: str):
    log = get_logger("alienvault")
    subdomains = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        res = requests.get(url, timeout=10)
        if res.status_code != 200:
            return subdomains
        data = res.json()
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname")
            if hostname:
                sub = hostname.strip().lower()
                if sub and (sub.endswith(f".{domain}") or sub == domain):
                    yield sub
    except requests.exceptions.Timeout:
        log.error("Request Timeout")
    except requests.exceptions.RequestException as e:
        log.error(f"{e}")