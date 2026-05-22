# ===================================================
### API KEY is needed for This request
# ===================================================

from utils import get_logger

def fetch_alienvault(domain: str):
    from core import send_request
    log = get_logger("alienvault")
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        res = send_request(method="GET", url=url, timeout=10)
        if not res:
            log.error("Failed to fetch data from Alien Vault (Connection or Proxy Error).")
            return

        if res.status_code != 200:
            return
        data = res.json()
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname")
            if hostname:
                sub = hostname.strip().lower()
                if sub and (sub.endswith(f".{domain}") or sub == domain):
                    yield sub
    except Exception as e:
        log.error(f"Unexpected error in Alien Vault module: {e}")