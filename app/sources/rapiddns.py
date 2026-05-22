import re
from utils import get_logger

def fetch_rapiddns(domain: str):
    from core import send_request

    log = get_logger("rapiddns")
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"

    try:
        res = send_request(method="GET", url=url, timeout=10)
        if not res:
            log.error("Failed to fetch data from RapidDNS (Connection or Proxy Error).")
            return

        if res.status_code != 200:
            return

        pattern = r'>([a-z0-9.-]+\.' + re.escape(domain) + r')<'
        matches = re.findall(pattern, res.text)
        for sub in matches:
            if sub:
                yield sub
    except Exception as e:
        log.error(f"Unexpected error in RapidDNS module: {e}")