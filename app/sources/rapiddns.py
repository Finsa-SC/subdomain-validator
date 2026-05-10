import re
import requests
from utils import get_logger

def fetch_rapiddns(domain: str):
    log = get_logger("rapiddns")
    subdomains = set()
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"

    try:
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0'}
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code != 200:
            return subdomains

        pattern = r'>([a-z0-9.-]+\.' + re.escape(domain) + r')<'
        matches = re.findall(pattern, res.text)
        for sub in matches:
            if sub:
                yield sub
    except requests.exceptions.Timeout:
        log.error("Request timeout")
    except requests.exceptions.RequestException as e:
        log.error(f"{e}")