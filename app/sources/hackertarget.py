import requests
from utils import get_logger

def fetch_hackertarget(domain: str):
    log = get_logger("hackertarget")
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url=url, timeout=5)

        if "error" in response.text.lower() or response.status_code != 200:
            log.error(f"Error: {response.text}")
            return
        for line in response.text.strip().splitlines():
            sub = line.split(",")[0].lower().strip()
            if sub:
                yield sub
    except requests.exceptions.Timeout:
        log.error("Request Timeout")
    except requests.exceptions.RequestException as e:
        log.error(f"{e}")
