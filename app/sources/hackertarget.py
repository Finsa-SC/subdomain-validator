from utils import get_logger

def fetch_hackertarget(domain: str):
    from core import send_request
    log = get_logger("hackertarget")
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = send_request(method="GET", url=url, timeout=5)

        if not response:
            log.error("Failed to fetch data from HackerTarget (Connection or Proxy Error).")
            return

        if "error" in response.text.lower() or response.status_code != 200:
            log.error(f"Error: {response.text}")
            return
        for line in response.text.strip().splitlines():
            sub = line.split(",")[0].lower().strip()
            if sub:
                yield sub
    except Exception as e:
        log.error(f"Unexpected error in hackertarget module: {e}")
