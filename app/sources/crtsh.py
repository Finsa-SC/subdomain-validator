import ijson
from utils import get_logger

def fetch_crtsh(domain: str):
    from core import send_request
    log = get_logger("crtsh")
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        res = send_request(method="GET", url=url, timeout=10)
        if not res:
            log.error("Failed to fetch data from crt.sh (Connection or Proxy Error).")
            return

        if res.status_code == 200:
            for entry in ijson.items(res.raw, "item"):
                name = entry['name_value'].lower()
                for n in name.split("\n"):
                    clean = n.replace("*.", "").strip()
                    if clean:
                        yield clean
    except Exception as e:
        log.error(f"Unexpected error in hackertarget module: {e}")