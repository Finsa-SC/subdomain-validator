import requests
import ijson
from utils import get_logger
def fetch_crtsh(domain: str):
    log = get_logger("crtsh")
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            for entry in ijson.items(res.raw, "item"):
                name = entry['name_value'].lower()
                for n in name.split("\n"):
                    clean = n.replace("*.", "").strip()
                    if clean:
                        yield clean
    except requests.exceptions.Timeout:
        log.error("Request Timeout")
    except requests.exceptions.RequestException as e:
        log.error(f"{e}")