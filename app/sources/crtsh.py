import ijson, io
from utils import get_logger

def fetch_crtsh(domain: str):
    from core import send_request
    log = get_logger("crtsh")
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        res = send_request(method="GET", url=url, timeout=15)
        if not res:
            log.error("Failed to fetch data from crt.sh (Connection or Proxy Error).")
            return

        if res.status_code == 200:
            f_stream = io.BytesIO(res.content)
            for entry in ijson.items(f_stream, "item"):
                name = entry['name_value'].lower()
                for n in name.split("\n"):
                    clean = n.replace("*.", "").strip()
                    if clean:
                        yield clean
    except Exception as e:
        log.error(f"Unexpected error in Crt sh module: {e}")