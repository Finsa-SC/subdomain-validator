from .stealth import StealthMode

from curl_cffi import requests
import html
import urllib3
import re
import hashlib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

stealth = StealthMode()

def send_request(proto ,sub, time_out):
    try:
        sub_url = f"{proto}://{sub}"
        stealth_header, browser_engine = stealth.get_payload()

        with requests.Session() as session:
            res = session.get(
                url=sub_url,
                timeout=time_out,
                headers=stealth_header,
                impersonate=browser_engine,
                allow_redirects=False,
                verify=False
            )

        body_hash = hashlib.md5(res.content).hexdigest() if res.content else "d41d8cd98f00b204e9800998ecf8427e"

        request_dict = {
            "title": get_html_title(res),
            "status": res.status_code,
            "server": res.headers.get('Server', 'Unknown'),
            "location": res.headers.get("Location", "-"),
            "latency": int(res.elapsed.total_seconds() * 1000),
            "length": len(res.content),
            "timestamp": res.headers.get('Date'),
            "header": res.headers,
            "body_hash": body_hash,
            "header_keys": list(res.headers.keys())
        }
        return request_dict
    except requests.errors.RequestsError as e:
        err_msg = str(e).upper()
        if "SSL" in err_msg or "CERTIFICATE" in err_msg:
            return {"status": "SSL_ERR"}
        return {"status": "CONN_ERR"}
    except Exception:
        return {"status": "CONN_ERR"}

def get_html_title(res):
    res.encoding = res.charset_encoding or "utf-8"
    try:
        title_search = re.search(r'<title>(.*?)</title>', res.text, re.IGNORECASE | re.DOTALL)
        if title_search:
            title = html.unescape(title_search.group(1).strip())
            return title.replace('\n', ' ').replace('\r', '')
        return "-"
    except:
        return "-"
