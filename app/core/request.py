from .stealth import StealthMode
from models import DNS_PROVIDERS
from utils import get_logger

from curl_cffi import requests
import html
import urllib3
import re
import hashlib
import dns.resolver

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

stealth = StealthMode()
log = get_logger("request")

def send_request(proto: str ,sub: str, time_out: float, custom_dns: str = None) -> dict:
    try:
        stealth_header, browser_engine = stealth.get_payload()

        if custom_dns:
            dns_ip = DNS_PROVIDERS.get(custom_dns.lower(), custom_dns)
            ip = resolve_ip(sub, dns_ip, 'A') or resolve_ip(sub, dns_ip, 'AAAA')
            if ip:
                formated_ip = f"[{ip}]" if ":" in ip else ip
                sub_url = f"{proto}://{formated_ip}"
                stealth_header["Host"] = sub
            else:
                return {"status": "DNS Error!!"}
        else:
            sub_url = f"{proto}://{sub}"

        req_kwargs = {
            "url":sub_url,
            "timeout": time_out,
            "headers": stealth_header,
            "impersonate": browser_engine,
            "allow_redirects": False,
            "verify": False
        }

        res = requests.get(**req_kwargs)

        body_hash = hashlib.md5(res.content).hexdigest() if res.content else "d41d8cd98f00b204e9800998ecf8427e"

        request_dict = {
            "title": get_html_title(res),
            "status": res.status_code,
            "server": res.headers.get('Server', 'Unknown'),
            "location": res.headers.get("Location", "-"),
            "latency": int(res.elapsed.total_seconds() * 1000),
            "size": len(res.content),
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
    except Exception as e:
        log.error(f"[DEBUG] Error detail for {sub}: {type(e).__name__} - {e}")
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

def resolve_ip(sub: str, custom_dns: str, record_type: str) -> str | None:
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [custom_dns]
        resolver.lifetime = 2.0
        resolver.timeout = 2.0

        answer = resolver.resolve(sub, record_type)
        return str(answer[0])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except Exception:
        return None