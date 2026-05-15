import time

from .stealth import StealthMode
from models import DNS_PROVIDERS, get_config
from utils import get_logger

from curl_cffi import requests
import html
import urllib3
import re
import dns.resolver

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

stealth = StealthMode()
log = get_logger("request")

def send_request(
        proto: str ,
        sub: str,
        timeout: float,
        custom_dns: str = None,
        allow_redirects: bool = False
) -> requests.Response | None:

    config = get_config()
    try:
        stealth_header, browser_engine = stealth.get_payload()

        if custom_dns:
            dns_ip = DNS_PROVIDERS.get(custom_dns.lower(), custom_dns)
            ip = resolve_ip(sub, dns_ip, 'A') or resolve_ip(sub, dns_ip, 'AAAA')
            if ip:
                formatted_ip = f"[{ip}]" if ":" in ip else ip
                url = f"{proto}://{formatted_ip}"
                stealth_header["Host"] = sub
            else:
                return None
        else:
            url = f"{proto}://{sub}"

        res = _do_request(
            url=url,
            base_timeout=timeout,
            headers=stealth_header,
            impersonate=browser_engine,
            allow_redirects=allow_redirects,
            retries=config.retry
        )

        return res
    except Exception as e:
        log.debug(f"send_request failed [{proto}] {sub}: {type(e).__name__} - {e}")
        return None

def send_request_with_error(
        proto: str,
        sub: str,
        timeout: float,
        custom_dns: str = None,
        allow_redirects: bool = False,
    ) -> tuple[requests.Response | None, str | None]:
    config = get_config()

    try:
        stealth_header, browser_engine = stealth.get_payload()

        if custom_dns:
            dns_ip = DNS_PROVIDERS.get(custom_dns.lower(), custom_dns)
            ip = resolve_ip(sub, dns_ip, "A") or resolve_ip(sub, dns_ip, "AAAA")
            if ip:
                formatted_ip = f"[{ip}]" if ":" in ip else ip
                url = f"{proto}://{formatted_ip}"
                stealth_header["Host"] = sub
            else:
                return None, "DNS_ERR"
        else:
            url = f"{proto}://{sub}"
        res = _do_request(
            url=url,
            base_timeout=timeout,
            headers=stealth_header,
            impersonate=browser_engine,
            allow_redirects=allow_redirects,
            retries=config.retry
        )
        return res, None

    except requests.errors.RequestsError as e:
        err = str(e).upper()
        if "SSL" in err or "CERTIFICATE" in err:
            return None, "SSL_ERR"
        return None, "CONN_ERR"
    except Exception as e:
        log.error(f"send_request_with_error [{proto}] {sub}: {type(e).__name__} - {e}")
        return None, "CONN_ERR"


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

def _do_request(
    url,
    headers,
    impersonate,
    allow_redirects,
    base_timeout,
    retries,
):
    last_error = None

    for retry_count in range(retries + 1):
        try:
            timeout = base_timeout + retry_count

            return requests.get(
                url=url,
                timeout=timeout,
                headers=headers,
                impersonate=impersonate,
                allow_redirects=allow_redirects,
                verify=False,
            )
        except requests.errors.RequestsError as e:
            last_error = e
            err = str(e).upper()
            transient = [
                "TIMEDOUT",
                "CONNECTION RESET",
                "FAILED TO CONNECT",
                "EOF",
                "NETWORK",
                "TLSV1 ALERT INTERNAL ERROR",
                "RECV FAILURE",
                "EMPTY REPLY",
            ]
            if 'SSL' in err or 'CERTIFICATE' in err:
                raise e
            if any(x in err for x in transient):
                if retry_count < retries:
                    log.debug(
                        f"Retry [{retry_count+1}/{retries}] "
                        f"timeout={timeout}s -> {url}"
                    )
                    time.sleep(0.5 * (retry_count + 1))
                    continue
            raise e
    raise last_error


