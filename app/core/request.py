import time, os, re, urllib3, html
from dotenv import load_dotenv
from .stealth import StealthMode
from models import DNS_PROVIDERS, get_config
from utils import get_logger
from curl_cffi import requests
import dns.resolver
from .state import app_state

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

stealth = StealthMode()
log = get_logger("request")
load_dotenv()

PROXY_URL = os.getenv("PROXY_URL", "").strip().lower()

if not PROXY_URL or PROXY_URL == 'none':
    PROXY_URL = None

debug_mode = os.getenv('DEBUG', '').lower().strip()
DEBUG = debug_mode == 'true'

def _do_request(
    url: str,
    method: str,
    headers: dict,
    impersonate: str,
    allow_redirects: bool,
    base_timeout: float,
    retries: int,
    **kwargs
) -> requests.Response | None:
    last_error = None
    proxies = None

    for retry_count in range(retries + 1):
        if not app_state.is_running:
            return None
        try:
            timeout = base_timeout + retry_count
            if PROXY_URL:
                proxies = {
                    "http": PROXY_URL,
                    "https": PROXY_URL
                }

            return requests.request(
                method=method.upper(),
                url=url,
                timeout=timeout,
                headers=headers,
                impersonate=impersonate,
                allow_redirects=allow_redirects,
                verify=False,
                proxies=proxies,
                **kwargs
            )
        except requests.errors.RequestsError as e:
            last_error = e
            err = str(e).upper()

            if DEBUG:
                log.debug(f"RAW ERROR => {err}")

            transient = [
                "TIMED OUT",
                "TIMEOUT",
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
                    if DEBUG:
                        log.debug(
                            f"Retry [{retry_count+1}/{retries}] "
                            f"timeout={timeout}s -> {url}"
                        )

                    wait_time = 0.5 * (retry_count + 1)
                    stop_at = time.time() + wait_time
                    while time.time() < stop_at:
                        if not app_state.is_running:
                            return None
                        time.sleep(0.1)
                    continue
            raise e
        except Exception as e:
            if DEBUG:
                log.debug(
                    f"UNKNOWN ERROR => {type(e).__name__}: {e}"
                )
            raise e
    raise last_error

def send_request(
        url: str,
        method: str,
        timeout: float,
        allow_redirects: bool = False,
        **kwargs
) -> requests.Response | None:

    config = get_config()
    try:
        stealth_header, browser_engine = stealth.get_payload()

        user_header = kwargs.pop("headers", {})
        stealth_header.update(user_header)

        res = _do_request(
            url=url,
            method=method,
            headers=stealth_header,
            base_timeout=timeout,
            impersonate=browser_engine,
            allow_redirects=allow_redirects,
            retries=config.retry,
            **kwargs
        )
        return res

    except Exception as e:
        str_err = str(e).upper()
        if "DNSERROR" in str_err or "COULD NOT RESOLVE HOST":
            if DEBUG:
                log.debug(f"Send request failed (DNS) for {url}: {type(e).__name__} - {e}")
            return None
        log.error(f"Send request failed for {url}: {type(e).__name__} - {e}")
        return None

def send_subdomain_request(
        proto: str,
        sub: str,
        timeout: float,
        custom_dns: str = None,
        allow_redirects: bool = False,
        return_error_token: bool = False
    ) -> tuple[requests.Response | None, str | None] | None:
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
                return (None, "DNS_ERR") if return_error_token else None
        else:
            url = f"{proto}://{sub}"

        res = _do_request(
            url=url,
            method="GET",
            base_timeout=timeout,
            headers=stealth_header,
            impersonate=browser_engine,
            allow_redirects=allow_redirects,
            retries=config.retry
        )
        return (res, None) if return_error_token else res

    except requests.errors.RequestsError as e:
        if return_error_token:
            err = str(e).upper()
            if "SSL" in err or "CERTIFICATE" in err:
                return None, "SSL_ERR"
            return None, "CONN_ERR"
        return None
    except Exception as e:
        log.error(f"send_request_request [{proto}] {sub}: {type(e).__name__} - {e}")
        return (None, "CONN_ERR") if return_error_token else None


def get_html_title(res: requests.Response):
    if not res:
        return '-'

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
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
        return None