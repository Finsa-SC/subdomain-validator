from urllib.parse import urlparse, urljoin
import mmh3, hashlib, base64, re, os
from dotenv import load_dotenv

from .logger import get_logger

log = get_logger("favicon")
load_dotenv()
DEBUG = os.getenv("DEBUG", "false") == "true"

KNOWN_FAVICON_HASHES: dict[int, str] = {
    # CMS
    -1255853263: "WordPress",
    116323821: "Joomla",
    -1506805757: "Drupal",
    1085041361: "Ghost CMS",
    -1251682462: "Magento",

    # Web servers / panels
    -335242539: "Nginx default page",
    1771008400: "Apache default page",
    -421993668: "cPanel",
    -1427222059: "Plesk",
    116836539: "Webmin",
    -1534575556: "phpMyAdmin",

    # Network devices
    -1160087947: "Cisco IOS",
    1028723239: "Fortinet FortiGate",
    -1411578193: "Palo Alto Networks",
    -1322284664: "MikroTik",
    -885210565: "pfSense",
    630641635: "Juniper",

    # Monitoring / DevOps
    -880068513: "Grafana",
    1765625046: "Kibana",
    -1135714337: "Prometheus",
    -1399555081: "Zabbix",
    -949425829: "Nagios",
    -1424337732: "Portainer",
    1455260951: "Rancher",

    # CI/CD & Dev tools
    -1983527995: "Jenkins",
    1484180222: "GitLab",
    -1885111544: "Gitea",
    1768835265: "Nexus Repository",
    -1113428726: "SonarQube",

    # Honeypots
    -1474703247: "Glastopf (Honeypot)",
    -728578634: "Cowrie (Honeypot)",
}


def _pick_base_url(result) -> str:
    subdomain = result.get("subdomain", "")
    if result.get("https", {}).get("status") in (200, 301, 302, 307, 308):
        return f"https://{subdomain}"
    return f"http://{subdomain}"

def _fetch_content(url: str, timeout: float = 5.0):
    from core import send_request
    parsed = urlparse(url)

    res = send_request(
        method="GET",
        url=url,
        timeout=timeout,
        allow_redirects=True
    )
    if res:
        ctype = res.headers.get("Content-Type", "")
        if res.status_code == 200 and res.content:
            return res.content, ctype
        return None, ctype
    return None, ""

def _find_favicon_in_html(html: str, base_url: str) -> str | None:
    p1 = r'<link[^>]+rel=["\'](?:shortcut\s+)?icon["\'][^>]*href=["\']([^"\']+)["\']'
    p2 = r'<link[^>]+href=["\']([^"\']+)["\'][^>]*rel=["\'](?:shortcut\s+)?icon["\']'

    match = re.findall(p1, html, re.I) + re.findall(p2, html, re.I)
    if not match:
        return None
    return urljoin(base_url, match[0].strip())

def _mm3_hash(data: bytes) -> int:
    return mmh3.hash(base64.encodebytes(data))

def fetch_favicon(result: dict, timeout: float = 5.0) -> dict:
    subdomain = result.get("subdomain", "")
    base_url = _pick_base_url(result)

    out = {
        "found": False, "url": None,
        "hash_mmh3": None, "hash_md5": None,
        "size": 0, "matched": None,
        "shodan_query": None, "error": None,
    }

    favicon_url = urljoin(base_url, "/favicon.ico")
    data, ctype = _fetch_content(favicon_url, timeout)

    is_invalid = not data or (data and b"<html" in data[:500].lower())

    if is_invalid:
        if DEBUG:
            log.debug(f"{subdomain}: /favicon.ico Empty, trying parse HTML...")
        html_bytes, html_type = _fetch_content(base_url, timeout)

        if not html_bytes:
            return out

        if not html_bytes or "html" not in (html_type or "").lower():
            return out

        html_str = html_bytes.decode("utf-8", errors="ignore")
        found_url = _find_favicon_in_html(html_str, base_url)
        if found_url:
            data, _ = _fetch_content(found_url, timeout)
            if data and (len(data) < 100 or data[:4] == b"<html"):
                data = None
            if data:
                favicon_url = found_url

    if not data:
        out["error"] = "Favicon not found (tried /favicon.ico and HTML parse)"
        return out

    mmh3_hash = _mm3_hash(data)
    md5_hash = hashlib.md5(data).hexdigest()
    match = KNOWN_FAVICON_HASHES.get(mmh3_hash)

    out.update({
        "found":        True,
        "url":          favicon_url,
        "hash_mmh3":    mmh3_hash,
        "hash_md5":     md5_hash,
        "size":         len(data),
        "matched":      match,
        "shodan_query": f"http.favicon.hash:{mmh3_hash}",
    })

    if DEBUG:
        log.info(f"{subdomain}: favicon mmh3={mmh3_hash} matched={match or 'unknown'}")
    return out