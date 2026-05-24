import re, os
from dotenv import load_dotenv

from utils import get_logger

load_dotenv()
log = get_logger("Page Recon")
DEBUG = os.getenv("DEBUG", "false") == "true"

URL_PATTERNS = [
    r'href=["\']([^"\'#][^"\']*)["\']',
    r'src=["\']([^"\'#][^"\']*)["\']',
    r'action=["\']([^"\'#][^"\']*)["\']',
    r'(?:fetch|axios\.get|axios\.post|http\.get)\(["\']([^"\']+)["\']',
    r'url:\s*["\']([^"\']+)["\']',
    r'(?:endpoint|api_url|base_url)\s*=\s*["\']([^"\']+)["\']',
]

LOGIN_SIGNALS = [
    r'<input[^>]+type=["\']password["\']',
    r'(?:id|name|class)=["\'](?:login|signin|sign-in|log-in)["\']',
    r'action=["\'][^"\']*(?:login|signin|authenticate|auth)["\']',
    r'<form[^>]+(?:login|signin)',
    r'(?:forgot.?password|remember.?me)',
    r'<button[^>]*>(?:login|sign\s*in|log\s*in)</button>',
    r'placeholder=["\'](?:password|username|email address)["\']',
]

REGISTER_SIGNALS = [
    r'(?:id|name|class)=["\'](?:register|signup|sign-up|create.?account)["\']',
    r'action=["\'][^"\']*(?:register|signup|create.?account)["\']',
    r'<form[^>]+(?:register|signup)',
    r'(?:confirm.?password|repeat.?password|retype.?password)',
    r'<button[^>]*>(?:register|sign\s*up|create\s*account)</button>',
    r'placeholder=["\'](?:confirm password|repeat password)["\']',
]

ADMIN_SIGNALS = [
    r'(?:id|name|class)=["\'](?:admin|dashboard|control.?panel)["\']',
    r'<title>[^<]*(?:admin|dashboard|control panel|management)[^<]*</title>',
    r'href=["\'][^"\']*(?:/admin|/dashboard|/cp|/panel|/manage)["\']',
    r'(?:admin|administrator)\s+(?:panel|portal|console|area)',
]

INTERESTING_PATHS = [
    r'/api/', r'/v1/', r'/v2/', r'/v3/',
    r'/admin', r'/dashboard', r'/panel',
    r'/login', r'/signin', r'/logout',
    r'/register', r'/signup',
    r'/upload', r'/download', r'/file',
    r'/backup', r'/config', r'/setup',
    r'/user', r'/account', r'/profile',
    r'/search', r'/query',
    r'/debug', r'/test', r'/dev',
    r'\.php', r'\.asp', r'\.aspx', r'\.jsp',
    r'\.env', r'\.git', r'\.sql', r'\.bak',
]

def _fetch_body(result: dict, timeout: float) -> str | None:
    from core import send_request

    subdomain = result.get("subdomain", "")
    https_status = result.get("https", {}).get("status")

    url = f"https://{subdomain}" if https_status in (200, 301, 302, 307, 308) else f"http://{subdomain}"
    res = send_request(
        url=url,
        method="GET",
        timeout=timeout,
        allow_redirects=True
    )

    if res and res.status_code == 200 and res.content:
        res.encoding = res.charset_encoding or "utf-8"
        return res.text, url
    return None, None

def _extract_urls(body: str, base_url: str) -> list[dict]:
    from urllib.parse import urljoin, urlparse

    base_parsed = urlparse(base_url)
    base_domain = base_parsed.netloc

    found = {}

    for pattern in URL_PATTERNS:
        for match in re.finditer(pattern, body, re.IGNORECASE):
            raw = match.group(1).strip()
            if not raw or raw.startswith("data:") or raw.startswith("javascript:"):
                continue

            try:
                full_url = urljoin(base_url, raw)
                parsed = urlparse(full_url)

                if parsed.scheme not in ("http", "https"):
                    continue

                path = parsed.path.lower()
                is_internal = parsed.netloc == base_domain or not parsed.netloc

                category = 'external'
                if is_internal:
                    category = _categories_path(path)

                if full_url not in found:
                    found[full_url] = {
                        "url": full_url,
                        "path": parsed.path,
                        "category": category,
                        "internal": is_internal
                    }
            except:
                continue
    return list(found.values())

def _categories_path(path: str) -> str:
    path = path.lower()
    categories = {
        "api": [r"/api/", r"/v\d+/", r"/graphql", r"/rest/"],
        "auth": [r"/login", r"/signin", r"/logout", r"/auth", r"/oauth"],
        "register": [r"/register", r"/signup", r"/create.?account"],
        "admin": [r"/admin", r"/dashboard", r"/panel", r"/manage", r"/cp/"],
        "file": [r"/upload", r"/download", r"/file", r"\.php$", r"\.asp", r"\.jsp"],
        "sensitive": [r"\.env", r"\.git", r"\.sql", r"\.bak", r"/config", r"/backup", r"/debug"],
    }
    for cat, pattern in categories:
        for p in pattern:
            if re.search(p, path):
                return cat
    return "page"

def _detect_login(body: str, urls: list[dict]) -> dict:
    signals_found = []
    matched_paths = []

    for sig in LOGIN_SIGNALS:
        if re.search(sig, body, re.IGNORECASE):
            signals_found.append(sig)

    for entry in urls:
        path = entry.get("path", "").lower()
        if entry.get("category") == "auth" or re.search(f'/login|/signin|/auth', path):
            matched_paths.append(entry['url'])

    return {
        "detected": len(signals_found) > 0 or len(matched_paths) > 0,
        "signal_count": len(signals_found),
        "paths": list(set(matched_paths)),
    }

def _detect_register(body: str, urls: list[dict]) -> dict:
    signals_found = []
    matched_paths = []

    for sig in REGISTER_SIGNALS:
        if re.search(sig, body, re.IGNORECASE):
            signals_found.append(sig)

    for entry in urls:
        path = entry.get("path", "").lower()
        if entry.get("category") == "register" or re.search(f'/register|/signup', path):
            matched_paths.append(entry['url'])

    return {
        "detected": len(signals_found) > 0 or len(matched_paths) > 0,
        "signal_count": len(signals_found),
        "paths": list(set(matched_paths)),
    }

def _detect_admin(body: str, urls: list[dict]) -> dict:
    signals_found = []
    matched_paths = []

    for sig in ADMIN_SIGNALS:
        if re.search(sig, body, re.IGNORECASE):
            signals_found.append(sig)

    for entry in urls:
        if entry.get("category") == "admin":
            matched_paths.append(entry['url'])

    return {
        "detected": len(signals_found) > 0 or len(matched_paths) > 0,
        "signal_count": len(signals_found),
        "paths": list(set(matched_paths)),
    }

def _filter_interesting(urls: list[dict]) -> list[dict]:
    interesting = []
    for entry in urls:
        if not entry.get("internal"):
            continue
        path = entry.get("path", "").lower()
        for pattern in INTERESTING_PATHS:
            if re.search(pattern, path):
                interesting.append(entry)
                break
    return interesting

def run_page_recon(result: dict, timeout: float) -> dict:
    out = {
        "urls": [],
        "interesting": [],
        "login": {"detected": False, "paths": []},
        "register": {"detected": False, "paths": []},
        "admin": {"detected": False, "paths": []},
        "body_fetched": False,
        "total_urls": 0,
    }

    body, base_url = _fetch_body(result, timeout)
    if not body:
        return out

    out["body_fetched"] = True

    urls = _extract_urls(body, base_url)
    out["urls"] = urls
    out["total_urls"] = len(urls)
    out["interesting"] = _filter_interesting(urls)
    out["login"] = _detect_login(body, urls)
    out["register"] = _detect_register(body, urls)
    out["admin"] = _detect_admin(body, urls)

    if DEBUG:
        log.debug(
            f"{result.get('subdomain')}: page_recon → "
            f"{len(urls)} urls, "
            f"login={out['login']['detected']}, "
            f"register={out['register']['detected']}, "
            f"admin={out['admin']['detected']}"
        )

    return out