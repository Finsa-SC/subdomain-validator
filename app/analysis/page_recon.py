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

    for cat, pattern in categories.items():
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
        "js_credentials": {
            "js_scanned": [],
            "js_skipped": [],
            "findings": [],
            "total_found": 0
        },
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
    out["js_credentials"] = _scan_js_credentials(urls, timeout)

    if DEBUG:
        log.debug(
            f"{result.get('subdomain')}: page_recon → "
            f"{len(urls)} urls, "
            f"login={out['login']['detected']}, "
            f"register={out['register']['detected']}, "
            f"admin={out['admin']['detected']}"
        )

    return out

# ─── JS Credential Scanner ────────────────────────────────────────────────────
JS_SKIP_PATTERNS = [
    # vendor/library — ga perlu di-scan
    r'jquery', r'bootstrap', r'lodash', r'moment', r'axios',
    r'react', r'vue', r'angular', r'webpack', r'chunk',
    r'polyfill', r'modernizr', r'leaflet', r'chart\.js',
    r'fontawesome', r'gtm', r'analytics', r'recaptcha',
    r'cloudflare', r'cdn\.', r'cdnjs', r'unpkg\.com',
    r'jsdelivr', r'googleapis', r'gstatic',
]

CREDENTIAL_PATTERNS = [
    # API Keys
    {"label": "Generic API Key",      "pattern": r'(?:api[_\-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']'},
    {"label": "Generic Secret",       "pattern": r'(?:secret|secret[_\-]?key)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']'},
    {"label": "Generic Token",        "pattern": r'(?:token|access[_\-]?token|auth[_\-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']'},
    {"label": "Generic Password",     "pattern": r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']'},

    # Cloud
    {"label": "AWS Access Key",       "pattern": r'AKIA[0-9A-Z]{16}'},
    {"label": "AWS Secret Key",       "pattern": r'(?:aws[_\-]?secret|secret[_\-]?access[_\-]?key)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']'},
    {"label": "Google API Key",       "pattern": r'AIza[0-9A-Za-z\-_]{35}'},
    {"label": "Firebase URL",         "pattern": r'https://[a-z0-9\-]+\.firebaseio\.com'},

    # Auth
    {"label": "JWT Token",            "pattern": r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'},
    {"label": "Bearer Token",         "pattern": r'[Bb]earer\s+([A-Za-z0-9\-_\.]{20,})'},
    {"label": "Basic Auth",           "pattern": r'[Bb]asic\s+([A-Za-z0-9+/]{20,}={0,2})'},

    # Services
    {"label": "Stripe Key",           "pattern": r'(?:pk|sk)_(?:live|test)_[0-9a-zA-Z]{24,}'},
    {"label": "Twilio SID",           "pattern": r'AC[a-zA-Z0-9]{32}'},
    {"label": "SendGrid Key",         "pattern": r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'},
    {"label": "Mailgun Key",          "pattern": r'key-[0-9a-zA-Z]{32}'},
    {"label": "Slack Token",          "pattern": r'xox[baprs]-[0-9A-Za-z\-]{10,}'},
    {"label": "GitHub Token",         "pattern": r'gh[pousr]_[A-Za-z0-9]{36,}'},
    {"label": "Private Key Header",   "pattern": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'},

    # DB connection strings
    {"label": "DB Connection String", "pattern": r'(?:mongodb|mysql|postgres|postgresql|redis|mssql)://[^\s"\'<>]+'},
]

def _is_important_js(url: str) -> bool:
    url = url.lower()
    for pattern in JS_SKIP_PATTERNS:
        if re.search(pattern, url):
            return False
    return True

def _fetch_js(url: str, timeout: float) -> str | None:
    from core import send_request
    try:
        res = send_request(
            url=url,
            method="GET",
            timeout=timeout,
            allow_redirects=True
        )
        if res and res.status_code == 200 and res.content:
            res.encoding = res.charset_encoding or "utf-8"
            return res.text
    except:
        pass
    return None

def _scan_js_for_credentials(js_content: str, source_url: str) -> list[dict]:
    findings = []
    seen = set()

    for cred in CREDENTIAL_PATTERNS:
        for match in re.finditer(cred["pattern"], js_content, re.IGNORECASE):
            value = match.group(1) if match.lastindex else match.group(0)
            value = value.strip()

            key = f"{cred['label']}: {value[:40]}"
            if key in seen:
                continue
            seen.add(key)

            masked = value[:6] + "..." + value[-4:] if len(value) > 12 else value[:4] + "..."

            findings.append({
                "label": cred['label'],
                "masked": masked,
                "source_url": source_url,
                "line_hint": _get_line_hint(js_content, match.start())
            })
    return findings

def _get_line_hint(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1

def _scan_js_credentials(urls: list[dict], timeout: float) -> dict:
    out = {
        "js_scanned": [],
        "findings": [],
        "total_found": 0
    }

    js_urls = [
        u for u in urls
        if u.get("internal") and u.get("url", "").split("?")[0].endswith(".js")
    ]

    for entry in js_urls:
        url = entry.get('url', '')
        if _is_important_js(url):
            out['js_scanned'].append(url)

    for js_url in out['js_scanned'][:10]:
        content = _fetch_js(js_url, timeout)
        if not content:
            continue
        hits = _scan_js_for_credentials(content, js_url)
        out['findings'].extend(hits)

    out['total_found'] = len(out['findings'])

    if DEBUG:
        log.debug(
            f"js_credential: scanned={len(out['js_scanned'])}, "
            f"skipped={len(out['js_skipped'])}, "
            f"findings={out['total_found']}"
        )
    return out