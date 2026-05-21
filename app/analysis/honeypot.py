import math


HONEYPOT_NAME = [
    "admin", "login", "portal", "dashboard",
    "setup", "db", "internal", "vpn", "staging",
    "dev", "test", "backup", "secret", "hidden",
    "shell", "cmd", "root", "secure",
]

HONEYPOT_TITLE = [
    "iis7",
    "iis windows server",
    "apache2 ubuntu default page",
    "apache2 debian default page",
    "test page for apache",
    "welcome to nginx",
    "it works!",
    "default web site page",
    "index of /",
    "directory listing",
]

HONEYPOT_HASHES = {
    "5f352330a108a73b75a1334c264284d3": "Glastopf default login page",
    "7215ee9c7d9dc229d2921a40e899ec5f": "Dionaea bare HTTP response",
    "cfcd208495d565ef66e7dff9f98764da": "Heralding default response",
    "b026324c6904b2a9cb4b88d6d61c81d1": "Conpot default ICS interface",
    "d751713988987e9331980363e24189ce": "Python SimpleHTTPServer directory listing",
}

HONEYPOT_HEADERS = [
    "x-honeypot",
    "x-honey",
    "x-deception",
    "x-trap",
    "x-canary",
]

HONEYPOT_SIZE_RANGE = [
    "tiny_trap",
    "login_trap",
    "cms_trap"
]


HONEYPOT_SERVERS = [
    "glastopf",
    "wordpot",
    "shockpot",
    "dionaea",
    "conpot",
    "heralding",
    "elasticpot",
    "hellpot",
    "basehttp",
    "twistedweb",
    "honeyd",
    "simplehttp",
    "scada",
]
OBSOLETE_VERSIONS = ["apache/2.2", "php/5.", "iis/7.0", "iis/6.0"]

SUSPICIOUS_HEADER_ORDERS = [
    ["server", "x-powered-by", "x-honeypot"],
    ["x-aspnet-version", "x-powered-by", "server", "x-honeypot"],
]

SIGNAL_WEIGHTS = {
    "hash_match": 0.95,
    "honeypot_header": 0.92,
    "server_sig_match": 0.82,
    "obsolete_version": 0.65,
    "identical_body_both_proto": 0.50,
    "header_order": 0.52,
    "clickbait_title": 0.48,
    "subdomain_name": 0.10,
    "missing_title": 0.14,
    "tls_ja3_suspicious": 0.35,
    "response_timing": 0.25,
    "fake_cookie": 0.40,
    "body_entropy": 0.30,
    "cdn_mismatch": 0.28,

}

SIGNAL_TIER = {
    "subdomain_name": "weak",
    "missing_title": "weak",
    "obsolete_version": "strong",
    "header_order": "strong",
    "clickbait_title": "strong",
    "identical_body_both_proto": "strong",
    "tls_ja3_suspicious": "strong",
    "response_timing": "strong",
    "fake_cookie": "strong",
    "body_entropy": "strong",
    "cdn_mismatch": "strong",
    "hash_match": "critical",
    "honeypot_header": "critical",
    "server_sig_match": "critical",
}

CONFIDENCE_LABELS = [
    (0.90, "Confirmed"),
    (0.75, "Likely"),
    (0.50, "Probable"),
    (0.25, "Possible"),
    (0.00, "Unlikely"),
]

KNOWN_PROXY_SERVERS = [
    "cloudflare",
    "cloudfront",
    "akamai",
    "fastly",
    "sucuri",
    "imperva",
    "varnish",
    "edgecast",
    "stackpath",
    "bunnycdn",
    "cdn77",
]

FAKE_COOKIE_PATTERNS = [
    "sessionid=1",
    "session=default",
    "auth=test",
    "token=debug",
    "jsessionid=0",
]

SUSPICIOUS_TLS_SIGNATURES = {
    # Honeypot framework identifiers
    "python": ["python-requests", "python/", "aiohttp"],
    "simple": ["simplehttpserver", "basehttpserver", "wsgiref"],
    # Bare/minimal stacks
    "minimal": ["tinyhttp", "microhttp"],
}

EMPTY_HASH = "d41d8cd98f00b204e9800998ecf8427e"

def noisy_or(probabilities: list[float]) -> float:
    if not probabilities:
        return 0.0
    complement = math.prod(1.0 - prob for prob in probabilities)
    return 1.0 - complement

def get_confidence_level(score: float) -> str:
    for treshold, label in CONFIDENCE_LABELS:
        if score >= treshold:
            return label
    return "Unlikely"

def _calculate_entropy(data: str) -> float:
    if not data:
        return 0.0

    from collections import Counter
    entropy = 0.0
    len_data = len(data)
    unique_chars = len(Counter(data))

    for count in Counter(data).values():
        prob = count / len_data
        entropy -= prob * math.log2(prob)

    max_entropy = math.log2(unique_chars) if unique_chars > 1 else 1.0
    normalized = entropy / max_entropy if max_entropy > 0 else 0.0

    return min(normalized, 1.0)

def _chek_http_framwork_leak(server_str: str) -> bool:
    if not server_str:
        return False

    server = server_str.lower()

    for framework, signature in SUSPICIOUS_TLS_SIGNATURES.items():
        for sig in signature:
            if sig.lower() in server:
                return True
    return False

def _check_fake_cookies(headers: dict) -> bool:
    if not headers:
        return False

    set_cookie = headers.get("set-cookie", "") or headers.get("Set-Cookie", "")
    if not set_cookie:
        return False

    set_cookie = set_cookie.lower()

    for fake_pattern in FAKE_COOKIE_PATTERNS:
        if fake_pattern.lower() in set_cookie:
            return True

    try:
        for cookie_part in set_cookie.split(";"):
            if '=' in cookie_part:
                name, value = cookie_part.split('=', 1)
                entropy = _calculate_entropy(value.strip())
                if entropy < 0.2 and len(value.strip()) > 5:
                    return True
    except:
        pass

    return False

class HoneypotAnalyzer:
    def __init__(self, data, config):
        self.data = data
        self.http = data["http"]
        self.https = data["https"]
        self.config = config
        self.signal: dict[str, float] = {}
        self.findings: list[str] = []

    def _add_signal(self, key: str, note: str) -> None:
        scoring = SIGNAL_WEIGHTS[key]
        if key not in self.signal or self.signal[key] < scoring:
            self.signal[key] = scoring
        if note not in self.findings:
            self.findings.append(note)

    def _is_reverse_proxy(self):
        h_server = self.http.get("server", "").lower()
        s_server = self.https.get("server", "").lower()
        combined = f"{h_server} {s_server}"
        return any(sig in combined for sig in KNOWN_PROXY_SERVERS)

    def _is_host_responsive(self):
        h_status = self.http.get("status")
        s_status = self.https.get("status")
        return h_status is not None or s_status is not None

    def _compute_score(self) -> float:
        if not self.signal:
            return 0.0

        tiers: dict[str, list[float]] = {"critical": [], "strong": [], "weak": []}
        for key, score in self.signal.items():
            tiers[SIGNAL_TIER[key]].append(score)

        tiers_scores = {t: noisy_or(ps) for t, ps in tiers.items() if ps}

        final = noisy_or(list(tiers_scores.values()))

        n_critical = len(tiers["critical"])
        if n_critical >= 2:
            final = max(final, 0.88)
        elif n_critical == 1:
            final = max(final, 0.70)

        if not self._is_host_responsive():
            final *= 0.3

        return round(min(final, 1.0), 4)

    def check_server(self):
        h_server = self.http.get("server", "").lower() or ""
        s_server = self.https.get("server", "").lower() or ""

        for sig in HONEYPOT_SERVERS:
            if sig in h_server or sig in s_server:
                self._add_signal(
                    "server_sig_match",
                    f"Server signature matches known honeypot software: '{sig}'")
                break

        for ver in OBSOLETE_VERSIONS:
            if ver in h_server or ver in s_server:
                self._add_signal(
                    "obsolete_version",
                    f"Deliberately exposed obsolete version: '{h_server or s_server}'")
                break

        if _chek_http_framwork_leak(h_server) or _chek_http_framwork_leak(s_server):
            self._add_signal(
                "tls_ja3_suspicious",
                f"Suspicious TLS/Server signature: likely honeypot framework")

    def check_response(self):
        h_hash = self.http.get("body_hash")
        s_hash = self.https.get("body_hash")

        for b_hash in (h_hash, s_hash):
            if b_hash and b_hash in HONEYPOT_HASHES:
                self._add_signal(
                    "hash_match",
                    f"Body hash matches known honeypot: '{HONEYPOT_HASHES[b_hash]}'")
                break
        h_keys = [k.lower() for k in self.http.get("header_keys", [])]
        s_keys = [k.lower() for k in self.https.get("header_keys", [])]
        all_headers = set(h_keys) | set(s_keys)

        for trap_header in HONEYPOT_HEADERS:
            if trap_header in all_headers:
                self._add_signal(
                    "honeypot_header",
                    f"Literal honeypot header found: '{trap_header}'")
                break

        for keys in [h_keys, s_keys]:
            if not keys: continue
            for trap_order in SUSPICIOUS_HEADER_ORDERS:
                if all(item in keys for item in trap_order):
                    indices = [keys.index(item) for item in trap_order]
                    if indices == sorted(indices):
                        self._add_signal(
                            "header_order",
                            "Suspicious HTTP header ordering detected")
                        break

        h_title = (self.http.get("title") or "").lower().strip()
        s_title = (self.https.get("title") or "").lower().strip()
        for title in HONEYPOT_TITLE:
            if title in h_title or title in s_title:
                self._add_signal(
                    "clickbait_title",
                    f"Default server page title detected: '{title}'")
                break

        h_headers = self.http.get("raw_header") or {}
        s_headers = self.https.get("raw_header") or {}
        if _check_fake_cookies(h_headers) or _check_fake_cookies(s_headers):
            self._add_signal(
                "fake_cookie",
                "Suspiciously predictable cookie values (low entropy)")

    def check_subdomain(self):
        if not self._is_host_responsive():
            return

        sub = self.data.get("subdomain", "").lower()
        for name in HONEYPOT_NAME:
            if name in sub:
                self._add_signal(
                    "subdomain_name",
                    f"High-value bait subdomain: '{name}'")
                break

    def check_behavioral(self):
        if not self._is_host_responsive():
            return

        h_hash = self.http.get("body_hash")
        s_hash = self.https.get("body_hash")
        h_size = self.http.get("size")

        h_status = self.http.get("status")
        s_status = self.https.get("status")

        h_200 = h_status == 200
        s_200 = s_status == 200

        # Identical body
        if h_200 and s_200 and h_hash and h_hash == s_hash and not self._is_reverse_proxy():
            self._add_signal(
                "identical_body_both_proto",
                "Identical body on HTTP and HTTPS (no redirect) — abnormal for real servers")

        # CDN mismatch detection
        h_server = self.http.get("server", "").lower()
        s_server = self.https.get("server", "").lower()

        h_is_cdn = any(cdn in h_server for cdn in KNOWN_PROXY_SERVERS)
        s_is_cdn = any(cdn in s_server for cdn in KNOWN_PROXY_SERVERS)

        if h_is_cdn != s_is_cdn:
            self._add_signal(
                "cdn_mismatch",
                "Inconsistent CDN/Proxy detection between HTTP and HTTPS")

        if h_200 and h_hash == EMPTY_HASH and h_size == 0:
            self._add_signal(
                "missing_title",
                "HTTP 200 with empty body — server returning nothing")

        # Body entropy deviation
        if h_hash and h_hash != EMPTY_HASH:
            if h_size and isinstance(h_size, int) and h_size < 500 and h_200:
                self._add_signal(
                    "body_entropy",
                    "Suspiciously small static response body (<500B)")

        h_title = self.http.get("title", "").strip().lower()
        s_title = self.https.get("title", "").strip().lower()

        # Empty 200 response
        if h_200 and not h_title:
            self._add_signal(
                "missing_title",
                "HTTP 200 but no page title — possible bare honeypot response")
        if s_200 and not s_title:
            self._add_signal(
                "missing_title",
                "HTTPS 200 but no page title — possible bare honeypot response")

        h_latency = self.http.get("latency")
        s_latency = self.https.get("latency")

        # Timing anomaly
        for latency in (h_latency, s_latency):
            if latency and isinstance(latency, int):
                if latency < 30 and h_200:
                    self._add_signal(
                        "response_timing",
                        f"Unnaturally fast response time: {latency}ms (likely honeypot)")
                elif latency > 15000:
                    self._add_signal(
                        "response_timing",
                        f"Suspiciously slow response time: {latency}ms (artificial delay)")

    def run_all(self):
        self.check_server()
        self.check_response()
        self.check_subdomain()
        self.check_behavioral()

        score = self._compute_score()
        label = get_confidence_level(score)
        return score, label, self.findings