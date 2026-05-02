from models import (HONEYPOT_TITLE, HONEYPOT_NAME, HONEYPOT_HASHES, HONEYPOT_SERVERS, OBSOLETE_VERSIONS,
    SUSPICIOUS_HEADER_ORDERS, SIGNAL_TIER, SIGNAL_WEIGHTS, CONFIDENCE_LABELS, HONEYPOT_HEADERS)
from utils import is_cloudflare

import math


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

    def _is_cloudflare_host(self):
        h_server = self.http.get("server", "").lower()
        s_server = self.https.get("server", "").lower()
        return "cloudflare" in h_server or "cloudflare" in s_server

    def _is_host_responsive(self):
        h_status = self.http.get("status")
        s_status = self.https.get("status")
        return h_status in [200, 403] or s_status in [200, 403]

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
                self._add_signal("server_sig_match",
                                 f"Server signature matches known honeypot software: '{sig}'")
                break

        for ver in OBSOLETE_VERSIONS:
            if ver in h_server or ver in s_server:
                self._add_signal("obsolete_version",
                                 f"Deliberately exposed obsolete version: '{h_server or s_server}'")
                break

        ip_addr = self.data.get("ip_address")
        if ip_addr and ip_addr != "No IP":
            try:
                if is_cloudflare(self.data.get("ip_address", "")) and not self._is_cloudflare_host():
                    self._add_signal("cloudflare_leak",
                                     "Cloudflare IP but real backend exposed in server header")
            except:
                pass

    def check_response(self):
        h_hash = self.http.get("body_hash")
        s_hash = self.https.get("body_hash")

        for b_hash in (h_hash, s_hash):
            if b_hash and b_hash in HONEYPOT_HASHES:
                self._add_signal("hash_match",
                                 f"Body hash matches known honeypot: '{HONEYPOT_HASHES[b_hash]}'")
                break
        h_keys = [k.lower() for k in self.http.get("header_keys", [])]
        s_keys = [k.lower() for k in self.https.get("header_keys", [])]
        all_headers = set(h_keys) | set(s_keys)

        for trap_header in HONEYPOT_HEADERS:
            if trap_header in all_headers:
                self._add_signal("honeypot_header",
                                 f"Literal honeypot header found: '{trap_header}'")
                break

        for keys in [h_keys, s_keys]:
            if not keys: continue
            for trap_order in SUSPICIOUS_HEADER_ORDERS:
                if all(item in keys for item in trap_order):
                    indices = [keys.index(item) for item in trap_order]
                    if indices == sorted(indices):
                        self._add_signal("header_order",
                                         "Suspicious HTTP header ordering detected")
                        break

        h_title = (self.http.get("title") or "").lower().strip()
        s_title = (self.https.get("title") or "").lower().strip()
        for title in HONEYPOT_TITLE:
            if title in h_title or title in s_title:
                self._add_signal("clickbait_title",
                                 f"Default server page title detected: '{title}'")
                break


    def check_subdomain(self):
        if not self._is_host_responsive():
            return

        sub = self.data.get("subdomain", "").lower()
        for name in HONEYPOT_NAME:
            if name in sub:
                self._add_signal("subdomain_name",
                                 f"High-value bait subdomain: '{name}'")
                break

    def check_behavioral(self):
        if not self._is_host_responsive():
            return

        h_hash = self.http.get("body_hash")
        s_hash = self.https.get("body_hash")
        h_size = self.http.get("size")

        h_200 = self.http.get("status") == 200
        s_200 = self.https.get("status") == 200
        if h_200 and s_200 and h_hash and h_hash == s_hash and not self._is_cloudflare_host():
            self._add_signal("identical_body_both_proto",
                             "Identical body on HTTP and HTTPS (no redirect) — abnormal for real servers")

        EMPTY_HASH = "d41d8cd98f00b204e9800998ecf8427e"
        if h_200 and h_hash == EMPTY_HASH and h_size == 0:
            self._add_signal("missing_title",
                             "HTTP 200 with empty body — server returning nothing")

        h_title = self.http.get("title", "").strip().lower()
        s_title = self.https.get("title", "").strip().lower()
        if h_200 and not h_title:
            self._add_signal("missing_title",
                             "HTTP 200 but no page title — possible bare honeypot response")
        if s_200 and not s_title:
            self._add_signal("missing_title",
                             "HTTPS 200 but no page title — possible bare honeypot response")

    def run_all(self):
        self.check_server()
        self.check_response()
        self.check_subdomain()
        self.check_behavioral()

        score = self._compute_score()
        label = get_confidence_level(score)
        return score, label, self.findings