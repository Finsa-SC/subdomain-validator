from models import HONEYPOT_TITLE, HONEYPOT_NAME, HONEYPOT_HASHES, HONEYPOT_SERVERS, OBSOLETE_VERSIONS
from utils import is_cloudflare

class HoneypotAnalyzer:
    def __init__(self, data, config):
        self.data = data
        self.http = data["http"]
        self.https = data["https"]
        self.config = config
        self.chance = 0
        self.findings = []

    def check_static(self):
        sub = self.data["subdomain"].lower()
        h_title = self.http["title"].lower()
        s_title = self.https["title"].lower()
        h_server = self.http["server"].lower()
        s_server = self.https["server"].lower()

        for pattern, weight in HONEYPOT_NAME.items():
            if pattern in sub:
                self.chance += weight
                self.findings.append("Unusual subdomain")

        for pattern, weight in HONEYPOT_TITLE:
            if pattern in [h_title, s_title]:
                self.chance += weight
                self.findings.append("Clickbait title")

        for pattern, weight in HONEYPOT_SERVERS.items():
            if h_server in pattern or s_server in pattern:
                self.chance += weight
                self.findings.append("Suspicious server signature")

        if any(v in h_server for v in OBSOLETE_VERSIONS) or any(v in s_server for v in OBSOLETE_VERSIONS):
            self.chance += 25
            self.findings.append(f"Server is leaking an obsolete/vulnerable version: '{h_server or s_server}'")

        if s_server != h_server and "Unknown" not in [h_server, s_server]:
            self.chance += 15
            self.findings.append("Different server")

        if is_cloudflare(self.data["ip_address"]) and "cloudflare" not in [h_server, s_server]:
            self.chance += 30
            self.findings.append("Cloudflare detected but server header is leaking backend info (High Anomaly)")



    def check_structural(self):


    def check_behavioral(self):
        ...

    def run_all(self):
        return self.chance, self.findings