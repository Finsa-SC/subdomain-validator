import re
import ipaddress
from distutils.command.install import sys_key

from models import PROXY_IPS

class FilterParser:
    def __init__(self):
        self.http = {}
        self.https = {}
    def parse(self, query, results):
        if not query.strip():
            return results

        filtered = []

        for result in results:
            if self.matches(query, result):
                filtered.append(result)

        return filtered

    def matches(self, query: str, result):
        query = query.lower()
        self.http = result.get("http", {})
        self.https = result.get("https", {})

        if query.startswith("not "):
            return not self.matches(query[4:], result)

        if "status:" in query:
            match = re.search(r'status:([\w,]+)', query)
            if match:
                targets = match.group(1).split(",")
                h_status = self.http.get("status")
                s_status = self.https.get("status")

                forbidden = (401, 402, 403)
                redirect = (301, 302, 307, 308)

                matched = False
                for target in targets:
                    target = target.strip()
                    if target == 'forbidden':
                        if h_status in forbidden or s_status in forbidden:
                            matched = True
                    elif target == 'redirect':
                        if h_status in redirect or s_status in redirect:
                            matched = True
                    else:
                        try:
                            target_code = int(target)
                            if h_status == target_code or s_status == target_code:
                                matched = True
                        except ValueError:
                            pass
                if not matched:
                    return False

        if 'server:' in query:
            match = re.search(r'server:([\w+,-]+)', query)
            if match:
                targets = [x.strip() for x in match.group(1).split(",")]
                server = (
                    self.http.get("server", "").lower() + " " +
                    self.https.get("server", "").lower()
                ).lower()

                if not any(target in server for target in targets):
                    return False

        if 'tech:' in query:
            match = re.search(r'tech:([\w\s,-]+)', query)
            if match:
                targets = [x.strip() for x in match.group(1).split(",")]

                h_tech = str(self.http.get("tech", ""))
                s_tech = str(self.https.get("tech", ""))
                h_keys = str(self.http.get("header_keys", ""))
                s_keys = str(self.https.get("header_keys", ""))

                tech_data = " ".join([
                    h_tech,
                    s_tech,
                    h_keys,
                    s_keys
                ]).lower()

                if not any(target in tech_data for target in targets):
                    return False

        if 'title:' in query:
            match = re.search(r'title:([\w\s,-]+)', query)
            if match:
                targets = [x.strip() for x in match.group(1).split(",")]

                title = (
                    self.http.get("title", "-").lower() + " " +
                    self.https.get("title", "-").lower()
                )

                if not any(target in title for target in targets):
                    return False

        if 'wildcard:' in query:
            match = re.search(f'wildcard:(true|false)', query)
            if match:
                target = match.group(1)
                wildcard = result.get("wildcard", False)
                if target == 'true' and not wildcard:
                    return False
                if target == 'false' and wildcard:
                    return False


        if 'honeypot:' in query:
            match = re.search(r'honeypot:([\w+,]+)', query)
            if match:
                targets = [x.strip() for x in match.group(1).split(",")]
                score = result.get("honeypot_score", 0)
                label = result.get("honeypot_label", "Unlikely").lower()
                matched = False
                for target in targets:
                    if target == 'true':
                        if score >= 0.5:
                            matched = True
                    elif target == 'false':
                        if score < 0.5:
                            matched = True
                    elif label == target:
                            matched = True

                if not matched:
                    return False

        if 'subdomain:' in query:
            match = re.search(r'subdomain:([\w.*,-]+)', query)
            if match:
                targets = [x.strip() for x in match.group(1).split(",")]
                subdomain = result.get("subdomain", "")
                matched = False

                for target in targets:
                    pattern = (
                        target
                        .replace(".", r"\.")
                        .replace("*", ".*")
                    )
                    if re.search(pattern, subdomain):
                        matched = True
                        break
                if not matched:
                    return False

        if 'ip:' in query:
            match = re.search(r'ip:([\d.*,\w]+)', query)
            matched = False

            if match:
                targets = [x.strip() for x in match.group(1).split(",")]
                ip_str = result.get("ip_address", "")

                for target in targets:
                    if target == 'proxy':
                        proxy = False
                        if ip_str and ip_str != "No IP":
                            try:
                                ip_obj = ipaddress.ip_address(ip_str)
                                for network in PROXY_IPS:
                                    if ip_obj in ipaddress.ip_network(network):
                                        proxy = True
                                        matched = True
                                        break
                            except ValueError:
                                pass
                        if not proxy:
                            return False
                    else:
                        pattern = target.replace(".", r"\.").replace("*", ".*")
                        if re.fullmatch(pattern, ip_str):
                            matched = True
                if not matched:
                    return False

        if 'size:' in query:
            match = re.search(r'size:([\d,-]+)', query)
            if match:
                targets = [x.strip() for x in match.group(1).split(",")]
                h_size = self.http.get("size", 0)
                s_size = self.https.get("size", 0)

                matched = False

                for target in targets:
                    if "-" in target:
                        try:
                            min_size, max_size = map(int, target.split("-"))
                            if (
                                min_size <= h_size <= max_size or
                                min_size <= s_size <= max_size
                            ):
                                matched = True

                        except ValueError:
                            pass
                    else:
                        try:
                            exact = int(target)
                            if h_size == exact == s_size:
                                matched = True
                        except ValueError:
                            pass

                if not matched:
                    return False

        if 'latency:' in query:
            match = re.search(f'latency:([\d,-]+)', query)
            if match:
                targets = [x.strip() for x in match.group(1).split(",")]
                h_lat = self.http.get("latency") or 0
                s_lat = self.https.get("latency") or 0
                matched = False
                for target in targets:
                    if "-" in target:
                        try:
                            min_lat, max_lat = map(int, target.split("-"))
                            if (
                                min_lat <= h_lat <= max_lat or
                                min_lat <= s_lat <= max_lat
                            ):
                                matched = True
                        except ValueError:
                            pass
                    else:
                        try:
                            exact = int(target)

                            if h_lat == exact == s_lat:
                                matched = True
                        except ValueError:
                            pass
                if not matched:
                    return False

        return True