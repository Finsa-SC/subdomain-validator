import re
import ipaddress
from models import PROXY_IPS

class FilterParser:
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

        if query.startswith("not "):
            return not self.matches(query[4:], result)

        if "status:" in query:
            match = re.search(r'status:([\w,]+)', query)
            if match:
                targets = match.group(1).split(",")
                h_status = result.get("http", {}).get("status")
                s_status = result.get("https", {}).get("status")

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
                    result.get("http", {}).get("server", "").lower() + " " +
                    result.get("https", {}).get("server", "").lower()
                ).lower()

                if not any(target in server for target in targets):
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
            if match:
                target = match.group(1)
                ip_str = result.get("ip_address", "")

                if target == 'proxy':
                    proxy = False
                    if ip_str and ip_str != "No IP":
                        try:
                            ip_obj = ipaddress.ip_address(ip_str)
                            for network in PROXY_IPS:
                                if ip_obj in ipaddress.ip_network(network):
                                    proxy = True
                                    break
                        except ValueError:
                            pass
                    if not proxy:
                        return False
                else:
                    pattern = target.replace(".", r"\.").replace("*", ".*")
                    if not re.fullmatch(pattern, ip_str):
                        return False


        return True