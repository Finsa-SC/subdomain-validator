import re

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

        if "status:" in query:
            match = re.search(r'status:(\d+|forbidden|redirect)', query)
            if match:
                target = match.group(1)
                h_status = result.get("http", {}).get("status")
                s_status = result.get("https", {}).get("status")

                forbidden = (401, 402, 403)
                redirect = (301, 302, 307, 308)
                if target == 'forbidden':
                    if h_status not in forbidden and s_status not in forbidden:
                        return False
                elif target == 'redirect':
                    if h_status not in redirect and s_status not in redirect:
                        return False
                else:
                    target_code = int(target)
                    if h_status != target_code and s_status != target_code:
                        return False

        if 'server:' in query:
            match = re.search(r'server:(\w+)', query)
            if match:
                target = match.group(1)
                server = result.get("http", {}).get("server", "").lower()
                if target not in server:
                    return False

        if 'honeypot:' in query:
            match = re.search(r'honeypot:(\w+)', query)
            if match:
                target = match.group(1)
                score = result.get("honeypot_score", 0)
                label = result.get("honeypot_label", "Unlikely").lower()
                if target == 'true':
                    if score < 0.5:
                        return False
                if target == 'false':
                    if score >= 0.5:
                        return False
                else:
                    if label != target:
                        return False

        if 'subdomain:' in query:
            match = re.search(r'subdomain:(\S+)', query)
            if match:
                target = match.group(1)
                if target not in result.get("subdomain", "").lower():
                    return False

        if 'ip:' in query:
            match = re.search(r'ip:([\d\.\*]+)', query)
            if match:
                pattern = match.group(1).replace(".", r"\.").replace("*", r"\*")
                ip = result.get("ip_address", "")
                if not re.match(pattern, ip):
                    return False

        if query.startswith("not "):
            return not self.matches(query[4:], result)

        return True