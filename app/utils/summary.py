from dataclasses import dataclass
import threading

add_lock = threading.Lock()

@dataclass()
class ReconStats:
    ok: int = 0
    redirect: int = 0
    forbidden: int = 0
    rate_limit: int = 0
    ssl_error: int = 0
    conn_error: int = 0
    server_error: int = 0
    dead: int = 0
    other: int = 0
    not_found: int = 0

    def log(self, http_status, https_status):
        code = [http_status, https_status]
        forbidden = (301, 302, 307, 308)
        unauthor = (401, 402, 403)

        with add_lock:
            if any(c == 200 for c in code if isinstance(c, int)):
                self.ok += 1
            elif any(c in forbidden for c in code if isinstance(c, int)):
                self.redirect += 1
            elif any(c in unauthor for c in code if isinstance(c, int)):
                self.forbidden += 1
            elif any(c == 429 for c in code if isinstance(c, int)):
                self.rate_limit += 1
            elif "SSL_ERR" in code:
                self.ssl_error += 1
            elif any(500 <= c <= 504 for c in code if isinstance(c, int)):
                self.server_error += 1
            elif "CONN_ERR" in code:
                self.dead += 1
            elif any(c == 404 for c in code if isinstance(c, int)):
                self.not_found += 1
            else:
                self.other += 1

    def summary(self, time_scan):
        host_up = (self.ok +
                   self.forbidden +
                   self.server_error +
                   self.redirect +
                   self.not_found +
                   self.other
        )

        total_scan = host_up + self.ssl_error + self.dead

        status = {
            "Host Up": host_up,
            "Live": self.ok,
            "Redirect": self.redirect,
            "Rate Limit": self.rate_limit,
            "Forbidden": self.forbidden,
            "SSL Error": self.ssl_error,
            "Server Error": self.server_error,
            "Not Found": self.not_found,
            "No Response": self.dead,
            "Other Response": self.other
        }

        print("\n\nSummary:")

        for title, total in status.items():
            if total > 0:
                print(f"{title: <15}: {total}")

        print(f"\n\nTotal Host Scanned: {total_scan}, scanned in {time_scan} seconds")