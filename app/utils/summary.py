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

    def log(self, http_status, https_status):
        code = [http_status, https_status]
        forbidden = (301, 302, 307, 308)
        unauthor = (401, 402, 403)

        add_lock.acquire()
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
        add_lock.release()

    def summary(self):
        host_up = self.ok + self.forbidden + self.server_error + self.redirect
        total_scan = host_up + self.ssl_error + self.dead

        print("\n\nSummary:")
        print(f"Host Up      : {host_up}")
        print(f"Live         : {self.ok}")
        print(f"Redirect     : {self.redirect}")
        print(f"Forbidden    : {self.forbidden}")
        print(f"SSL Error    : {self.ssl_error}")
        print(f"Server Error : {self.server_error}")
        print(f"No Response  : {self.dead}")
        print(f"\n\nTotal Host Scanned: {total_scan}")