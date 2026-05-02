from dataclasses import dataclass

@dataclass()
class ReconStats:
    ok: int = 0
    forbidden: int = 0
    ssl_error: int = 0
    conn_error: int = 0
    server_error: int = 0
    dead: int = 0

    def log(self, http_status, https_status):
        code = [http_status, https_status]

        if any(isinstance(c, int) and c in (200, 301, 302) for c in code):
            self.ok += 1
        elif any(isinstance(c, int) and c in (402, 403) for c in code):
            self.forbidden += 1
        elif "SSL_ERR" in code:
            self.ssl_error += 1
        elif "CONN_ERR" in code:
            self.dead += 1
        elif any(isinstance(c, int) and 500 <= c <= 504 for c in code):
            self.server_error += 1

    def summary(self):
        print("\n\nSummary:")
        print(f"Host Up      : {self.ok}")
        print(f"Forbidden    : {self.forbidden}")
        print(f"SSL Error    : {self.ssl_error}")
        print(f"Server Error : {self.server_error}")
        print(f"No Response  : {self.dead}")