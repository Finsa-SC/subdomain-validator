from dataclasses import dataclass

@dataclass
class ScanConfig:
    # --- Rule --- #
    timeout: float = 3.0
    thread: int = 5
    delay: float = 0.0
    retry: int = 0

    # --- Discovery --- #
    source: str | None = None
    all_resource: bool = False

    # ---Filter--- #
    no_wildcard: bool = False
    available: bool = True
    live: bool = True
    ip_address: str = None
    query: str = None

    # --- Profiling --- #
    honeypot: bool = False
    screenshot: bool = False
    deep_scan: bool = False

    # --- Dns --- #
    dns: str | None = None
    port: set[int] | None = None

    # --- Save --- #
    save_file_plain: bool = False
    save_file_json: bool = False

_config = ScanConfig()

def get_config() -> ScanConfig:
    return _config

def set_config(config: ScanConfig) -> None:
    global _config
    _config = config