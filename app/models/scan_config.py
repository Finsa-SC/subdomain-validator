from dataclasses import dataclass

@dataclass
class ScanConfig:
    # --- Required --- #
    timeout: float = 3.0
    thread: int = 5
    delay: float = 0.0

    # --- Discovery --- #
    source: str | None = None
    all_resource: bool = False

    # --- Filtering --- #
    available: bool = False
    live: bool = False
    no_wildcard: bool = False
    min_size: int | None = None
    max_size: int | None = None

    # --- Information --- #
    verbose: bool = False
    redirect: bool = False
    quiet: bool = False
    quiet_ip: bool = False
    show_title: bool = False
    show_tech: bool = False
    color: bool = False
    honeypot: bool = False

    # --- Save --- #
    save_file_plain: bool = False
    save_file_json: bool = False

    # --- Dns --- #
    dns: str | None = None

_config = ScanConfig()

def get_config() -> ScanConfig:
    return _config

def set_config(config: ScanConfig) -> None:
    global _config
    _config = config