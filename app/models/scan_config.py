from dataclasses import dataclass

@dataclass
class ScanConfig:
    # --- Scan --- #
    domain: str = None
    domain_list: str = None

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
    honeypot: bool = False
    query: str = None

    # --- Profiling --- #
    screenshot: bool = False
    deep_scan: bool = False

    # --- Dns --- #
    dns: str | None = None
    port: set[int] | None = None

    # --- Save --- #
    save_file_plain: bool = False
    save_file_json: bool = False
    fresh: bool = False

_config = ScanConfig()

def get_config() -> ScanConfig:
    return _config

def set_config(config: ScanConfig) -> None:
    global _config
    _config = config

##Load env
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

def _load_raw_toml(file_name: str = "config.toml") -> dict:
    current_dir = Path(__file__).parent
    base_dir = current_dir.parents[1]
    file_path = base_dir / file_name
    if not Path(file_path).exists():
        return {}

    with open(file_path, 'rb') as file:
        return tomllib.load(file)

_config_data = _load_raw_toml()


# General
_general_section = _config_data.get('general', {})
DEBUG: bool = _general_section.get("debug", False)

# Scan
_scan_section = _config_data.get('scan', {})
TIMEOUT: float = float(_scan_section.get("timeout", 3.0))
THREAD: int = int(_scan_section.get("thread", 5))
DELAY: float = float(_scan_section.get("delay", 0.0))
RETRIES: int = int(_scan_section.get("retries", 0))

# Network
_networ_sectionk = _config_data.get('network', {})
PROXY_URL: str = str(_networ_sectionk.get("proxy_url", ""))
