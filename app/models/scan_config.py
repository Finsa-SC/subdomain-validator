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

    # --- Dns --- #
    dns: str | None = None

_config = ScanConfig()

def get_config() -> ScanConfig:
    return _config

def set_config(config: ScanConfig) -> None:
    global _config
    _config = config