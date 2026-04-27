from dataclasses import dataclass

@dataclass
class ScanConfig:
    timeout: float
    thread: int
    available: bool
    verbose: bool
    redirect: bool
    no_wildcard: bool
    quiet: bool
    quiet_ip: bool
    show_title: bool
    show_tech: bool
    save_file_plain: bool
    save_file_json: bool
    delay: float
    source: str
    all_resource: bool
    color: bool
    honeypot: bool

current: 'ScanConfig' = None