import tldextract

from sources import hackertarget, crtsh, alienvault, rapiddns
from utils import load_result_from_cache, get_logger

log = get_logger("Source Handler")

def get_subdomain(domain: str, use_all: bool = False, selected_source: str = None, fresh: bool = False):
    seen = set()

    source_map = {
        "hackertarget": hackertarget.fetch_hackertarget,
        "crtsh": crtsh.fetch_crtsh,
        "alienvault": alienvault.fetch_alienvault,
        "rapiddns": rapiddns.fetch_rapiddns
    }

    if isinstance(selected_source, str):
        selected_source: list[str] = [selected_source]
    to_run = source_map.keys() if use_all else (selected_source or ["hackertarget"])

    cached_subdomains = set()
    if not fresh:
        root = tldextract.extract(domain)
        domain_root = f"{root.domain}.{root.suffix}"
        cached_data = load_result_from_cache(domain_root)
        cached_subdomains = set(cached_data.keys())
        log.info(f"Resume scan: Found {len(cached_subdomains)} cached subdomains from previous scan")

    for s_name in to_run:
        if s_name in source_map:
            for sub in source_map[s_name](domain):
                if sub not in seen:
                    seen.add(sub)
                    if not fresh and sub in cached_subdomains:
                        continue
                    yield sub