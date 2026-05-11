from sources import hackertarget, crtsh, alienvault, rapiddns


def get_subdomain(domain: str, use_all: bool = False, selected_source: str = None):
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

    for s_name in to_run:
        if s_name in source_map:
            for sub in source_map[s_name](domain):
                if sub not in seen:
                    seen.add(sub)
                    yield sub