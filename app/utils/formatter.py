from tldextract import ExtractResult


def format_size(size_bytes: float) -> str:
    try:
        if size_bytes is None or size_bytes <= 0:
            return "0 B"

        size_bytes = int(size_bytes)
    except (ValueError, TypeError):
        return "0 B"

    suffixes = ['B', 'KB', 'MB', 'GB']
    i = 0
    while size_bytes >= 1024 and i < len(suffixes) - 1:
        size_bytes /= 1024.0
        i += 1

    return f"{int(size_bytes)} {suffixes[i]}" if i == 0 else f"{size_bytes:.1f} {suffixes[i]}"

def format_redirect(url: str, current_subdomain: str = "") -> str:
    from urllib.parse import urlparse

    if not url or url in ["-", None, "None", ""]:
        return "-"
    parsed = urlparse(url)

    if current_subdomain and parsed.netloc == current_subdomain.lower():
        return "[bold #9ECE6A]HTTPS Upgrade[/]"

    if parsed.netloc:
        return parsed.netloc
    if parsed.path:
        return parsed.path
    return "-"

def format_subdomain(subdomain: str) -> ExtractResult:
    import tldextract
    root = tldextract.extract(subdomain)
    return root