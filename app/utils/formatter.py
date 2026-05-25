def format_size(size_bytes: float) -> str:
    try:
        if size_bytes is None or isinstance(size_bytes, float | int) or size_bytes <= 0:
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