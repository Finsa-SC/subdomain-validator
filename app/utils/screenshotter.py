from idlelib import browser
from pathlib import Path
from models.signatures import TITLE_IGNORE
from .logger import get_logger

log = get_logger("screenshotter")

screenshot_dir = Path("result") / "screenshots"

def can_screenshot(result: dict) -> tuple[bool, str]:
    http = result.get("http", {})
    https = result.get("https", {})

    h_status = http.get("status")
    s_status = http.get("status")
    h_size = http.get("size")
    s_size = https.get("size")
    h_title = http.get("title").lower().strip()
    s_title = https.get("title").lower().strip()

    if h_status != 200 and s_status != 200:
        return False, f"Not a live host (HTTP: {h_status}, HTTPS: {s_status})"

    size = h_size if h_status == 200 else s_size
    if size <= 100:
        return False, f"Response is too small ({size} bytes)"

    title = h_title if h_status == 200 else s_title
    for junk in TITLE_IGNORE:
        if junk in title:
            return False, f"Title generic: '{title}'"

    return True, ""

def _pick_url(result: dict) -> str:
    subdomain = result.get("subdomain", "")
    if result.get("https", {}).get("status") == 200:
        return f"https://{subdomain}"
    return f"http://{subdomain}"

def take_screenshot(result: dict) -> tuple[bool, str]:
    ok, reason = can_screenshot(result)
    if not ok:
        return False, reason

    subdomain = result.get("subdomain", "")
    url = _pick_url(subdomain)

    save_name = subdomain.replace(".", "_").replace("/", "_")
    screenshot_dir.makedir(parent=True, exist_ok=True)
    out_path = screenshot_dir / save_name

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as play:
            browser = play.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
            )
            page = context.new_page()

            try:
                page.goto(url=url, timeout=15000, wait_until="domcontentloaded")
            except Exception:
                pass

            page.screenshot(path=str(out_path), clip={"x": 0, "y": 0, "width": 1280, "height": 800})
            browser.close()

        log.info(f"Screenshot saved: {out_path}")
        return True, str(out_path)
    except Exception as e:
        log.error(f"Screenshot failed for {subdomain}: {e}")
        return False, f"{e}"

