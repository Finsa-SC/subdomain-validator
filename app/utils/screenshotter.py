from pathlib import Path
import threading
import sys
import platform, os, subprocess, random

from models.signatures import TITLE_IGNORE
from .logger import get_logger
from core import StealthMode

log = get_logger("screenshotter")

screenshot_dir = Path("results") / "screenshots"

def can_screenshot(result: dict) -> tuple[bool, str]:
    http = result.get("http", {})
    https = result.get("https", {})

    h_status = http.get("status")
    s_status = https.get("status")
    h_size = http.get("size")
    s_size = https.get("size")
    h_title = (http.get("title") or "").lower().strip()
    s_title = (https.get("title") or "").lower().strip()

    live_host = {200, 301, 302, 307, 308}
    if h_status not in live_host and s_status not in live_host:
        return False, f"Not a live host (HTTP: {h_status}, HTTPS: {s_status})"

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

def take_screenshot(result: dict, open_image: bool = False):
    ok, reason = can_screenshot(result)
    if not ok:
        return False, reason

    subdomain = result.get("subdomain", "")
    url = _pick_url(result)

    stealth = StealthMode()
    header, engine = stealth.get_payload()

    save_name = subdomain.replace(".", "_").replace("/", "_")
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    out_path = screenshot_dir / f"{save_name}.png"

    try:
        p, browser = ensure_chromium()

        page = browser.new_page(
            user_agent=header.get('User-Agent')
        )
        page.set_extra_http_headers(header)
        page.goto(url, timeout=15000, wait_until="domcontentloaded")
        page.wait_for_timeout(random.uniform(2000, 4000))
        page.screenshot(path=str(out_path), full_page=True)

        browser.close()
        p.stop()

        if open_image:
            open_image_popup(str(out_path))

        return True, str(out_path)

    except Exception as e:
        log.error(f"Screenshot failed: {e}")
        return False, str(e)

def open_image_popup(path: str):
    if platform.system() == 'Linux':
        subprocess.Popen(["xdg-open", path])
    elif platform.system() == 'Darwin':
        subprocess.run(["open", path])
    elif platform.system() == 'Windows':
        os.startfile(path)

def ensure_chromium():
    from playwright.sync_api import sync_playwright
    try:
        play = sync_playwright().start()
        args = [
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-blink-features=AutomationControlled"
        ]

        if random.random() > 0.5:
            args.append('--disable-gpu')

        proxy_url = os.getenv('PROXY_URL', None)
        browser = play.chromium.launch(
            args=args,
            proxy={'server': proxy_url} if proxy_url else None
        )
        return play, browser
    except Exception:
        log.error("Chromium not found! Installing...")
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            check=True
        )
        log.info("Chromium installed!")
        play = sync_playwright().start()
        args = [
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-blink-features=AutomationControlled"
        ]
        proxy_url = os.getenv('PROXY_URL', None)
        browser = play.chromium.launch(
            args=args,
            proxy={'server': proxy_url} if proxy_url else None
        )
        return play, browser

def do_screenshot(app, result: dict, notify=None, callback=None):
        from utils import take_screenshot, can_screenshot

        ok, reason = can_screenshot(result)
        if not ok:
            if notify:
                notify(
                    f"Can't take screenshot: {reason}",
                    severity="error",
                    timeout=4
                )
            return

        def _do():
            success, path_or_err = take_screenshot(
                result,
                open_image=True
            )

            def _notify():
                if success:
                    result["screenshot"] = path_or_err

                    if callback:
                        callback()

                    if notify:
                        notify(
                            f"✓ Saved: {path_or_err}",
                            severity="information",
                            timeout=5
                        )
                else:
                    if notify:
                        notify(
                            f"✗ Failed: {path_or_err}",
                            severity="error",
                            timeout=4
                        )
            app.call_from_thread(_notify)

        threading.Thread(target=_do, daemon=True).start()
        if notify:
            notify("Taking screenshot...", timeout=2)