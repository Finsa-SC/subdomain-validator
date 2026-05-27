from concurrent.futures import ThreadPoolExecutor, as_completed

from utils import get_logger, update_result_in_cache
from enum import Enum

log = get_logger("deep_scan")

class StatusAction(Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"

def _run_favicon(result: dict, timeout: float) -> dict:
    from utils import fetch_favicon
    return fetch_favicon(result, timeout)

def _run_tech_version(result: dict, timeout: float) -> dict:
    from .tech_version import detect_version
    return detect_version(result, timeout)

def _run_page_recon(result: dict, timeout: float) -> dict:
    from .page_recon import run_page_recon
    return run_page_recon(result, timeout)

MODULES: dict[str, dict] = {
    "favicon": {
        "label": "Favicon Hash",
        "fn":    _run_favicon,
    },
    "tech_version": {
        "label": "Tech Versions",
        "fn":    _run_tech_version,
    },
    "page_recon": {
        "label": "Page Recon",
        "fn": _run_page_recon,
    }
}

def initial_state():
    return {
        key: {"status": StatusAction.PENDING, "label": mod["label"], "data": None}
        for key, mod in MODULES.items()
    }

def run_deep_scan(
        result: dict,
        on_module_done: callable,
        timeout: float = 8.0
):
    from core import app_state, send_request

    if not app_state.is_running:
        return

    if 'deep_scan' not in result:
        result['deep_scan'] = initial_state()

    subdomain = result.get("subdomain", "")
    import tldextract
    root = tldextract.extract(subdomain)
    domain_root = f"{root.domain}{root.suffix}"

    https_status = result.get('https', {}).get('status')
    base_url = f"https://{subdomain}" if https_status in (200, 301, 302, 307, 308) else f"http://{subdomain}"

    shared_body_html = None
    try:
        res = send_request(
            url=base_url,
            method="GET",
            timeout=timeout,
            allow_redirects=True
        )
        if res and res.status_code == 200 and res.content:
            res.encoding = res.charset_encoding or 'utf-8'
            shared_body_html = res.text
    except Exception as e:
        log.error(f"Failed to fetch shared body for {subdomain}: {e}")

    def _run_module(key: str, mod: dict):
        result['deep_scan'][key]['status'] = StatusAction.RUNNING
        on_module_done(key, result['deep_scan'])

        try:
            data = mod['fn'](result, timeout, shared_body_html, base_url)

            result['deep_scan'][key].update({
                "status": StatusAction.DONE,
                "data": data
            })
        except Exception as err:
            log.error(f"deep_scan module '{key}' failed: {err}")
            result['deep_scan'][key].update({
                "status": StatusAction.ERROR,
                "data": {"error": str(err)}
            })

        on_module_done(key, result['deep_scan'])

        update_result_in_cache(domain_root, subdomain, {"deep_scan": result["deep_scan"]})

    with ThreadPoolExecutor(max_workers=len(MODULES)) as ex:
        futures = {
            ex.submit(_run_module, key, mod): key
            for key, mod in MODULES.items()
        }
    for future in as_completed(futures):
        key = futures[future]
        try:
            future.result()
        except Exception as e:
            log.error(f"deep_scan future '{key}' raised: {e}")
