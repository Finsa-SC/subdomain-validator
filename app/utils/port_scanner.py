from utils import get_logger
import socket
import socks
import os

log = get_logger("port_scanner")
PROXY_URL = os.getenv("PROXY_URL", "").strip().lower()
DEBUG = str(os.getenv("DEBUG", 'false')).lower().strip() == 'true'

if PROXY_URL and "socks5" in PROXY_URL:
    try:
        clean_url = PROXY_URL.replace("socks5://", "")
        proxy_host, proxy_port = clean_url.split(":")

        socks.set_default_proxy(socks.SOCKS5, proxy_host, int(proxy_port))
        socket.socket = socks.socksocket
        log.info(f"Port scanner successfully hooked to SOCKS5 Proxy: {proxy_host}:{proxy_port}")
    except Exception as e:
        log.error(f"Failed to hook SOCKS5 proxy to socket layer: {e}")

def parse_port(ports: str) -> set:
    result = set()
    if not ports:
        return result
    for part in ports.split(","):
        part = part.strip()
        try:
            if '-' in part:
                start, end = part.split("-", 1)
                start = int(start)
                end = int(end)

                if start > end:
                    start, end = end, start
                result.update(range(start, end + 1))
            else:
                result.add(int(part))

        except ValueError:
            log.error(f"Invalid port format: ({part})")

    result = {
        p for p in result
        if 1 <= p <= 65535
    }

    if len(result) > 2000:
        log.warning(f"Large port scan detected ({len(result)}) ports")

    return result

def scan_port(host: str, ports: set[int], timeout: float = 1.0) -> dict[int, str]:
    result = {}

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                code = sock.connect_ex((host, port))
                if code == 0:
                    result[port] = 'open'
                elif code in (11, 111, 61, 10061):
                    continue
                else:
                    result[port] = 'filtered'
        except socket.timeout:
            result[port] = 'filtered'
        except Exception as ex:
            if DEBUG:
                log.debug(f"Can't scan port: {ex}")
            continue
    return result