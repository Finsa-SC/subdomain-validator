from models import USER_AGENT_FALLBACK

import random
from fake_useragent import UserAgent
import logging
from utils import get_logger

logging.getLogger('fake_useragent').setLevel(logging.CRITICAL)
log = get_logger("Stealth")

class StealthMode:
    def __init__(self):
        self.ua_active = False
        try:
            self.ua = UserAgent()
            self.ua_active = True
        except Exception as e:
            log.error(f"Error while trying to get User-Agent: {e}")
            self.ua = None
        self.base_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "DNT": "1"
        }

    @staticmethod
    def _get_engine(ua: str) -> str:
        if "firefox" in ua: return "firefox120"
        if "safari" in ua and "chrome" not in ua: return "safari15_5"
        return "chrome120"

    def get_payload(self):
        full_ua = self.ua.random if self.ua_active else self._get_manual_ua()

        referrers = [
            "https://www.google.com/",
            "https://www.google.co.id/",
            "https://search.yahoo.com/",
            "https://www.bing.com/",
            "https://duckduckgo.com/",
            None
        ]

        headers = {
            "User-Agent": full_ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "DNT": "1",
        }

        ref = random.choice(referrers)
        if ref:
            headers["Referer"] = ref

        return headers, self._get_engine(full_ua.lower())

    @staticmethod
    def _get_manual_ua() -> str:
        fallbacks = USER_AGENT_FALLBACK
        return random.choice(fallbacks)


