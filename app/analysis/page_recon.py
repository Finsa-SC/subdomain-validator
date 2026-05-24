import re

from utils import get_logger

log = get_logger("Page Recon")

URL_PATTERNS = [
    r'href=["\']([^"\'#][^"\']*)["\']',
    r'src=["\']([^"\'#][^"\']*)["\']',
    r'action=["\']([^"\'#][^"\']*)["\']',
    r'(?:fetch|axios\.get|axios\.post|http\.get)\(["\']([^"\']+)["\']',
    r'url:\s*["\']([^"\']+)["\']',
    r'(?:endpoint|api_url|base_url)\s*=\s*["\']([^"\']+)["\']',
]

LOGIN_SIGNALS = [
    r'<input[^>]+type=["\']password["\']',
    r'(?:id|name|class)=["\'](?:login|signin|sign-in|log-in)["\']',
    r'action=["\'][^"\']*(?:login|signin|authenticate|auth)["\']',
    r'<form[^>]+(?:login|signin)',
    r'(?:forgot.?password|remember.?me)',
    r'<button[^>]*>(?:login|sign\s*in|log\s*in)</button>',
    r'placeholder=["\'](?:password|username|email address)["\']',
]

REGISTER_SIGNALS = [
    r'(?:id|name|class)=["\'](?:register|signup|sign-up|create.?account)["\']',
    r'action=["\'][^"\']*(?:register|signup|create.?account)["\']',
    r'<form[^>]+(?:register|signup)',
    r'(?:confirm.?password|repeat.?password|retype.?password)',
    r'<button[^>]*>(?:register|sign\s*up|create\s*account)</button>',
    r'placeholder=["\'](?:confirm password|repeat password)["\']',
]

ADMIN_SIGNALS = [
    r'(?:id|name|class)=["\'](?:admin|dashboard|control.?panel)["\']',
    r'<title>[^<]*(?:admin|dashboard|control panel|management)[^<]*</title>',
    r'href=["\'][^"\']*(?:/admin|/dashboard|/cp|/panel|/manage)["\']',
    r'(?:admin|administrator)\s+(?:panel|portal|console|area)',
]

INTERESTING_PATHS = [
    r'/api/', r'/v1/', r'/v2/', r'/v3/',
    r'/admin', r'/dashboard', r'/panel',
    r'/login', r'/signin', r'/logout',
    r'/register', r'/signup',
    r'/upload', r'/download', r'/file',
    r'/backup', r'/config', r'/setup',
    r'/user', r'/account', r'/profile',
    r'/search', r'/query',
    r'/debug', r'/test', r'/dev',
    r'\.php', r'\.asp', r'\.aspx', r'\.jsp',
    r'\.env', r'\.git', r'\.sql', r'\.bak',
]
