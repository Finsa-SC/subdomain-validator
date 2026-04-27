TITLE_IGNORE = [
    "301 moved permanently",
    "302 found",
    "object moved",
    "welcome to nginx!",
    "welcome to openresty",
    "403 forbidden",
    "404 not found",
    "used cloudflare to restrict access"]

HONEYPOT_NAME = [
    "admin",
    "login",
    "portal",
    "dashboard",
    "setup",
    "db",
    "internal"
]

HONEYPOT_TITLE = [
    "admin portal",
    "restricted access",
    "management console",
    "login page"
]

HONEYPOT_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": "Generic Empty Response",
    "5f352330a108a73b75a1334c264284d3": "Glastopf Default Login"
}

HONEYPOT_SIZE_RANGE = [
    "tiny_trap",
    "login_trap",
    "cms_trap"
]


HONEYPOT_SERVERS = [
    "twistedweb",
    "kestrel",
    "jetty",
    "simplehttp",
    "openssh_5.3"
]

OBSOLETE_VERSIONS = ["apache/2.2", "php/5.", "iis/7.0", "iis/6.0"]

SUSPICIOUS_HEADER_ORDERS = [
    ["content-type", "server", "date"],
    ["x-powered-by", "content-type", "server"]
]

CLOUDFLARE_IPS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
]

# models.py — tambahkan mapping probabilistik
SIGNAL_WEIGHTS = {
    # Critical tier: P(honeypot | signal) = 0.80–0.95
    "hash_match":          0.95,
    "cloudflare_leak":     0.85,
    "server_sig_match":    0.80,

    # Strong tier: 0.40–0.65
    "obsolete_version":    0.65,
    "header_order":        0.50,
    "server_mismatch":     0.45,

    # Weak tier: 0.10–0.25
    "subdomain_name":      0.20,
    "identical_size":      0.15,
    "clickbait_title":     0.12,
}

SIGNAL_TIER = {
    "hash_match":       "critical",
    "cloudflare_leak":  "critical",
    "server_sig_match": "critical",
    "obsolete_version": "strong",
    "header_order":     "strong",
    "server_mismatch":  "strong",
    "subdomain_name":   "weak",
    "identical_size":   "weak",
    "clickbait_title":  "weak",
}

CONFIDENCE_LABELS = [
    (0.90, "Confirmed"),
    (0.75, "Likely"),
    (0.50, "Probable"),
    (0.25, "Possible"),
    (0.00, "Unlikely"),
]