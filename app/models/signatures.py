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
    "admin", "login", "portal", "dashboard",
    "setup", "db", "internal", "vpn", "staging",
    "dev", "test", "backup", "secret", "hidden",
    "shell", "cmd", "root", "secure",
]

HONEYPOT_TITLE = [
    "iis7",
    "iis windows server",
    "apache2 ubuntu default page",
    "apache2 debian default page",
    "test page for apache",
    "welcome to nginx",
    "it works!",
    "default web site page",
    "index of /",
    "directory listing",
]

HONEYPOT_HASHES = {
    "5f352330a108a73b75a1334c264284d3": "Glastopf default login page",
    "7215ee9c7d9dc229d2921a40e899ec5f": "Dionaea bare HTTP response",
    "cfcd208495d565ef66e7dff9f98764da": "Heralding default response",
    "b026324c6904b2a9cb4b88d6d61c81d1": "Conpot default ICS interface",
    "d751713988987e9331980363e24189ce": "Python SimpleHTTPServer directory listing",
}

HONEYPOT_HEADERS = [
    "x-honeypot",
    "x-honey",
    "x-deception",
    "x-trap",
    "x-canary",
]

HONEYPOT_SIZE_RANGE = [
    "tiny_trap",
    "login_trap",
    "cms_trap"
]


HONEYPOT_SERVERS = [
    # Web honeypots
    "glastopf",
    "wordpot",
    "shockpot",
    "dionaea",
    "conpot",
    "heralding",
    "elasticpot",
    "hellpot",
    "basehttp",
    "twistedweb",
    "honeyd",
    "simplehttp",
    "scada",
]
OBSOLETE_VERSIONS = ["apache/2.2", "php/5.", "iis/7.0", "iis/6.0"]

SUSPICIOUS_HEADER_ORDERS = [
    ["server", "x-powered-by", "x-honeypot"],
    ["x-aspnet-version", "x-powered-by", "server", "x-honeypot"],
]

PROXY_IPS = [
    # Cloudflare
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",

    # Fastly
    "151.101.0.0/16",
    "146.75.0.0/16",

    # Akamai
    "23.0.0.0/12",
    "23.32.0.0/11",
    "96.6.0.0/15",

    # Imperva / Incapsula
    "45.64.64.0/22",
    "107.154.0.0/16",
    "199.83.128.0/21",
    "198.143.32.0/19",

    # AWS CloudFront
    "13.32.0.0/15",
    "13.224.0.0/14",
    "18.64.0.0/14",
    "52.46.0.0/18",
    "54.182.0.0/16",

    # Google CDN
    "34.96.0.0/20",
    "34.104.0.0/14",
    "35.190.0.0/17",

    # BunnyCDN
    "89.187.160.0/19",

    # QUIC.cloud
    "77.75.76.0/23",

    # Sucuri
    "192.88.134.0/23",
    "185.93.228.0/22",

    # StackPath
    "151.139.0.0/16",

    # KeyCDN
    "87.253.128.0/19",

    # Azure Front Door
    "147.243.0.0/16",

    # Gcore CDN
    "92.223.0.0/16",

    # Edgecast / Verizon
    "93.184.216.0/21",

    # Alibaba Cloud CDN
    "47.246.0.0/16",

    # Tencent CDN
    "43.152.0.0/13",

    # DDOS-Guard
    "185.129.100.0/22",

    # CDN77
    "169.150.192.0/18",

    # Leaseweb CDN
    "5.79.0.0/16",
]

SIGNAL_WEIGHTS = {
    "hash_match":        0.95,
    "honeypot_header":   0.92,
    "server_sig_match":  0.82,
    "obsolete_version":  0.65,
    "identical_body_both_proto": 0.50,
    "header_order":      0.52,
    "clickbait_title":   0.48,
    "subdomain_name":    0.20,
    "missing_title":     0.14,
}

SIGNAL_TIER = {
    "hash_match":       "critical",
    "honeypot_header":  "critical",
    "server_sig_match": "critical",
    "obsolete_version": "strong",
    "header_order":     "strong",
    "clickbait_title":  "strong",
    "identical_body_both_proto": "strong",
    "subdomain_name":   "weak",
    "missing_title":    "weak",
}

CONFIDENCE_LABELS = [
    (0.90, "Confirmed"),
    (0.75, "Likely"),
    (0.50, "Probable"),
    (0.25, "Possible"),
    (0.00, "Unlikely"),
]

KNOWN_PROXY_SERVERS = [
    "cloudflare",
    "cloudfront",
    "akamai",
    "fastly",
    "sucuri",
    "imperva",
    "varnish",
    "edgecast",
    "stackpath",
    "bunnycdn",
    "cdn77",
]

USER_AGENT_FALLBACK = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"
        ]

DNS_PROVIDERS = {
    "cloudflare": "1.1.1.1",
    "google": "8.8.8.8",
    "quad9": "9.9.9.9",
    "opendns": "208.67.222.222"
}