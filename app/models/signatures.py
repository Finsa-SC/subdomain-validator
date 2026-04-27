HONEYPOT_NAME = {
    "admin": 25,
    "login": 25,
    "portal": 20,
    "dashboard": 15,
    "setup": 30,
    "db": 20,
    "internal": 10
}

HONEYPOT_TITLE = {
    "admin portal": 30,
    "restricted access": 20,
    "management console": 25,
    "login page": 15
}

HONEYPOT_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": "Generic Empty Response",
    "5f352330a108a73b75a1334c264284d3": "Glastopf Default Login"
}

HONEYPOT_SIZE_RANGE = {
    "tiny_trap": (0, 500),
    "login_trap": (1000, 8000),
    "cms_trap": (13000, 16000)
}


HONEYPOT_SERVERS = {
    "twistedweb": 30,
    "kestrel": 20,
    "jetty": 15,
    "simplehttp": 25,
    "openssh_5.3": 30
}

OBSOLETE_VERSIONS = ["apache/2.2", "php/5.", "iis/7.0", "iis/6.0"]

SUSPICIOUS_HEADER_ORDERS = [
    ["content-type", "server", "date"], 
    ["x-powered-by", "content-type", "server"]
]