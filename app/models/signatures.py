TITLE_IGNORE = [
    "301 moved permanently",
    "302 found",
    "object moved",
    "welcome to nginx!",
    "welcome to openresty",
    "403 forbidden",
    "404 not found",
    "used cloudflare to restrict access"]

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