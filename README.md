# subdomain-scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python&logoColor=white)
![uv](https://img.shields.io/badge/env-uv-purple?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Security](https://img.shields.io/badge/Use-Ethical%20Only-red?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

**A subdomain enumeration and validation tool with a Terminal User Interface (TUI), honeypot detection, deep scan analysis, and real-page screenshot capture.**

</div>

---

> [!WARNING]
> **Recon Type: Hybrid (Passive + Active)**
> Subdomain *discovery* is done passively via external APIs — no direct contact with the target.
> The *validation* phase sends real HTTP/HTTPS requests to each discovered subdomain, meaning your traffic **will be logged** by the target and may trigger IDS/WAF alerts.
> **Only use this tool on domains you own or have explicit written permission to test.**

---

## ✨ Features

**Discovery**
- Multi-source subdomain enumeration — HackerTarget, crt.sh, RapidDNS, AlienVault OTX
- Source selection — pick a specific source (`-s`) or run all at once (`--all`)
- Flexible input — domain (`-d`), file (`-dL`), or stdin/pipe support
- Wildcard DNS baseline detection to filter false positives (`-w`)
- Auto-resume scan — caches results for up to 2 hours, skips already-scanned subdomains on restart

**Validation**
- Dual-protocol HTTP/HTTPS validation with IP resolution, server header, and latency measurement
- Custom DNS resolver — Cloudflare, Google, Quad9, OpenDNS, or custom IP (`--dns`)
- Response size filtering by min/max bytes (`--min-size`, `--max-size`)
- Technology detection from response headers (Nginx, Apache, PHP, WordPress, Cloudflare, etc.)

**TUI (Terminal User Interface)**
- Full interactive TUI powered by [Textual](https://github.com/Textualize/textual)
- Live table with real-time scan results — subdomain, IP, server, HTTP/HTTPS status
- Side detail panel with per-subdomain HTTP, HTTPS, tech, and honeypot breakdown
- Fullscreen detail view with complete header, cookie, and findings display
- Filter bar with structured query syntax — `status:200`, `server:nginx`, `honeypot:true`, `NOT status:404`, etc.
- Keyboard-driven navigation

**🍯 Honeypot Analyzer**
- Multi-signal fingerprinting engine to detect honeypots, canary traps, and fake services
- Signals checked: server signatures, body hashes, literal honeypot headers, suspicious header ordering, identical HTTP/HTTPS bodies, default page titles, bait subdomain names, fake cookies, body entropy, CDN mismatch, and response timing anomalies
- Noisy-OR probability model with tiered signal weighting (Critical / Strong / Weak)
- Confidence labels: Confirmed / Likely / Probable / Possible / Unlikely

**🔬 Deep Scan** *(Active — sends additional requests)*

> [!WARNING]
> **Deep Scan significantly increases the number of HTTP requests sent to each target.**
> Each module (Favicon, Tech Version, Page Recon) fetches additional pages and resources per subdomain — including crawling internal links and downloading JavaScript files.
> Enable only when you need detailed intelligence and have explicit permission to send increased traffic.

Press `X` in fullscreen view or use the `--deep-scan` / `-X` flag to trigger it. Deep scan runs three modules per subdomain:

- **Favicon Hash** — fetches `/favicon.ico` (and parses HTML as fallback), computes MMH3 hash, and matches against a known-tech database including honeypot frameworks. Generates a Shodan-compatible query.
- **Tech Version** — scans response headers and HTML body to identify precise versions of web servers, CMS platforms (WordPress, Joomla, Drupal, Ghost, Magento, etc.), JavaScript frameworks (React, Vue, Angular, jQuery), and backend stacks (PHP, ASP.NET, Django, Laravel, Rails). More accurate than standard header-only detection.
- **Page Recon** — fetches and parses the full page HTML to extract all internal/external URLs, detect login forms, registration pages, admin panels, and interesting paths (`/api/`, `/admin`, `.env`, `.git`, etc.). Also scans internal JavaScript files for hardcoded secrets and credentials (API keys, AWS keys, JWTs, DB connection strings, Stripe/Slack/GitHub tokens, etc.).

**📸 Screenshot Capture**

Press `S` in fullscreen view to capture the current live page using Playwright (Chromium headless rendering).

- Screenshots are saved to `results/screenshots/<subdomain>.png`
- Only executed for valid targets (HTTP 200, non-error response)
- Preview is shown inside the TUI fullscreen view

> After saving, the image is also opened using the system default image viewer:
> Linux: `xdg-open` · macOS: `open` · Windows: `os.startfile`

**🔧 External Tool Integration**

Press `A` to open the action menu for the selected subdomain, or `Shift+A` for bulk actions across all filtered results. Supported tools:

| Tool | Actions |
|------|---------|
| Nmap | Fast top-port discovery, full service enumeration |
| FFuf | Directory fuzzing, JSON payload fuzzing |
| SQLMap | SQL injection testing |
| Nuclei | Vulnerability template scanning |
| Nikto | Web server vulnerability scanning |
| WafW00f | WAF fingerprinting |
| WhatWeb | Web technology fingerprinting |
| theHarvester | OSINT email/subdomain gathering |
| Whois | Domain ownership lookup |
| Dig | DNS record inspection |
| Curl | HTTP header inspection |
| Searchsploit | Exploit database search (auto-matched to detected tech) |

**Export**
- Save IPs as plain text list (`-o`)
- Save structured JSON with metadata, summary, and grouped findings (`-oJ`)
- Automatic Cloudflare and CDN IP filtering on all saved output
- JSON deduplicates by response fingerprint hash
- Purge results directory with `--purge`

---

## 📋 Requirements

- Python 3.10+
- [uv](https://github.com/astral-sh/uv)
- Chromium (auto-installed by Playwright on first screenshot)

---

## 🚀 Getting Started

```bash
# Clone
git clone --depth 1 https://github.com/Finsa-SC/subdomain-scanner.git
cd subdomain-scanner

# Create virtual environment
uv venv --python 3.10
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows

# Install dependencies
uv sync #if use uv for package manager
pip install . #if use pip for package manager

# Install Playwright browser (required for screenshots)
playwright install chromium

# (Optional) Configure defaults
cp .env.example .env
```

---

## 📖 Usage

```bash
python app/main.py (-d DOMAIN | -dL FILE) [options]
```

Pipe/stdin support:
```bash
cat hosts.txt | python app/main.py
```

---

## 🚩 Flags

### Input

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Target domain to enumerate subdomains from |
| `-dL`, `--domain-list` | Path to file of subdomains to validate directly |
| `-s`, `--source` | Pick one source: `hackertarget`, `crtsh`, `rapiddns`, `alienvault` |
| `--all` | Use all available discovery sources and merge results |

### Configuration

| Flag | Description |
|------|-------------|
| `--timeout` | Request timeout in seconds (default: 3.0) |
| `--thread` | Concurrent threads (default: 5) |
| `--delay` | Delay between requests in seconds (default: 0.0) |
| `--retry` | Retry failed requests on transient/network errors (default: 0) |
| `--dns` | DNS resolver: `cloudflare`, `google`, `quad9`, `opendns`, or raw IP |

### Output & Export

| Flag | Description |
|------|-------------|
| `-o`, `--output` | Save live IPs as plain text |
| `-oJ`, `--output-json` | Save full structured results as JSON |
| `-w`, `--no-wildcard` | Skip subdomains matching wildcard DNS baseline |
| `--honeypot` | Enable honeypot analyzer (always runs in TUI regardless) |
| `--purge` | Delete the entire `results/` directory |
| `-V`, `--version` | Show version |

### Filtering

| Flag | Description |
|------|-------------|
| `-A`, `--available` | Only show subdomains with any HTTP response |
| `-L`, `--live` | Only show subdomains with HTTP 200 |
| `-q`, `--query` | Apply a structured filter query at startup |

### Profiling & Analysis

| Flag | Description |
|------|-------------|
| `--screenshot` | Auto-screenshot each 200-status subdomain during scan |
| `-X`, `--deep-scan` | ⚠️ Auto-run deep scan per subdomain (sends many extra requests) |
| `-p`, `--port` | Scan specific ports, e.g. `80,443,1-1000` |

### Scanning

| Flag | Description |
|------|-------------|
| `--fresh` | Force fresh scan, ignore existing cache |

---

## ⌨️ TUI Keybindings

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate table |
| `Enter` / `D` | Open side detail panel |
| `F` | Toggle fullscreen detail |
| `S` | Screenshot the live page (fullscreen only) |
| `X` | Run deep scan on selected subdomain (fullscreen only) |
| `P` | Port scan the selected subdomain (fullscreen only) |
| `A` | Open single-target action menu |
| `Shift+A` | Open bulk action menu (all filtered results) |
| `B` | Open subdomain in browser |
| `/` | Focus filter bar |
| `Escape` | Close detail / unfocus filter |
| `C` | Copy subdomain to clipboard |
| `E` | Export selected |
| `Shift+E` | Export all filtered results |
| `R` | Refresh / restart scan |
| `F1` | Show help |
| `Q` | Quit |

---

## 🔍 Filter Query Syntax

The filter bar accepts structured queries. Multiple filters can be combined.

| Query | Description |
|-------|-------------|
| `status:200` | Match specific HTTP status code |
| `status:forbidden` | Match 401/402/403 |
| `status:redirect` | Match 301/302/307/308 |
| `status:live` | Match 200 or redirects |
| `status:available` | Any subdomain with a valid HTTP response |
| `status:misconfigured` | Match 526/527/530 (Cloudflare errors) |
| `server:nginx` | Match by server header value |
| `tech:cloudflare` | Match by detected technology |
| `title:admin` | Match by page title |
| `honeypot:true` | Show only suspected honeypots |
| `honeypot:confirmed` | Match by confidence label |
| `wildcard:true` | Show/hide wildcard matches |
| `ip:1.2.3.*` | Match by IP pattern (supports wildcards) |
| `ip:proxy` | Show only proxy/CDN IPs |
| `size:500-5000` | Filter by response size range |
| `latency:100-500` | Filter by latency range in ms |
| `subdomain:*.dev.*` | Glob match on subdomain name |
| `port:80` | Filter by open port |
| `has:login` | Filter by deep scan findings (login, register, admin, credentials, js) |
| `NOT status:404` | Negate any filter |

---

## 💡 Examples

```bash
# Basic scan with TUI
python app/main.py -d example.com

# Use all discovery sources
python app/main.py -d example.com --all

# Use a specific source
python app/main.py -d example.com -s crtsh

# Custom DNS + skip wildcards + save JSON
python app/main.py -d example.com --dns cloudflare -w -oJ

# Scan from a file of subdomains
python app/main.py -dL hosts.txt --thread 20 --timeout 5

# Pipe from another tool
subfinder -d example.com | python app/main.py

# Only show live subdomains, auto-screenshot, save JSON
python app/main.py -d example.com -L --screenshot -oJ

# Deep scan every subdomain automatically (⚠️ high traffic)
python app/main.py -d example.com -X

# Port scan while discovering
python app/main.py -d example.com -p 80,443,8080,8443

# Start with a filter pre-applied
python app/main.py -d example.com -q "status:200 NOT honeypot:true"

# Slow scan with jitter delay
python app/main.py -d example.com --delay 0.5 --thread 3

# Force fresh scan, ignore cache
python app/main.py -d example.com --fresh

# Purge results folder
python app/main.py --purge
```

---

## 🍯 Honeypot Analyzer

The honeypot engine runs automatically on every subdomain in the TUI. Signals are grouped into tiers and combined using a **Noisy-OR** probability model.

| Tier | Signals |
|------|---------|
| **Critical** | Known honeypot server signature, body hash match against known honeypots, literal honeypot headers (`x-honeypot`, `x-canary`, etc.) |
| **Strong** | Obsolete/deliberately exposed server version, suspicious header ordering, identical body on HTTP and HTTPS (without redirect), default server page title, suspicious TLS/server stack (Python, SimpleHTTP, etc.), fake/low-entropy cookies, CDN mismatch between protocols, unnaturally fast/slow response timing, suspiciously small response body |
| **Weak** | High-value bait subdomain name (`admin`, `vpn`, `db`, `shell`, etc.), HTTP 200 with no page title |

| Score | Label |
|-------|-------|
| ≥ 90% | Confirmed |
| ≥ 75% | Likely |
| ≥ 50% | Probable |
| ≥ 25% | Possible |
| < 25% | Unlikely |

---

## 🔬 Deep Scan Modules

> [!WARNING]
> **Deep scan sends significantly more HTTP requests per subdomain.**
> Each module makes separate network calls beyond the initial validation request. With many subdomains and `--deep-scan` enabled, total request volume can multiply by 5–10x or more per subdomain. Use with caution and only on authorized targets.

### Favicon Hash (`favicon`)
Fetches `/favicon.ico` and computes an MMH3 hash. Falls back to HTML parsing if the default path returns nothing useful. Matches against a database of known technologies and honeypot frameworks, and generates a Shodan-compatible search query (`http.favicon.hash:<value>`).

### Tech Version (`tech_version`)
Goes beyond header-only detection by also parsing the full HTML body. Identifies precise versions of:
- **Web servers:** Nginx, Apache, IIS, LiteSpeed, Caddy, OpenResty
- **CMS:** WordPress, Joomla, Drupal, Ghost, Magento, TYPO3, Wix, Shopify
- **Frameworks:** Django, Laravel, Ruby on Rails, ASP.NET, ColdFusion, Express, Next.js
- **Frontend:** React, Vue.js, Angular, jQuery, Bootstrap

### Page Recon (`page_recon`)
Fetches the full page and crawls all extracted links. Reports:
- All internal and external URLs, categorized (api, auth, admin, file, sensitive, page)
- Login form detection (input patterns, form actions, button text)
- Registration page detection
- Admin panel detection
- **JS credential scanning** — downloads and scans internal `.js` files for hardcoded secrets: API keys, AWS keys, Google keys, JWTs, Bearer/Basic tokens, DB connection strings, Stripe, Twilio, SendGrid, Mailgun, Slack, GitHub tokens, and private key headers

Filterable in the TUI using `has:login`, `has:admin`, `has:credentials`, `has:js`, etc.

---

## 🔍 Discovery Sources

| Source | Key | Notes |
|--------|-----|-------|
| HackerTarget | `hackertarget` | Default. Free, no API key. |
| crt.sh | `crtsh` | Certificate transparency logs. No key required. |
| RapidDNS | `rapiddns` | Scrapes rapiddns.io. |
| AlienVault OTX | `alienvault` | Passive DNS. Requires an API key. |

---

## 📸 Screenshots

Screenshots are taken by opening the real URL in a headless Chromium browser (via Playwright), then saving the full page viewport.

Saved to `results/screenshots/<subdomain>.png`.

Screenshot conditions (any must pass):
- HTTP or HTTPS status in `{200, 301, 302, 307, 308}`

---

## 💾 Output Files

All saved to `results/`. CDN and proxy IPs (Cloudflare, Akamai, Fastly, etc.) are automatically filtered from output.

| File | Contents |
|------|----------|
| `results/<domain>_healthy_ip.txt` | IPs that returned HTTP 200 |
| `results/<domain>_problem_ip.txt` | IPs with non-200 responses |
| `results/<domain>.json` | Structured JSON with metadata, summary, and deduplicated findings |
| `results/screenshots/<subdomain>.png` | Full-page screenshots of live hosts |
| `results/cache/<domain>_result.json` | Scan cache (auto-resume within 2 hours) |

### JSON Structure

```json
{
  "metadata": {
    "timestamp": "2026-01-01 12:00:00",
    "domain": "example.com",
    "thread_used": 10
  },
  "summary": {
    "total_found": 42,
    "unique_active": 8,
    "honeypots": 2,
    "wildcard_ignored": 5,
    "others": 27
  },
  "findings": {
    "unique_active": {
      "<fingerprint_hash>": { "total": 3, "sample": { ... } }
    },
    "honeypots": [ { ... } ],
    "wildcard_sample": [ { ... } ],
    "others": { ... }
  }
}
```

Findings in `unique_active` and `others` are deduplicated by a fingerprint hash of `http_status + https_status + server + body_hash`. Each entry includes a `total` count and one representative `sample`. CDN/proxy IPs are excluded from JSON output.

---

## ⚙️ Environment Variables

Configure via `.env` (copy from `.env.example`). CLI flags override these at runtime.

| Variable | Default | Description |
|----------|---------|-------------|
| `TIMEOUT` | `3.0` | HTTP request timeout in seconds |
| `THREAD` | `5` | Concurrent thread count |
| `DELAY` | `0.0` | Delay between requests |
| `RETRIES` | `0` | Retry count for transient errors |
| `PROXY_URL` | _(none)_ | HTTP/SOCKS5 proxy URL, e.g. `socks5://127.0.0.1:1080` |
| `DEBUG` | `False` | When `True`, enables verbose debug logging |

---

## 🏗️ Project Structure

```
subdomain-scanner/
├── app/
│   ├── main.py                  # Entry point — argparse CLI, pipe support, --purge
│   ├── analysis/
│   │   ├── honeypot.py          # HoneypotAnalyzer — Noisy-OR fingerprinting engine
│   │   ├── deep_scan.py         # Deep scan orchestrator — runs modules in parallel
│   │   ├── page_recon.py        # Page crawler — URL extraction, login/admin detection, JS credential scanner
│   │   └── tech_version.py      # Header + body tech/version fingerprinting
│   ├── core/
│   │   ├── request.py           # HTTP/HTTPS requests via curl_cffi with stealth headers
│   │   ├── scanner.py           # ThreadPoolExecutor orchestration, wildcard baseline, cache resume
│   │   ├── state.py             # Global app state (running flag, executor ref)
│   │   ├── stealth.py           # Randomized User-Agent and browser impersonation
│   │   └── validate.py          # Per-subdomain validation, tech detection, data building
│   ├── models/
│   │   ├── scan_config.py       # ScanConfig dataclass and global config accessor
│   │   └── signatures.py        # Honeypot signatures, PROXY_IPS, DNS providers, UA fallbacks
│   ├── sources/
│   │   ├── handler.py           # Source dispatcher with cache-aware deduplication
│   │   ├── hackertarget.py
│   │   ├── crtsh.py
│   │   ├── rapiddns.py
│   │   └── alienvault.py
│   ├── tui/
│   │   ├── app.py               # Textual App root — global keybindings, screen management
│   │   ├── filter_parser.py     # Structured filter query engine
│   │   ├── styles.css           # TUI theme (dark, cyan/gold palette)
│   │   ├── screens/
│   │   │   ├── main_screen.py   # Main layout — table + filter + detail panel
│   │   │   ├── fullscreen.py    # Fullscreen detail + S screenshot + X deep scan + P port scan
│   │   │   ├── action_modal.py  # Single-target external tool launcher
│   │   │   ├── multi_action_model.py # Bulk target external tool launcher
│   │   │   └── help_screen.py   # F1 help modal
│   │   └── widgets/
│   │       ├── subdomain_table.py
│   │       ├── detail_panel.py
│   │       └── stats_bar.py
│   └── utils/
│       ├── screenshotter.py     # Playwright screenshot + system image viewer
│       ├── writer.py            # JSON/TXT export, CDN IP filtering, cache read/write
│       ├── favicon.py           # Favicon fetching, MMH3 hashing, known-tech matching
│       ├── launcher.py          # Terminal emulator detection + external tool launch
│       ├── port_scanner.py      # TCP port scanner with SOCKS5 proxy support
│       ├── formatter.py         # Size and redirect URL formatting helpers
│       └── logger.py            # File logger to logs/latest.log
├── assets/
│   └── banner.txt
├── .env.example
├── Dockerfile
└── pyproject.toml
```

---

## 🐳 Docker

```bash
# Build
docker build -t subv .

# Run
docker run --rm subv -d example.com --all
```

> Screenshot capture and external tool integration are not available inside Docker without a display server or virtual framebuffer. Deep scan and all network-based features work normally.

---

> [!WARNING]
> **Gunakan dengan bijak. / Use responsibly.**
>
> This tool performs **active reconnaissance** — HTTP/HTTPS requests are sent directly to each discovered subdomain during validation. Your traffic **will be logged** by the target and may trigger IDS/WAF alerts.
>
> The `--deep-scan` / `-X` flag and the in-TUI deep scan (`X` key) send **substantially more requests** per subdomain — including fetching full HTML pages, crawling internal links, and downloading JavaScript files. This significantly increases your traffic footprint.
>
> Only use on domains you **own** or have **explicit written permission** to test.
> Unauthorized use may violate:
> - 🇮🇩 **UU ITE** (Indonesia)
> - 🇺🇸 **CFAA** (United States)
> - And equivalent laws in your jurisdiction.
>
> The author is not responsible for any misuse or damage caused by this tool.

---

## 📜 License

Distributed under the [MIT License](LICENSE).

---

<div align="center">

**subdomain-scanner** — Built with ❤️ using Python & multiple OSINT sources

*made by [Finsa Kusuma Putra](https://github.com/Finsa-SC)*

</div>
