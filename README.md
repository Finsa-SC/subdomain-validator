# subdomain-validator

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python&logoColor=white)
![uv](https://img.shields.io/badge/env-uv-purple?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Security](https://img.shields.io/badge/Use-Ethical%20Only-red?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

**A subdomain enumeration and validation tool with a Terminal User Interface (TUI), honeypot detection, and real-page screenshot capture.**

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
- Signals checked: server signatures, body hashes, literal honeypot headers, suspicious header ordering, identical HTTP/HTTPS bodies, default page titles, bait subdomain names
- Noisy-OR probability model with tiered signal weighting (Critical / Strong / Weak)
- Confidence labels: Confirmed / Likely / Probable / Possible / Unlikely

**📸 Screenshot Capture**

Press S in fullscreen view to capture the current live page using Playwright (Chromium headless rendering).

- Screenshots are saved to results/screenshots/<subdomain>.png
- Only executed for valid targets (HTTP 200, size > 100 bytes, non-generic title)
- Preview is shown inside the TUI using rich-pixels for inline rendering

> After saving, the image is also opened using the system default image viewer:

Linux: xdg-open
macOS: open
Windows: os.startfile

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
git clone --depth 1 https://github.com/Finsa-SC/subdomain-validator.git
cd subdomain-validator

# Create virtual environment
uv venv --python 3.10
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows

# Install dependencies
uv sync

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
| `--dns` | DNS resolver: `cloudflare`, `google`, `quad9`, `opendns`, or raw IP |
| `--min-size` | Skip responses smaller than N bytes |
| `--max-size` | Skip responses larger than N bytes |

### Output & Export

| Flag | Description |
|------|-------------|
| `-o`, `--output` | Save live IPs as plain text |
| `-oJ`, `--output-json` | Save full structured results as JSON |
| `-w`, `--no-wildcard` | Skip subdomains matching wildcard DNS baseline |
| `--honeypot` | Enable honeypot analyzer (always runs in TUI regardless) |
| `--purge` | Delete the entire `results/` directory |
| `-V`, `--version` | Show version |

---

## ⌨️ TUI Keybindings

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate table |
| `Enter` / `D` | Open side detail panel |
| `F` | Toggle fullscreen detail |
| `S` | Screenshot the live page (fullscreen only) |
| `/` | Focus filter bar |
| `Escape` | Close detail / unfocus filter |
| `C` | Copy subdomain to clipboard |
| `B` | Open subdomain in browser |
| `E` | Export selected |
| `Shift+E` | Export all filtered results |
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

# Filter by size (50 bytes min, 1MB max)
python app/main.py -d example.com --min-size 50 --max-size 1000000

# Slow scan with jitter delay
python app/main.py -d example.com --delay 0.5 --thread 3

# Purge results folder
python app/main.py --purge
```

---

## 🍯 Honeypot Analyzer

The honeypot engine runs automatically on every subdomain in the TUI. Signals are grouped into tiers and combined using a **Noisy-OR** probability model.

| Tier | Signals |
|------|---------|
| **Critical** | Known honeypot server signature, body hash match against known honeypots, literal honeypot headers (`x-honeypot`, `x-canary`, etc.) |
| **Strong** | Obsolete/deliberately exposed server version, suspicious header ordering, identical body on HTTP and HTTPS (without redirect), default server page title |
| **Weak** | High-value bait subdomain name (`admin`, `vpn`, `db`, `shell`, etc.), HTTP 200 with no page title |

| Score | Label |
|-------|-------|
| ≥ 90% | Confirmed |
| ≥ 75% | Likely |
| ≥ 50% | Probable |
| ≥ 25% | Possible |
| < 25% | Unlikely |

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
 
Screenshots are taken by opening the real URL in a headless Chromium browser (via Playwright), then saving the top viewport.
 
Saved to `results/screenshots/<subdomain>.png`. A preview is also rendered inline in the TUI fullscreen view using `rich-pixels`.
 
Screenshot conditions (all must pass):
- HTTP or HTTPS status = 200
- Response size > 100 bytes
- Page title is not a generic default (nginx default page, "It works!", etc.)
---

## 💾 Output Files

All saved to `results/`. CDN and proxy IPs (Cloudflare, Akamai, Fastly, etc.) are automatically filtered from output.

| File | Contents |
|------|----------|
| `results/<domain>_healthy_ip.txt` | IPs that returned HTTP 200 |
| `results/<domain>_problem_ip.txt` | IPs with non-200 responses |
| `results/<domain>.json` | Structured JSON with metadata, summary, and deduplicated findings |
| `results/screenshots/<subdomain>.png` | Full-page screenshots of live hosts |

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

Findings in `unique_active` and `others` are deduplicated by a fingerprint hash of `status + server + body_hash`. Each entry includes a `total` count and one representative `sample`.

---

## ⚙️ Environment Variables

Configure via `.env` (copy from `.env.example`). CLI flags override these at runtime.

| Variable | Default | Description |
|----------|---------|-------------|
| `TIMEOUT` | `3.0` | HTTP request timeout in seconds |
| `THREAD` | `5` | Concurrent thread count |
| `DELAY` | `0.0` | Delay between requests |
| `DEBUG` | `False` | When `True`, bypasses CLI and runs against `hosts.txt` directly |

---

## 🏗️ Project Structure

```
subdomain-validator/
├── app/
│   ├── main.py                  # Entry point — argparse CLI, pipe support, --purge
│   ├── analysis/
│   │   └── honeypot.py          # HoneypotAnalyzer — Noisy-OR fingerprinting engine
│   ├── core/
│   │   ├── request.py           # HTTP/HTTPS requests via curl_cffi with stealth headers
│   │   ├── scanner.py           # ThreadPoolExecutor orchestration, wildcard baseline
│   │   ├── stealth.py           # Randomized User-Agent and browser impersonation
│   │   └── validate.py          # Per-subdomain validation, tech detection, data building
│   ├── models/
│   │   ├── scan_config.py       # ScanConfig dataclass and global config accessor
│   │   └── signatures.py        # Honeypot signatures, PROXY_IPS, DNS providers, UA fallbacks
│   ├── sources/
│   │   ├── handler.py           # Source dispatcher
│   │   ├── hackertarget.py
│   │   ├── crtsh.py
│   │   ├── rapiddns.py
│   │   └── alienvault.py
│   ├── tui/
│   │   ├── app.py               # Textual App root
│   │   ├── filter_parser.py     # Structured filter query engine
│   │   ├── styles.css           # TUI theme (dark, cyan/gold palette)
│   │   ├── screens/
│   │   │   ├── main_screen.py   # Main layout — table + filter + detail panel
│   │   │   ├── fullscreen.py    # Fullscreen detail + S to screenshot
│   │   │   └── help_screen.py   # F1 help modal
│   │   └── widgets/
│   │       ├── subdomain_table.py
│   │       ├── detail_panel.py
│   │       └── stats_bar.py
│   └── utils/
│       ├── screenshotter.py     # Playwright screenshot + rich-pixels TUI preview
│       ├── writer.py            # JSON/TXT export with CDN IP filtering
│       └── logger.py            # File logger to /tmp/subv.log
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
docker build -t subvr .

# Run
docker run --rm subvr -d example.com --all
```

> Screenshot capture is not available inside Docker without a display server or virtual framebuffer.

---

> [!WARNING]
> **Gunakan dengan bijak. / Use responsibly.**
>
> This tool performs **active reconnaissance** — HTTP/HTTPS requests are sent directly to each discovered subdomain during validation. Your traffic **will be logged** by the target and may trigger IDS/WAF alerts.
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

**subdomain-validator** — Built with ❤️ using Python & multiple OSINT sources

🇮🇩 *Proudly made in Indonesia by [Finsa Kusuma Putra](https://github.com/Finsa-SC)*

#### *"Dari Indonesia, untuk dunia."*
*From Indonesia, for the world.*

</div>
