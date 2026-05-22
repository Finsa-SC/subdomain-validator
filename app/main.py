from models import set_config
from utils import parse_port
from dotenv import load_dotenv
from models.scan_config import ScanConfig
from pathlib import Path
import os, sys, argparse, tempfile, shutil, platform
import platform

### Init env
load_dotenv()
TIMEOUT = float(os.getenv("TIMEOUT", 3.0))
THREAD = int(os.getenv("THREAD", 5))
DEBUG = os.getenv("DEBUG", "false").lower().strip() == "true"
DELAY = float(os.getenv("DELAY", 0.0))
RETRIES = int(os.getenv("RETRIES", 0))

VERSION = "1.0.0"

def main():
    temp_path = None

    if not sys.stdin.isatty():
        try:
            temp = tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8')
            temp.write(sys.stdin.read())
            temp.close()
            temp_path = temp.name
            sys.argv.extend(["-dL", temp_path])

            if platform.system() == "Windows":
                import msvcrt
                tty = open("CON", 'r')
            else:
                tty = open("/dev/tty", "r")

            os.dup2(tty.fileno(), 0)
            tty.close()
            sys.stdin = os.fdopen(0, 'r')
        except Exception as e:
            print(f"[x] Failed reading pipe data: {e}")
            sys.exit(1) 

    current_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(current_dir)
    banner_path = os.path.join(base_dir, "assets", "banner.txt")
    try:
        with open(banner_path, 'r', encoding='utf-8') as file:
            banner = file.read()
    except FileNotFoundError:
        banner = "[ Subv ]"
    parser = argparse.ArgumentParser(
        prog="subv",
        description=f"{banner}\nSubdomain recon tool - FinSky IT Solutions\nsubv {VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="[!] WARNING: Use with caution. Scanning will trigger logs on the target server."
    )

    # 1. INPUT ARGUMENTS
    input_group = parser.add_argument_group('INPUT ARGUMENTS')
    me_group = input_group.add_mutually_exclusive_group(required=True)
    me_group.add_argument("-d", "--domain", help="Search for single domain")
    me_group.add_argument("-dL", "--domain-list", help="Validate multiple subdomain from file")
    input_group.add_argument("-s", "--source", type=str, help="Select source from domain track record")
    input_group.add_argument("-p", "--port", type=str, help="Scan specific ports (e.g. 80,443,1-1000)")

    # 2. CONFIGURATION
    config_group = parser.add_argument_group('CONFIGURATION')
    config_group.add_argument("--timeout", type=float, default=TIMEOUT, help="Request timeout (default: 3s)")
    config_group.add_argument("--thread", type=int, default=THREAD, help="Number of threads (default: 5)")
    config_group.add_argument("--delay", type=float, default=DELAY, help="Delay of request")
    config_group.add_argument("--retry", type=int, default=RETRIES, help="Retry failed requests for transient/network errors (default: 0)")
    config_group.add_argument("--dns", type=str, help="Custom DNS provider (cloudflare, google, quad9, opendns) or IP")
    config_group.add_argument("--all", action="store_true", help="Use all available subdomain source enumeration")

    # 3. OUTPUT FILTERING
    filter_group = parser.add_argument_group('OUTPUT FILTERING')
    filter_group.add_argument("-A", "--available", action="store_true", help="Only show domain with 200 status code")
    filter_group.add_argument("-L", "--live", action="store_true", help="Only show domain with 200 status code")
    filter_group.add_argument("-w", "--no-wildcard", action="store_true", help="Skip if wildcard DNS detected")
    filter_group.add_argument("--ip", type=str, help="Show IP address instead of subdomain")
    filter_group.add_argument("-q", "--query", type=str,  help="Filter query (e.g. 'status:200 server:nginx NOT honeypot:true')")

    # 4. PROFILING & ANALYSIS
    profile_group = parser.add_argument_group('PROFILING & ANALYSIS')
    profile_group.add_argument("--honeypot", action="store_true", help="Enable smart fingerprinting")
    profile_group.add_argument("--screenshot", action="store_true", help="Take screenshot to each subdomain with 200 status code")
    profile_group.add_argument("-X", "--deep-scan", action="store_true", help="Automaticaly run deep scan for each subdomain")

    # 5. EXPORT OPTIONS
    export_group = parser.add_argument_group('EXPORT OPTIONS')
    export_group.add_argument("-o", "--output", action="store_true", help="Save result as plain list")
    export_group.add_argument("-oJ", "--output-json", action="store_true", help="Save result as JSON with detail")

    # 6. Scanning
    scanning_group = parser.add_argument_group('Scanning')
    scanning_group.add_argument("--fresh", action="store_true", help="Force fresh scan, ignore cache (cache < 2h auto-resume)")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    # Program
    parser.add_argument("--purge", action="store_true", help="Purge entire data in results directory")
    parser.add_argument("--log", action="store_true", help="Show log")
    parser.add_argument("-V", "--version", action="version", version=f"subv {VERSION}")

    #purge
    if "--purge" in sys.argv:
        target = Path("results")
        shutil.rmtree(target, ignore_errors=True)
        print("\t[✓] results directory purged")
        sys.exit(0)
    elif '--log' in sys.argv:
        target = Path("logs/latest.log")
        if not target.exists():
            print("\t[x] No logs found!")
            sys.exit(0)
        print("\t[C] Tailing on latest log...")
        try:
            if platform.system() == "Windows":
                os.system(f"powershell Get-Content {target} -Wait")
            else:
                os.system('tail -f logs/latest.log')
        except KeyboardInterrupt:
            print('\t[C] Exit log viewer.')
        sys.exit(0)

    args = parser.parse_args()

    filter_query = args.query or ""
    if args.no_wildcard:
        filter_query += " wildcard:no"
    if args.available:
        filter_query += " status:available"
    if args.live:
        filter_query += " status:live"
    if args.ip:
        filter_query += f" ip:{args.ip}"

    if args.delay < 0.0:
        args.delay = 0.0

    config = ScanConfig(
        domain=args.domain,
        domain_list=args.domain_list,
        timeout=args.timeout,
        thread=args.thread,
        no_wildcard=args.no_wildcard,
        save_file_plain=args.output,
        save_file_json=args.output_json,
        delay=args.delay,
        source=args.source,
        all_resource=args.all,
        honeypot=args.honeypot,
        screenshot=args.screenshot,
        dns=args.dns,
        retry=args.retry,
        port=parse_port(args.port),
        query=filter_query,
        deep_scan=args.deep_scan,
        fresh=args.fresh
    )

    set_config(config)
    domain_or_file = args.domain or args.domain_list

    from tui import run_tui
    run_tui(config, domain_or_file)

    if temp_path:
        try:
            os.remove(temp_path)
        except OSError:
            ...

if __name__ == "__main__":
    main()