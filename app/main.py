from models import set_config

from dotenv import load_dotenv

from models.scan_config import ScanConfig
import os
import tempfile
import argparse
import sys


### Init env
load_dotenv()
TIMEOUT = float(os.getenv("TIMEOUT", 3.0))
THREAD = int(os.getenv("THREAD", 5))
DEBUG = os.getenv("DEBUG", "false").lower().strip() == "true"
DELAY = float(os.getenv("DELAY", 0.0))

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
        except Exception as e:
            print(f"[x] Failed reading pipe data: {e}")
            sys.exit(1)

    banner = ""
    parser = argparse.ArgumentParser(
        prog="subv",
        description=f"{banner}\nSubdomain recon tool - FinSky IT Solutions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="[!] WARNING: Use with caution. Scanning will trigger logs on the target server."
    )
    # 1. INPUT ARGUMENTS
    input_group = parser.add_argument_group('INPUT ARGUMENTS')
    me_group = input_group.add_mutually_exclusive_group(required=True)
    me_group.add_argument("-d", "--domain", help="Search for single domain")
    me_group.add_argument("-dL", "--domain-list", help="Validate multiple subdomain from file")
    input_group.add_argument("-s", "--source", type=str, help="Select source from domain track record")

    # 2. CONFIGURATION
    config_group = parser.add_argument_group('CONFIGURATION')
    config_group.add_argument("--timeout", type=float, default=TIMEOUT, help="Request timeout (default: 3s)")
    config_group.add_argument("--thread", type=int, default=THREAD, help="Number of threads (default: 5)")
    config_group.add_argument("--delay", type=float, default=DELAY, help="Delay of request")
    config_group.add_argument("-all", action="store_true", help="Use all available resources for scanning")
    config_group.add_argument("--dns", type=str, help="Custom DNS provider (cloudflare, google, quad9, opendns) or IP")

    # 3. OUTPUT FILTERING
    filter_group = parser.add_argument_group('OUTPUT FILTERING')
    filter_group.add_argument("-A", "--available", action="store_true", help="Only show domain with 200 status code")
    filter_group.add_argument("-L", "--live", action="store_true", help="Only show domain with 200 status code")
    filter_group.add_argument("-w", "--no-wildcard", action="store_true", help="Skip if wildcard DNS detected")
    filter_group.add_argument("--ip", action="store_true", help="Show IP address instead of subdomain")
    filter_group.add_argument("--color", action="store_true", help="Color output text")
    filter_group.add_argument("--min-size", type=int, help="Filter response smaller than N bytes")
    filter_group.add_argument("--max-size", type=int, help="Filter response larger than N bytes")

    # 4. EXPORT OPTIONS
    export_group = parser.add_argument_group('EXPORT OPTIONS')
    export_group.add_argument("-o", "--output", action="store_true", help="Save result as plain list")
    export_group.add_argument("-oJ", "--output-json", action="store_true", help="Save result as JSON with detail")


    # 3. PROFILING & ANALYSIS
    profile_group = parser.add_argument_group('PROFILING & ANALYSIS')
    profile_group.add_argument("--honeypot", action="store_true", help="Enable smart fingerprinting")

    parser.add_argument("-V", "--version", action="version", version=f"subf {VERSION}")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    config = ScanConfig(
        timeout=args.timeout,
        thread=args.thread,
        no_wildcard=args.no_wildcard,
        save_file_plain=args.output,
        save_file_json=args.output_json,
        delay=args.delay,
        source=args.source,
        all_resource=args.all,
        honeypot=args.honeypot,
        max_size=args.max_size,
        min_size=args.min_size,
        dns=args.dns,
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