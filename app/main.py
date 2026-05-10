from models import set_config

from dotenv import load_dotenv

from models.scan_config import ScanConfig
from utils import get_banner
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

    banner = get_banner()
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

    parser.add_argument("-V", "--version", action="version", version=f"subf {VERSION}")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.aggressive:
        args.verbose = args.title = args.header_tech = args.redirect = args.honeypot = True

    if args.redirect and not args.verbose:
        parser.error("redirect need verbose to show")
    if args.ip and not args.quiet:
        parser.error("Ip need quiet to show")

    config = ScanConfig(
        timeout=args.timeout,
        thread=args.thread,
        available=args.available,
        verbose=args.verbose,
        redirect=args.redirect,
        no_wildcard=args.no_wildcard,
        quiet=args.quiet,
        quiet_ip=args.ip,
        show_title=args.title,
        show_tech=args.header_tech,
        save_file_plain=args.output,
        save_file_json=args.output_json,
        delay=args.delay,
        source=args.source,
        all_resource=args.all,
        color=args.color,
        honeypot=args.honeypot,
        max_size=args.max_size,
        min_size=args.min_size,
        dns=args.dns,
        live=args.live
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