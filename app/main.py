from core import check_subdomain
from models import scan_config
from models import ScanConfig

from dotenv import load_dotenv
import os
import argparse
from utils import print_banner


### Init env
load_dotenv()
TIMEOUT = float(os.getenv("TIMEOUT", 3.0))
THREAD = int(os.getenv("THREAD", 10))
DEBUG = os.getenv("DEBUG", "false").lower().strip() == "true"
DELAY = os.getenv("DELAY", 0.0)

VERSION = "1.0.0"

def main():
    parser = argparse.ArgumentParser(description="Subdomain recon tool")

    group = parser.add_mutually_exclusive_group(required=True)

##Version
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"subf {VERSION}",
        help="Print version of the tool"
    )


##Input
    group.add_argument(
        "-d",
        "--domain",
        help="Search for single domain"
    )

    group.add_argument(
        "-dL",
        "--domain-list",
        help="Validate multiple domain from file"
    )

    parser.add_argument(
        "-s",
        "--source",
        type=str,
        help="Select source from domain tract record you want to use"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=TIMEOUT,
        help="Request timeout (default is 3 sec)"
    )

    parser.add_argument(
        "--thread",
        type=int,
        default=THREAD,
        help="Number of threads (default is 10)"
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=DELAY,
        help="Delay of request"
    )

##Inputless
    parser.add_argument(
        "-A",
        "--available",
        action="store_true",
        help="Only show domain with 200 status code"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show information more detail"
    )

    parser.add_argument(
        "-r",
        "--redirect",
        action="store_true",
        help="Show redirect information"
    )

    parser.add_argument(
        "-w",
        "--no-wildcard",
        action="store_true",
        help="Skip subdomain if wildcard dns detected in that's subdomain"
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Show clean output in terminal only subdoamin with http/https 200 status code"
    )

    parser.add_argument(
        "--ip",
        action="store_true",
        help="Show ip address instead subdomain clearly"
    )

    parser.add_argument(
        "-t",
        "--title",
        action="store_true",
        help="Print title of page below subdomain"
    )

    parser.add_argument(
        "-x",
        "--header-tech",
        action="store_true",
        help="Show subdomain tech from header"
    )

    parser.add_argument(
        "-a",
        "--aggressive",
        action="store_true",
        help="Enable all informative flags (-v, -T, -x, etc.)")

    parser.add_argument(
        "-all",
        action="store_true",
        help="Use all available resource"
    )

    parser.add_argument(
        "--honeypot",
        action="store_true",
        help="Detect honeypot from subdomain"
    )

    parser.add_argument(
        "-o",
        "--output",
        action="store_true",
        help="Save recon result as plain list ip"
    )

    parser.add_argument(
        "-oJ",
        "--output-json",
        action="store_true",
        help="Save recon result as json with detail information"
    )

    parser.add_argument(
        "--color",
        action="store_true",
        help="Color output text"
    )

    args = parser.parse_args()

    if args.aggressive:
        args.verbose = args.title = args.header_tech = args.redirect = args.honeypot = True

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
        honeypot=args.honeypot
    )
    scan_config.current = config


    if args.redirect and not args.verbose:
        parser.error("redirect need verbose to show")
    if args.ip and not args.quiet:
        parser.error("Ip need quiet to show")

    if args.domain:
        check_subdomain(args.domain)
    elif args.domain_list:
        check_subdomain(args.domain_list)

if __name__ == "__main__":
    main()