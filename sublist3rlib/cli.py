# coding: utf-8
"""Command-line interface: argument parsing, banner, and interactive entry."""
import argparse
import logging
import sys

from . import logutil
from .api import main

logger = logging.getLogger('sublist3r')


def banner():
    G, Y, B, R, W = logutil.colors()
    print(r"""%s
                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \___ \| | | | '_ \| | / __| __| |_ \| '__|
                 ___) | |_| | |_) | | \__ \ |_ ___) | |
                |____/ \__,_|_.__/|_|_|___/\__|____/|_|%s%s

                # Coded By Ahmed Aboul-Ela - @aboul3la
    """ % (R, W, Y))


def parser_error(errmsg):
    banner()
    G, Y, B, R, W = logutil.colors()
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit()


def parse_args():
    parser = argparse.ArgumentParser(
        epilog='\tExample: \r\npython ' + sys.argv[0] + " -d google.com")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain name to enumerate it's subdomains", required=True)
    parser.add_argument('-b', '--bruteforce', help='Enable the subbrute bruteforce module', nargs='?', default=False)
    parser.add_argument('-p', '--ports', help='Scan the found subdomains against specified tcp ports')
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime', nargs='?', default=False)
    parser.add_argument('-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)
    parser.add_argument('-e', '--engines', help='Specify a comma-separated list of search engines')
    parser.add_argument('-o', '--output', help='Save the results to text file')
    parser.add_argument('-n', '--no-color', help='Output without color', default=False, action='store_true')
    return parser.parse_args()


def interactive():
    args = parse_args()
    verbose = args.verbose or args.verbose is None
    logutil.setup_logging(verbose=verbose, no_color=args.no_color, silent=False)
    banner()
    if verbose:
        logger.info("verbosity is enabled, will show the subdomains results in realtime")
    main(args.domain, args.threads, args.output, args.ports,
         silent=False, verbose=verbose, enable_bruteforce=args.bruteforce,
         engines=args.engines)
