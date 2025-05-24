#!/usr/bin/env python3
# coding: utf-8
# Modern Sublist3r - Fixed and Updated Version
# Original by Ahmed Aboul-Ela, modernized for 2025

import re
import sys
import os
import argparse
import time
import hashlib
import random
import threading
import socket
import json
from urllib.parse import urlparse
from collections import Counter
import concurrent.futures
from typing import List, Set, Optional

# External modules with error handling
try:
    import dns.resolver
except ImportError:
    print("[!] Error: dnspython not installed. Run: pip install dnspython")
    sys.exit(1)

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] Error: requests not installed. Run: pip install requests")
    sys.exit(1)

# Disable SSL warnings
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except:
    pass

# Console Colors
G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white

def no_color():
    global G, Y, B, R, W
    G = Y = B = R = W = ''

def banner():
    print(f"""{R}
                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \___ \| | | | '_ \| | / __| __| |_ \| '__|
                 ___) | |_| | |_) | | \__ \ |_ ___) | |
                |____/ \__,_|_.__/|_|_|___/\__|____/|_|{W}{Y}

                # Modern Sublist3r - Fixed Version 2025
    """)

def parse_args():
    parser = argparse.ArgumentParser(
        description='Fast subdomains enumeration tool',
        epilog='Example: python3 sublist3r.py -d google.com'
    )
    parser.add_argument('-d', '--domain', help='Domain name to enumerate subdomains', required=True)
    parser.add_argument('-t', '--threads', help='Number of threads', type=int, default=10)
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('-v', '--verbose', help='Enable verbose output', action='store_true')
    parser.add_argument('-s', '--silent', help='Silent mode', action='store_true')
    parser.add_argument('-e', '--engines', help='Comma-separated list of engines to use')
    parser.add_argument('--no-color', help='Disable colored output', action='store_true')
    parser.add_argument('--timeout', help='Request timeout in seconds', type=int, default=10)
    return parser.parse_args()

class SubdomainEnumerator:
    def __init__(self, domain: str, verbose: bool = False, silent: bool = False, timeout: int = 10):
        self.domain = self.clean_domain(domain)
        self.verbose = verbose
        self.silent = silent
        self.timeout = timeout
        self.subdomains: Set[str] = set()
        self.session = self.create_session()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0'
        ]

    def clean_domain(self, domain: str) -> str:
        """Clean and validate domain"""
        if domain.startswith('http://') or domain.startswith('https://'):
            domain = urlparse(domain).netloc
        return domain.lower().strip()

    def create_session(self) -> requests.Session:
        """Create a robust session with retries"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def get_headers(self) -> dict:
        """Get randomized headers"""
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }

    def log(self, message: str, level: str = "info"):
        """Logging function"""
        if self.silent:
            return
        
        color = {'info': W, 'success': G, 'warning': Y, 'error': R}.get(level, W)
        print(f"{color}{message}{W}")

    def add_subdomain(self, subdomain: str, source: str = ""):
        """Add subdomain to results"""
        subdomain = subdomain.strip().lower()
        if subdomain and subdomain.endswith(self.domain) and subdomain not in self.subdomains:
            # Validate subdomain format
            if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$', subdomain):
                self.subdomains.add(subdomain)
                if self.verbose and source:
                    self.log(f"[{source}] {subdomain}", "success")

    def crt_search(self):
        """Search SSL certificates"""
        try:
            self.log("[-] Searching SSL certificates...")
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.session.get(url, headers=self.get_headers(), timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        if 'name_value' in entry:
                            names = entry['name_value'].split('\n')
                            for name in names:
                                name = name.strip()
                                if '*' not in name and '@' not in name:
                                    self.add_subdomain(name, "SSL Cert")
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            if self.verbose:
                self.log(f"[!] SSL certificate search error: {e}", "error")

    def hackertarget_search(self):
        """Search HackerTarget API"""
        try:
            self.log("[-] Searching HackerTarget...")
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = self.session.get(url, headers=self.get_headers(), timeout=self.timeout)
            
            if response.status_code == 200 and response.text:
                for line in response.text.split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        self.add_subdomain(subdomain, "HackerTarget")
        except Exception as e:
            if self.verbose:
                self.log(f"[!] HackerTarget search error: {e}", "error")

    def threatcrowd_search(self):
        """Search ThreatCrowd API"""
        try:
            self.log("[-] Searching ThreatCrowd...")
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            response = self.session.get(url, headers=self.get_headers(), timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'subdomains' in data and data['subdomains']:
                        for subdomain in data['subdomains']:
                            self.add_subdomain(subdomain, "ThreatCrowd")
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            if self.verbose:
                self.log(f"[!] ThreatCrowd search error: {e}", "error")

    def anubis_search(self):
        """Search Anubis API"""
        try:
            self.log("[-] Searching Anubis...")
            url = f"https://jldc.me/anubis/subdomains/{self.domain}"
            response = self.session.get(url, headers=self.get_headers(), timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, list):
                        for subdomain in data:
                            self.add_subdomain(subdomain, "Anubis")
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            if self.verbose:
                self.log(f"[!] Anubis search error: {e}", "error")

    def alienvault_search(self):
        """Search AlienVault OTX"""
        try:
            self.log("[-] Searching AlienVault OTX...")
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            response = self.session.get(url, headers=self.get_headers(), timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'passive_dns' in data:
                        for entry in data['passive_dns']:
                            if 'hostname' in entry:
                                self.add_subdomain(entry['hostname'], "AlienVault")
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            if self.verbose:
                self.log(f"[!] AlienVault search error: {e}", "error")

    def urlscan_search(self):
        """Search URLScan.io"""
        try:
            self.log("[-] Searching URLScan.io...")
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
            response = self.session.get(url, headers=self.get_headers(), timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'results' in data:
                        for result in data['results']:
                            if 'page' in result and 'domain' in result['page']:
                                self.add_subdomain(result['page']['domain'], "URLScan")
                            if 'task' in result and 'domain' in result['task']:
                                self.add_subdomain(result['task']['domain'], "URLScan")
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            if self.verbose:
                self.log(f"[!] URLScan search error: {e}", "error")

    def rapiddns_search(self):
        """Search RapidDNS"""
        try:
            self.log("[-] Searching RapidDNS...")
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            response = self.session.get(url, headers=self.get_headers(), timeout=self.timeout)
            
            if response.status_code == 200:
                # Parse HTML for subdomains
                pattern = r'<td><a[^>]*>([^<]*\.' + re.escape(self.domain) + r')</a></td>'
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    self.add_subdomain(match, "RapidDNS")
        except Exception as e:
            if self.verbose:
                self.log(f"[!] RapidDNS search error: {e}", "error")

    def dns_bruteforce(self, wordlist: List[str] = None):
        """DNS bruteforce with common subdomains"""
        if not wordlist:
            wordlist = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ssh', 'sftp', 'm', 'test',
                'staging', 'dev', 'development', 'prod', 'production', 'admin', 'www2', 'blog',
                'forum', 'api', 'app', 'mobile', 'support', 'help', 'shop', 'store', 'secure',
                'vpn', 'cdn', 'img', 'images', 'static', 'assets', 'media', 'upload', 'uploads',
                'download', 'downloads', 'files', 'docs', 'beta', 'alpha', 'demo', 'preview'
            ]

        self.log(f"[-] Starting DNS bruteforce with {len(wordlist)} words...")
        
        def check_subdomain(word):
            subdomain = f"{word}.{self.domain}"
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                resolver.nameservers = ['8.8.8.8', '1.1.1.1']
                
                result = resolver.resolve(subdomain, 'A')
                if result:
                    self.add_subdomain(subdomain, "DNS Bruteforce")
            except:
                pass

        # Use threading for DNS bruteforce
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(check_subdomain, wordlist)

    def run_all_searches(self, engines: Optional[List[str]] = None):
        """Run all available search engines"""
        available_engines = {
            'crt': self.crt_search,
            'hackertarget': self.hackertarget_search,
            'threatcrowd': self.threatcrowd_search,
            'anubis': self.anubis_search,
            'alienvault': self.alienvault_search,
            'urlscan': self.urlscan_search,
            'rapiddns': self.rapiddns_search,
        }

        if engines:
            selected_engines = {k: v for k, v in available_engines.items() if k in engines}
        else:
            selected_engines = available_engines

        # Run searches in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(selected_engines)) as executor:
            futures = [executor.submit(engine) for engine in selected_engines.values()]
            concurrent.futures.wait(futures)

    def enumerate(self, enable_bruteforce: bool = True, engines: Optional[List[str]] = None):
        """Main enumeration function"""
        self.log(f"[-] Starting subdomain enumeration for: {self.domain}")
        
        # Run API searches
        self.run_all_searches(engines)
        
        # DNS bruteforce
        if enable_bruteforce:
            self.dns_bruteforce()
        
        return sorted(list(self.subdomains))

def write_results(filename: str, subdomains: List[str]):
    """Write results to file"""
    try:
        with open(filename, 'w') as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
        print(f"{Y}[-] Results saved to: {filename}{W}")
    except Exception as e:
        print(f"{R}[!] Error saving results: {e}{W}")

def main():
    try:
        args = parse_args()
        
        if args.no_color:
            no_color()
        
        if not args.silent:
            banner()
        
        # Validate domain
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$', args.domain):
            print(f"{R}[!] Error: Invalid domain format{W}")
            return []
        
        # Parse engines
        engines = None
        if args.engines:
            engines = [e.strip().lower() for e in args.engines.split(',')]
        
        # Create enumerator
        enumerator = SubdomainEnumerator(
            domain=args.domain,
            verbose=args.verbose,
            silent=args.silent,
            timeout=args.timeout
        )
        
        # Start enumeration
        start_time = time.time()
        subdomains = enumerator.enumerate(engines=engines)
        end_time = time.time()
        
        if not args.silent:
            print(f"\n{G}[-] Enumeration completed in {end_time - start_time:.2f} seconds{W}")
            print(f"{Y}[-] Total unique subdomains found: {len(subdomains)}{W}")
            
            if not args.verbose:
                for subdomain in subdomains:
                    print(f"{G}{subdomain}{W}")
        
        # Save results
        if args.output:
            write_results(args.output, subdomains)
        
        return subdomains
        
    except KeyboardInterrupt:
        print(f"\n{R}[!] Enumeration interrupted by user{W}")
        return []
    except Exception as e:
        print(f"{R}[!] Error: {e}{W}")
        return []

if __name__ == "__main__":
    main()
