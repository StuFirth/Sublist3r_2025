# coding: utf-8
"""Result output: file writing, printing, and the optional port scan."""
import logging
import os
import socket
import threading

logger = logging.getLogger('sublist3r')


def write_file(filename, subdomains):
    """Write subdomains to *filename*, one per line."""
    logger.info("Saving results to file: %s", filename)
    with open(str(filename), 'wt') as f:
        for subdomain in subdomains:
            f.write(subdomain + os.linesep)


def print_results(subdomains):
    """Print the final subdomain list to stdout, one per line (greppable)."""
    for subdomain in subdomains:
        print(subdomain)


class PortScan:
    """Lightweight threaded TCP connect scan over the discovered subdomains."""

    def __init__(self, subdomains, ports):
        self.subdomains = subdomains
        self.ports = ports
        self.lock = threading.BoundedSemaphore(value=20)

    def port_scan(self, host, ports):
        openports = []
        self.lock.acquire()
        try:
            for port in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    if s.connect_ex((host, int(port))) == 0:
                        openports.append(port)
                    s.close()
                except Exception:
                    pass
        finally:
            self.lock.release()
        if openports:
            logger.info("%s - Found open ports: %s", host, ', '.join(openports))

    def run(self):
        threads = []
        for subdomain in self.subdomains:
            t = threading.Thread(target=self.port_scan, args=(subdomain, self.ports))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()


def run_portscan(subdomains, ports):
    """Parse a comma-separated *ports* string and scan *subdomains*."""
    if isinstance(ports, str):
        ports = [p.strip() for p in ports.split(',') if p.strip()]
    logger.info("Start port scan now for the following ports: %s", ', '.join(ports))
    PortScan(subdomains, ports).run()
