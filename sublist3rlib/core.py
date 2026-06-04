# coding: utf-8
"""Async orchestrator: gather passive sources, optionally brute-force, merge."""
import asyncio
import logging

from .http_client import build_client
from .normalize import validate_domain, extract_netloc, subdomain_sorting_key
from .sources import resolve_engines

logger = logging.getLogger('sublist3r')


async def gather_passive(domain, sources, *, client=None):
    """Run all *sources* concurrently against *domain*, return the union of hits.

    A source that fails has already logged and returned an empty set; the extra
    ``return_exceptions=True`` is a final safety net so one bad source can never
    abort the gather.
    """
    own_client = client is None
    if own_client:
        client = build_client()
    try:
        results = await asyncio.gather(
            *(s.fetch(domain, client) for s in sources),
            return_exceptions=True,
        )
    finally:
        if own_client:
            await client.aclose()

    found = set()
    for source, result in zip(sources, results):
        if isinstance(result, Exception):
            logger.warning("[%s] failed: %s", source.name, result)
            continue
        found |= result
    return found


async def main_async(domain, *, threads=30, savefile=None, ports=None,
                     silent=False, verbose=False, enable_bruteforce=False,
                     engines=None):
    """Enumerate subdomains for *domain*. Returns a sorted list of hostnames.

    Mirrors the behaviour and return type of the original ``main()``.
    """
    if not validate_domain(domain):
        logger.error("Please enter a valid domain")
        return []

    netloc = extract_netloc(domain)
    logger.info("Enumerating subdomains now for %s", netloc)

    sources = resolve_engines(engines)
    found = await gather_passive(netloc, sources)

    # Legacy semantics: flag present without a value (None) means "on".
    if enable_bruteforce or enable_bruteforce is None:
        logger.info("Starting bruteforce module now using subbrute..")
        from .bruteforce import run_bruteforce
        # subbrute uses multiprocessing and registers signal handlers, which only
        # works from the main thread — so run it directly here (the passive phase
        # is already complete, so blocking the loop briefly is fine) rather than
        # in an asyncio worker thread.
        found |= run_bruteforce(netloc, threads, found, verbose)

    subdomains = sorted(found, key=subdomain_sorting_key)

    # Output side-effects live in output.py; import lazily to keep core light.
    from . import output
    if savefile:
        output.write_file(savefile, subdomains)
    logger.info("Total Unique Subdomains Found: %d", len(subdomains))
    if ports:
        output.run_portscan(subdomains, ports)
    elif not silent:
        output.print_results(subdomains)
    return subdomains
