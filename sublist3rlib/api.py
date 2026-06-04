# coding: utf-8
"""Synchronous public entry point, preserving the original ``main()`` signature."""
import asyncio
import threading

from .core import main_async

__all__ = ['main', 'main_async']


def main(domain, threads, savefile, ports, silent, verbose, enable_bruteforce, engines):
    """Enumerate subdomains for *domain* and return a sorted list.

    Byte-for-byte compatible with the original positional signature so existing
    scripts (and the README example) keep working::

        import sublist3r
        subs = sublist3r.main('yahoo.com', 40, None, None, True, False, False, None)
    """
    coro = main_async(
        domain, threads=threads, savefile=savefile, ports=ports,
        silent=silent, verbose=verbose, enable_bruteforce=enable_bruteforce,
        engines=engines,
    )
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # No running loop (the normal case): just run it.
        return asyncio.run(coro)

    # Called from within an existing event loop (e.g. a notebook or async app):
    # run in a dedicated thread with its own loop to avoid asyncio.run() conflicts.
    result = {}

    def _runner():
        result['value'] = asyncio.run(coro)

    t = threading.Thread(target=_runner)
    t.start()
    t.join()
    return result.get('value', [])
