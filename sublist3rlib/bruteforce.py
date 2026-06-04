# coding: utf-8
"""Thin wrapper around the bundled subbrute DNS brute-force module.

subbrute uses ``multiprocessing`` internally. On macOS/Windows the ``spawn``
start method re-imports the parent module, so this wrapper must resolve the
wordlist/resolver paths from ``__file__`` (never the cwd) and import subbrute
lazily.
"""
import logging
import os

logger = logging.getLogger('sublist3r')

# repo root = parent of the sublist3rlib package directory
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
NAMES_FILE = os.path.join(_REPO_ROOT, 'subbrute', 'names.txt')
RESOLVERS_FILE = os.path.join(_REPO_ROOT, 'subbrute', 'resolvers.txt')


def run_bruteforce(netloc, threads, found, verbose=False):
    """Brute-force subdomains of *netloc*; return a set of discovered hostnames.

    *found* is the set of subdomains already discovered passively, passed to
    subbrute so it can skip them. Returns an empty set on any failure.
    """
    try:
        from subbrute import subbrute
    except Exception as exc:  # noqa: BLE001
        logger.warning("bruteforce unavailable (subbrute import failed): %s", exc)
        return set()
    try:
        return subbrute.print_target(
            netloc, False, NAMES_FILE, RESOLVERS_FILE,
            int(threads), False, False, set(found), verbose,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("bruteforce failed: %s", exc)
        return set()
