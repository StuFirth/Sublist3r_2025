# coding: utf-8
"""Source registry and legacy ``-e/--engines`` name resolution."""
import logging

from .crtsh import CrtSh
from .certspotter import CertSpotter
from .hackertarget import HackerTarget
from .alienvault import AlienVaultOTX
from .rapiddns import RapidDNS
from .anubis import Anubis
from .wayback import Wayback
from .urlscan import UrlScan

logger = logging.getLogger('sublist3r')

# Canonical source key -> class.
SOURCES = {
    cls.key: cls
    for cls in (CrtSh, CertSpotter, HackerTarget, AlienVaultOTX,
                RapidDNS, Anubis, Wayback, UrlScan)
}

# Legacy engine names from the old multiprocessing version.
#   value -> a new canonical key to use instead
#   None  -> the engine was removed in this version
ALIASES = {
    'ssl': 'crtsh',            # old CrtSearch
    'passivedns': 'alienvault',
    'google': None,
    'yahoo': None,
    'bing': None,
    'baidu': None,
    'ask': None,
    'netcraft': None,
    'dnsdumpster': None,
    'virustotal': None,
    'threatcrowd': None,
}


def resolve_engines(engines):
    """Resolve the ``-e/--engines`` value into a list of Source instances.

    *engines* is ``None`` (all sources) or a comma-separated string of keys.
    Unknown / removed engines are warned about and skipped. If the resulting
    list is empty, fall back to all sources so a run still produces results.
    """
    if engines is None:
        return [cls() for cls in SOURCES.values()]

    chosen = []
    seen = set()
    for token in engines.split(','):
        key = token.strip().lower()
        if not key:
            continue
        if key in SOURCES:
            target = key
        elif key in ALIASES:
            target = ALIASES[key]
            if target is None:
                logger.warning("engine '%s' was removed in this version; ignoring", key)
                continue
            logger.info("engine '%s' is now '%s'", key, target)
        else:
            logger.warning("unknown engine '%s'; ignoring", key)
            continue
        if target not in seen:
            seen.add(target)
            chosen.append(SOURCES[target]())

    if not chosen:
        logger.warning("no usable engines selected; falling back to all sources")
        return [cls() for cls in SOURCES.values()]
    return chosen
