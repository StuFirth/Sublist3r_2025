# coding: utf-8
"""Domain validation, normalization and sorting helpers.

These are pure functions with no I/O so they can be unit-tested without a network.
"""
import re
from urllib.parse import urlsplit

# Kept verbatim from the original sublist3r for input-validation parity.
# It is deliberately loose; tightening it would change which inputs are accepted.
DOMAIN_RE = re.compile(r"^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")


def validate_domain(domain):
    """Return True if *domain* looks like a domain we are willing to enumerate."""
    return bool(domain) and bool(DOMAIN_RE.match(domain))


def extract_netloc(domain):
    """Reduce a user-supplied domain/URL to its bare host (netloc).

    Mirrors the original behaviour: prepend a scheme if missing, then take the
    network location component.
    """
    if not domain.startswith(('http://', 'https://')):
        domain = 'http://' + domain
    return urlsplit(domain).netloc


def subdomain_sorting_key(hostname):
    """Sorting key for subdomains.

    Orders subdomains from the top-level domain at the right reading left, then
    moves 'www' to the top of its group. Copied verbatim from the original tool;
    its behaviour is relied upon by the README example and existing users.
    """
    parts = hostname.split('.')[::-1]
    if parts[-1] == 'www':
        return parts[:-1], 1
    return parts, 0


def _to_host(candidate):
    """Turn a single raw candidate into a bare lowercase host, or '' if unusable.

    Handles full URLs, certificate ``CN`` style ``email@host`` artefacts and
    surrounding whitespace.
    """
    host = candidate.strip().lower()
    if not host:
        return ''
    # Some sources (crt.sh) emit "user@host" from certificate subjects.
    if '@' in host:
        host = host[host.rfind('@') + 1:]
    # Some sources (wayback, urlscan) emit full URLs or host:port/path.
    if '://' in host or '/' in host:
        # urlsplit needs a scheme to populate netloc reliably.
        if '://' not in host:
            host = 'http://' + host
        host = urlsplit(host).netloc
    # Drop a port if one slipped through.
    if ':' in host:
        host = host.split(':', 1)[0]
    # Strip a trailing dot (FQDN root) and a leading wildcard label.
    host = host.rstrip('.')
    if host.startswith('*.'):
        host = host[2:]
    return host


def clean_subdomains(candidates, domain):
    """Normalize an iterable of raw candidate strings into a clean set of subdomains.

    - lowercases / strips / URL-decodes hosts
    - drops wildcard entries (``*``)
    - keeps only hosts within *domain* (``host == domain`` or ``*.domain``),
      using a dot-anchored check so ``evilexample.com`` is rejected for ``example.com``
    - drops the apex (*domain* itself), matching the original ``subdomain != domain``
    """
    domain = domain.strip().lower()
    suffix = '.' + domain
    result = set()
    for candidate in candidates:
        host = _to_host(candidate)
        if not host or '*' in host:
            continue
        if host == domain:
            continue
        if host.endswith(suffix):
            result.add(host)
    return result
