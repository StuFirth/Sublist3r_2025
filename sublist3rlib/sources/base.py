# coding: utf-8
"""Base class shared by all passive data sources."""
import asyncio
import logging
import random

import httpx

from .. import config
from ..normalize import clean_subdomains

logger = logging.getLogger('sublist3r')


class Source:
    """A single passive subdomain data source.

    Subclasses implement :meth:`query`, returning an iterable of *raw* candidate
    strings. The base class handles normalization and guarantees that a failing
    source logs a warning and yields an empty set instead of raising.
    """

    name = 'source'   # human-readable label, e.g. "crt.sh"
    key = 'source'    # registry key, e.g. "crtsh"

    async def query(self, domain, client):
        """Return an iterable of raw candidate hostnames. Override in subclasses."""
        raise NotImplementedError

    async def fetch(self, domain, client):
        """Run :meth:`query`, normalize, and never raise out of this method."""
        try:
            raw = await self.query(domain, client)
        except Exception as exc:  # noqa: BLE001 - sources must fail soft
            logger.warning("[%s] failed: %s", self.name, exc)
            return set()
        subs = clean_subdomains(raw or [], domain)
        for sub in sorted(subs):
            logger.debug("[%s] %s", self.name, sub)
        if subs:
            logger.info("[%s] found %d subdomains", self.name, len(subs))
        return subs

    async def _get(self, client, url, **kwargs):
        """GET *url* with retry/backoff on rate-limit and transient 5xx codes.

        Raises ``httpx.HTTPStatusError`` for non-retryable error codes so the
        caller's try/except in :meth:`fetch` records the failure.
        """
        last_exc = None
        for attempt in range(config.MAX_RETRIES + 1):
            try:
                resp = await client.get(url, **kwargs)
            except httpx.HTTPError as exc:
                last_exc = exc
                if attempt >= config.MAX_RETRIES:
                    raise
            else:
                if resp.status_code in config.RETRY_STATUS and attempt < config.MAX_RETRIES:
                    last_exc = httpx.HTTPStatusError(
                        "retryable status %d" % resp.status_code,
                        request=resp.request, response=resp,
                    )
                else:
                    resp.raise_for_status()
                    return resp
            # backoff with jitter before the next attempt
            delay = config.RETRY_BACKOFF_BASE * (attempt + 1) + random.uniform(0, 0.5)
            await asyncio.sleep(delay)
        # Exhausted retries on a retryable status.
        raise last_exc
