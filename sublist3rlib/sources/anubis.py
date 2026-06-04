# coding: utf-8
"""Anubis (jldc.me) — aggregated subdomain database (JSON API, no key)."""
from .base import Source


class Anubis(Source):
    name = 'anubis'
    key = 'anubis'

    async def query(self, domain, client):
        resp = await self._get(
            client, 'https://jldc.me/anubis/subdomains/%s' % domain,
        )
        data = resp.json()
        # API returns a flat JSON list of hostnames.
        return data if isinstance(data, list) else []
