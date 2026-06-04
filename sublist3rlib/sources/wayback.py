# coding: utf-8
"""Wayback Machine CDX — historical URLs (text API, no key)."""
from .base import Source


class Wayback(Source):
    name = 'wayback'
    key = 'wayback'

    async def query(self, domain, client):
        resp = await self._get(
            client, 'https://web.archive.org/cdx/search/cdx',
            params={
                'url': '*.%s/*' % domain,
                'output': 'text',
                'fl': 'original',
                'collapse': 'urlkey',
                'limit': '50000',
            },
        )
        # Each line is a full URL; clean_subdomains extracts the host.
        return resp.text.splitlines()
