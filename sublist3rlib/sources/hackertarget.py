# coding: utf-8
"""HackerTarget hostsearch — passive DNS (CSV text API, no key)."""
from .base import Source


class HackerTarget(Source):
    name = 'hackertarget'
    key = 'hackertarget'

    async def query(self, domain, client):
        resp = await self._get(
            client, 'https://api.hackertarget.com/hostsearch/',
            params={'q': domain},
        )
        text = resp.text
        # Free tier returns a plain error/quota message instead of CSV.
        if 'error' in text.lower() or 'api count exceeded' in text.lower():
            return []
        candidates = []
        for line in text.splitlines():
            host = line.split(',', 1)[0].strip()
            if host:
                candidates.append(host)
        return candidates
