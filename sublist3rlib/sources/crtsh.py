# coding: utf-8
"""crt.sh — Certificate Transparency search (JSON API, no key)."""
from .base import Source


class CrtSh(Source):
    name = 'crt.sh'
    key = 'crtsh'

    async def query(self, domain, client):
        resp = await self._get(
            client, 'https://crt.sh/',
            params={'q': '%.' + domain, 'output': 'json'},
        )
        candidates = []
        for entry in resp.json():
            # name_value can hold several newline-separated names.
            for field in ('name_value', 'common_name'):
                value = entry.get(field)
                if value:
                    candidates.extend(value.split('\n'))
        return candidates
