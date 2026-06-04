# coding: utf-8
"""urlscan.io — scanned-page search (JSON API, no key). Paginated."""
import asyncio

from .. import config
from .base import Source


class UrlScan(Source):
    name = 'urlscan'
    key = 'urlscan'

    async def query(self, domain, client):
        candidates = []
        params = {'q': 'domain:%s' % domain, 'size': '100'}
        for page in range(config.MAX_PAGES_PER_SOURCE):
            resp = await self._get(
                client, 'https://urlscan.io/api/v1/search/', params=dict(params),
            )
            data = resp.json()
            results = data.get('results', [])
            for result in results:
                for section in ('page', 'task'):
                    dom = result.get(section, {}).get('domain')
                    if dom:
                        candidates.append(dom)
            if not data.get('has_more') or not results:
                break
            # search_after = the `sort` array of the last result, comma-joined.
            sort = results[-1].get('sort')
            if not sort:
                break
            params['search_after'] = ','.join(str(x) for x in sort)
            await asyncio.sleep(config.URLSCAN_PAGE_DELAY)
        return candidates
