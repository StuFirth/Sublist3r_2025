# coding: utf-8
"""RapidDNS — passive DNS. The only HTML-scraping source left, so isolate it."""
import re

from .base import Source

# RapidDNS renders results in an HTML table; the host is in a <td>. We extract
# every table cell and let normalize.clean_subdomains keep only in-scope hosts.
_TD_RE = re.compile(r'<td[^>]*>(.*?)</td>', re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r'<[^>]+>')


class RapidDNS(Source):
    name = 'rapiddns'
    key = 'rapiddns'

    async def query(self, domain, client):
        resp = await self._get(
            client, 'https://rapiddns.io/subdomain/%s' % domain,
            params={'full': '1'},
        )
        candidates = []
        for cell in _TD_RE.findall(resp.text):
            text = _TAG_RE.sub('', cell).strip()
            if text:
                candidates.append(text)
        return candidates
