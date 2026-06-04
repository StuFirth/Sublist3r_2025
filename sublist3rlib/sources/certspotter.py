# coding: utf-8
"""Cert Spotter — Certificate Transparency issuances (JSON API, no key)."""
from .base import Source


class CertSpotter(Source):
    name = 'certspotter'
    key = 'certspotter'

    async def query(self, domain, client):
        resp = await self._get(
            client, 'https://api.certspotter.com/v1/issuances',
            params={
                'domain': domain,
                'include_subdomains': 'true',
                'expand': 'dns_names',
            },
        )
        candidates = []
        for issuance in resp.json():
            candidates.extend(issuance.get('dns_names', []))
        return candidates
