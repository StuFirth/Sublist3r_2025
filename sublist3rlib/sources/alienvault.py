# coding: utf-8
"""AlienVault OTX — passive DNS (JSON API, no key)."""
from .base import Source


class AlienVaultOTX(Source):
    name = 'alienvault'
    key = 'alienvault'

    async def query(self, domain, client):
        resp = await self._get(
            client,
            'https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns' % domain,
        )
        data = resp.json()
        return [rec.get('hostname', '') for rec in data.get('passive_dns', [])]
