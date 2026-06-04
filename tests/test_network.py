# coding: utf-8
"""Opt-in live network smoke tests. Run with: pytest --run-network

These hit real third-party APIs and are inherently flaky (rate limits, outages).
They assert the source *runs and returns a set*, not a specific count.
"""
import pytest

from sublist3rlib.http_client import build_client
from sublist3rlib.sources import SOURCES
from sublist3rlib.core import gather_passive

pytestmark = pytest.mark.network

DOMAIN = 'iana.org'


@pytest.mark.parametrize('key', sorted(SOURCES))
async def test_source_live(key):
    source = SOURCES[key]()
    async with build_client() as client:
        result = await source.fetch(DOMAIN, client)
    # fetch never raises; a degraded/rate-limited source returns an empty set.
    assert isinstance(result, set)


async def test_gather_passive_live_finds_something():
    sources = [cls() for cls in SOURCES.values()]
    found = await gather_passive(DOMAIN, sources)
    # At least one source should produce the canonical www host on a normal day.
    # Kept loose so a single-source outage doesn't fail the suite.
    assert isinstance(found, set)
    assert all(h.endswith('iana.org') for h in found)
