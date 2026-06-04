# coding: utf-8
import logging

import httpx
import pytest

from sublist3rlib.sources import SOURCES
from sublist3rlib.sources.crtsh import CrtSh
from sublist3rlib.sources.base import Source

DOMAIN = 'example.com'

# host -> (fixture filename, content-type)
ROUTES = {
    'crt.sh': ('crtsh.json', 'application/json'),
    'api.certspotter.com': ('certspotter.json', 'application/json'),
    'api.hackertarget.com': ('hackertarget.csv', 'text/plain'),
    'otx.alienvault.com': ('alienvault.json', 'application/json'),
    'rapiddns.io': ('rapiddns.html', 'text/html'),
    'jldc.me': ('anubis.json', 'application/json'),
    'web.archive.org': ('wayback.txt', 'text/plain'),
    'urlscan.io': ('urlscan.json', 'application/json'),
}

EXPECTED = {
    'crtsh': {'www.example.com', 'mail.example.com', 'shop.example.com'},
    'certspotter': {'www.example.com', 'api.example.com', 'cdn.example.com'},
    'hackertarget': {'www.example.com', 'mail.example.com', 'ftp.example.com'},
    'alienvault': {'www.example.com', 'blog.example.com'},
    'rapiddns': {'www.example.com', 'vpn.example.com'},
    'anubis': {'www.example.com', 'dev.example.com', 'staging.example.com'},
    'wayback': {'www.example.com', 'shop.example.com', 'blog.example.com'},
    'urlscan': {'www.example.com', 'portal.example.com'},
}


def _mock_client(load_fixture, status=200):
    def handler(request):
        if status != 200:
            return httpx.Response(status, text='boom')
        fixture, ctype = ROUTES[request.url.host]
        return httpx.Response(200, text=load_fixture(fixture),
                              headers={'content-type': ctype})
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.parametrize('key', sorted(SOURCES))
async def test_source_parses_fixture(key, load_fixture):
    source = SOURCES[key]()
    async with _mock_client(load_fixture) as client:
        result = await source.fetch(DOMAIN, client)
    assert result == EXPECTED[key]


async def test_source_failure_returns_empty_and_warns(load_fixture, caplog):
    source = CrtSh()
    with caplog.at_level(logging.WARNING, logger='sublist3r'):
        async with _mock_client(load_fixture, status=500) as client:
            result = await source.fetch(DOMAIN, client)
    assert result == set()
    assert any('crt.sh' in r.message for r in caplog.records)


async def test_base_query_not_implemented():
    with pytest.raises(NotImplementedError):
        await Source().query(DOMAIN, None)
