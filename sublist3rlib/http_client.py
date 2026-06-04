# coding: utf-8
"""Shared httpx.AsyncClient factory."""
import httpx

from . import config


def build_client(**overrides):
    """Return a configured ``httpx.AsyncClient``.

    Use as an async context manager:

        async with build_client() as client:
            ...
    """
    kwargs = dict(
        headers={'User-Agent': config.USER_AGENT,
                 'Accept': 'application/json, text/html, */*'},
        timeout=httpx.Timeout(config.REQUEST_TIMEOUT, connect=config.CONNECT_TIMEOUT),
        limits=httpx.Limits(max_connections=config.MAX_CONNECTIONS),
        transport=httpx.AsyncHTTPTransport(retries=config.TRANSPORT_RETRIES),
        follow_redirects=True,
    )
    kwargs.update(overrides)
    return httpx.AsyncClient(**kwargs)
