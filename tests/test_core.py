# coding: utf-8
import logging

from sublist3rlib.core import gather_passive
from sublist3rlib.sources import resolve_engines, SOURCES


class FakeSource:
    def __init__(self, name, result):
        self.name = name
        self.key = name
        self._result = result

    async def fetch(self, domain, client):
        if isinstance(self._result, Exception):
            raise self._result
        return set(self._result)


async def test_gather_passive_dedups_and_merges():
    sources = [
        FakeSource('a', {'www.example.com', 'shared.example.com'}),
        FakeSource('b', {'api.example.com', 'shared.example.com'}),
    ]
    found = await gather_passive('example.com', sources, client=object())
    assert found == {'www.example.com', 'api.example.com', 'shared.example.com'}


async def test_gather_passive_survives_raising_source(caplog):
    sources = [
        FakeSource('good', {'ok.example.com'}),
        FakeSource('bad', RuntimeError('kaboom')),
    ]
    with caplog.at_level(logging.WARNING, logger='sublist3r'):
        found = await gather_passive('example.com', sources, client=object())
    assert found == {'ok.example.com'}
    assert any('bad' in r.message for r in caplog.records)


def test_resolve_engines_all_when_none():
    assert len(resolve_engines(None)) == len(SOURCES)


def test_resolve_engines_known_keys():
    chosen = resolve_engines('crtsh,anubis')
    keys = {s.key for s in chosen}
    assert keys == {'crtsh', 'anubis'}


def test_resolve_engines_legacy_aliases(caplog):
    with caplog.at_level(logging.INFO, logger='sublist3r'):
        chosen = resolve_engines('ssl,passivedns')
    keys = {s.key for s in chosen}
    assert keys == {'crtsh', 'alienvault'}  # ssl->crtsh, passivedns->alienvault


def test_resolve_engines_removed_and_unknown_fall_back_to_all(caplog):
    # Only removed/unknown engines -> warn and fall back to all sources.
    with caplog.at_level(logging.WARNING, logger='sublist3r'):
        chosen = resolve_engines('google,virustotal,bogus')
    assert len(chosen) == len(SOURCES)
    assert any('removed' in r.message or 'unknown' in r.message for r in caplog.records)


def test_resolve_engines_dedups():
    chosen = resolve_engines('crtsh,ssl,crtsh')  # ssl is alias of crtsh
    assert [s.key for s in chosen] == ['crtsh']
