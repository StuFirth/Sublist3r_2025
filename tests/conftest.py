# coding: utf-8
import os

import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')


def pytest_addoption(parser):
    parser.addoption(
        '--run-network', action='store_true', default=False,
        help='run tests marked @pytest.mark.network (real network I/O)',
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption('--run-network'):
        return
    skip = pytest.mark.skip(reason='needs --run-network')
    for item in items:
        if 'network' in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def load_fixture():
    """Return a function that reads a fixture file's text from tests/fixtures/."""
    def _load(name):
        with open(os.path.join(FIXTURES, name), encoding='utf-8') as f:
            return f.read()
    return _load
