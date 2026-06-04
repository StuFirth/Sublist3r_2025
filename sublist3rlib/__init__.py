# coding: utf-8
"""Sublist3r — fast subdomain enumeration.

Public API:

    from sublist3rlib import main, interactive
    subs = main('example.com', 30, None, None, True, False, False, None)

The top-level ``sublist3r.py`` shim re-exports these names so that both
``python sublist3r.py -d example.com`` and ``import sublist3r`` keep working.
"""
from .api import main, main_async
from .cli import interactive
from .normalize import subdomain_sorting_key

__all__ = ['main', 'main_async', 'interactive', 'subdomain_sorting_key']
__version__ = '2.0'
