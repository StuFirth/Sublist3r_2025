#!/usr/bin/env python
# coding: utf-8
# Sublist3r v2.0
# By Ahmed Aboul-Ela - twitter.com/aboul3la
#
# This top-level module is a thin backward-compatibility shim. The implementation
# lives in the ``sublist3rlib`` package. It is kept so that both:
#
#     python sublist3r.py -d example.com         # CLI
#     import sublist3r; sublist3r.main(...)      # library API
#
# continue to work exactly as before.
from sublist3rlib.api import main, main_async          # noqa: F401
from sublist3rlib.cli import interactive, banner        # noqa: F401
from sublist3rlib.normalize import subdomain_sorting_key  # noqa: F401

if __name__ == "__main__":
    interactive()
