# coding: utf-8
"""Tunable constants for the HTTP client and sources."""

# A realistic desktop browser UA; some sources reject obvious bots / empty UAs.
USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
)

# Overall per-request timeout (seconds) and a tighter connect timeout.
REQUEST_TIMEOUT = 25.0
CONNECT_TIMEOUT = 10.0

# httpx transport-level retries (connection errors only, not HTTP status codes).
TRANSPORT_RETRIES = 2

# Application-level retry for rate-limit / transient status codes.
RETRY_STATUS = frozenset({429, 502, 503, 504})
MAX_RETRIES = 2
RETRY_BACKOFF_BASE = 1.5  # seconds; multiplied by attempt number with jitter

# Global cap on simultaneous outbound connections across all sources.
MAX_CONNECTIONS = 12

# Safety cap so a paginating source (e.g. urlscan) can never loop forever.
MAX_PAGES_PER_SOURCE = 20
URLSCAN_PAGE_DELAY = 1.0  # seconds between urlscan pages, to stay friendly
