# WE'RE CURRENTLY EXPERIENCING TECHNICAL DIFFICULTIES, WE'LL BE RIGHT BACK.

# **🚀 About Sublist3r (2026)**

Sublist3r is a fast subdomain-enumeration tool for penetration testers and bug hunters. This is the **2026 rework** — a ground-up modernization of the original Sublist3r that replaces the legacy process-per-engine design with a single **`asyncio` + `httpx`** core and a set of reliable, **key-less** OSINT data sources.

What makes this version better:

✅ **Concurrent by design** — all sources run in one async event loop, no multiprocessing/pickling fragility

✅ **Reliable sources** — dead search-engine scrapers replaced with Certificate-Transparency and passive-DNS APIs (no API keys required)

✅ **Fails soft** — a broken or rate-limited source logs a warning and is skipped; it never crashes the run

✅ **Backward compatible** — the classic CLI (`python sublist3r.py -d …`) and library API (`import sublist3r; sublist3r.main(...)`) still work

✅ **Tested** — 26 offline unit tests plus opt-in live network tests
