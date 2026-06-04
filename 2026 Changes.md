# Sublist3r_2025 — 2026 Rework

The 2026 rework rebuilds Sublist3r on an `asyncio` + `httpx` core and a set of
reliable, key-less data sources. It supersedes the earlier 2025 single-file
`modern_sublist3r.py`, which has been removed (its history is preserved in git).

## 🗑️ Removed

**Dead / hostile data sources** (replaced, not patched):
* **Search-engine scrapers** — Google, Yahoo, Bing, Ask, Baidu (bot detection, fragile HTML)
* **Netcraft**, **DNSdumpster** — JS/CSRF challenges
* **VirusTotal** — requires an API key
* **PassiveDNS** (`api.sublist3r.com`) — endpoint now serves a JS anti-bot challenge
* **ThreatCrowd** — service discontinued

**Legacy code:**
* Python 2 compatibility shims and `unicode` handling
* The `multiprocessing.Process` / `Manager()` source layer (the cause of the recurring `_thread.lock` pickle errors)
* The 2025 `modern_sublist3r.py` single-file implementation

## 🏗️ Core architecture changes

| | Before | After |
|---|---|---|
| Concurrency | process-per-engine `multiprocessing` (2025: threads) | single `asyncio` event loop + `httpx.AsyncClient` |
| Source layer | `enumratorBase` + multiple inheritance | one `Source` base class, one module per source |
| Failure handling | bare `try/except: pass` | fail-soft per source (warn + empty set) + `gather(return_exceptions=True)` |
| HTTP | new connection per request | shared async client, connection cap, retry/back-off on 429/5xx |
| Packaging | single script | `sublist3rlib/` package + thin `sublist3r.py` shim |

## 🚀 Data sources (free, no API key)

1. **crt.sh** — Certificate Transparency (JSON)
2. **Cert Spotter** — Certificate Transparency issuances *(new)*
3. **HackerTarget** — passive DNS
4. **AlienVault OTX** — passive DNS
5. **RapidDNS** — passive DNS
6. **Anubis** (jldc.me) — aggregated subdomain DB
7. **Wayback Machine** — historical URLs *(new)*
8. **urlscan.io** — scanned-page search

## ⚡ Performance & correctness

* **Concurrent** passive queries; the brute-force phase uses the full subbrute wordlist with DNS spidering.
* **Centralized normalization** — apex exclusion, dot-anchored scope checks (rejects look-alikes like `evilexample.com`), and URL/port/email cleanup.
* In a back-to-back passive-only run against `iana.org`, the rework returned a **strict superset** of the 2025 results (~2× the subdomains).

## 🔄 Backward compatibility

* CLI preserved: `python sublist3r.py -d example.com` with the original flags (`-d -b -p -v -t -e -o -n`).
* Library API preserved: `import sublist3r; sublist3r.main(domain, threads, savefile, ports, silent, verbose, enable_bruteforce, engines)` returns a sorted list.
* Legacy `-e` engine names are remapped (`ssl→crtsh`, `passivedns→alienvault`) or ignored with a warning (removed scrapers).

## ✅ Tests

* 26 offline unit tests (source parsers via fixtures, normalization, dedup/merge, engine mapping).
* Opt-in live network smoke tests (`pytest --run-network`).

## 📦 Dependencies

* `httpx>=0.27`, `dnspython>=2.0,<3`, `requests>=2.20`.

## 📈 Version

* **v2.0** (2026) — async rework (this document)
* **v1.0** (2016) — original Sublist3r by Ahmed Aboul-Ela
