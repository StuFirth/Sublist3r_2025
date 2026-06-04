# **🚀 About Sublist3r (2026)**

Sublist3r is a fast subdomain-enumeration tool for penetration testers and bug hunters. This is the **2026 rework** — a ground-up modernization of the original Sublist3r that replaces the legacy process-per-engine design with a single **`asyncio` + `httpx`** core and a set of reliable, **key-less** OSINT data sources.

What makes this version better:

✅ **Concurrent by design** — all sources run in one async event loop, no multiprocessing/pickling fragility
✅ **Reliable sources** — dead search-engine scrapers replaced with Certificate-Transparency and passive-DNS APIs (no API keys required)
✅ **Fails soft** — a broken or rate-limited source logs a warning and is skipped; it never crashes the run
✅ **Backward compatible** — the classic CLI (`python sublist3r.py -d …`) and library API (`import sublist3r; sublist3r.main(...)`) still work
✅ **Tested** — 26 offline unit tests plus opt-in live network tests

Sublist3r enumerates subdomains using certificate-transparency logs (**crt.sh**, **Cert Spotter**), passive-DNS providers (**HackerTarget**, **AlienVault OTX**, **RapidDNS**, **Anubis**) and historical-URL datasets (**Wayback Machine**, **urlscan.io**), plus an optional DNS brute-force module ([subbrute](https://github.com/TheRook/subbrute)) with a large wordlist.

# **🛠 Installation**

## **Quick Install**
### Clone the latest tagged release (v2.0)
* `git clone --branch v2.0 https://github.com/StuFirth/Sublist3r_2025.git`
* `cd Sublist3r_2025`

> To track ongoing development instead, clone the default branch: `git clone https://github.com/StuFirth/Sublist3r_2025.git`

### Install dependencies
* `pip install -r requirements.txt`

### Run the tool
* `python sublist3r.py -d example.com`

## **Install as a package**
This also installs a `sublist3r` console command and pulls in the dependencies:

```
pip install .
```

You can then run it as `sublist3r -d example.com` or `python -m sublist3rlib -d example.com`.

## 🐍 Python Version Requirements

Sublist3r requires **Python 3.8+**. Python 2 support has been removed.

# **📦 Dependencies**

| Package | Version | Purpose |
|----------|----------|----------|
| `httpx` | >=0.27 | Async HTTP client for all passive sources |
| `dnspython` | >=2.0,<3 | DNS resolution for the brute-force module |
| `requests` | >=2.20 | Used by the bundled subbrute module |

On Windows, install `colorama` for coloured output: `pip install colorama`.

# **📖 Usage**

### Command Line Options

| Short | Long | Description |
|-------|------|-------------|
| `-d` | `--domain` | Domain name to enumerate (required) |
| `-b` | `--bruteforce` | Enable the subbrute DNS brute-force module |
| `-p` | `--ports` | Scan found subdomains against the given TCP ports |
| `-v` | `--verbose` | Show subdomains in real time as they are found |
| `-t` | `--threads` | Threads for the brute-force module (default: 30) |
| `-e` | `--engines` | Comma-separated list of sources to use |
| `-o` | `--output` | Save results to a text file |
| `-n` | `--no-color` | Disable coloured output |
| `-h` | `--help` | Show the help message and exit |

### Examples

**Basic enumeration:**
```bash
python sublist3r.py -d example.com
```

**Verbose output, saved to a file:**
```bash
python sublist3r.py -d example.com -v -o results.txt
```

**Enable DNS brute-force:**
```bash
python sublist3r.py -d example.com -b
```

**Use specific sources only:**
```bash
python sublist3r.py -d example.com -e crtsh,hackertarget,anubis
```

**Find subdomains with open ports 80/443:**
```bash
python sublist3r.py -d example.com -p 80,443
```

## 🔧 Available Sources

All sources are free and require **no API key**:

| Source (`-e` key) | Type | Description |
|--------|------|-------------|
| `crtsh` | Certificate Transparency | crt.sh CT-log search (JSON) |
| `certspotter` | Certificate Transparency | Cert Spotter issuances API |
| `hackertarget` | Passive DNS | HackerTarget hostsearch |
| `alienvault` | Passive DNS | AlienVault OTX passive DNS |
| `rapiddns` | Passive DNS | RapidDNS subdomain records |
| `anubis` | Aggregated DB | jldc.me Anubis database |
| `wayback` | Historical URLs | Wayback Machine CDX index |
| `urlscan` | Historical URLs | urlscan.io scanned-page search |

> **Legacy engine names are still accepted.** `ssl` maps to `crtsh` and `passivedns` maps to `alienvault`; removed search-engine scrapers (`google`, `yahoo`, `bing`, `baidu`, `ask`, `netcraft`, `dnsdumpster`, `virustotal`, `threatcrowd`) are ignored with a warning.

**DNS brute-force** (`-b`) uses the bundled subbrute module with its large wordlist and DNS spidering.

## 🐍 Using Sublist3r as a Python Module

```python
import sublist3r

subdomains = sublist3r.main(
    'example.com',     # domain
    30,                # threads (for brute-force)
    None,              # savefile
    None,              # ports
    True,              # silent
    False,             # verbose
    False,             # enable_bruteforce
    None,              # engines (None = all sources)
)
print(f"Found {len(subdomains)} subdomains")
```

`main()` returns a sorted list of unique subdomains. The signature is unchanged from the original Sublist3r, so existing scripts keep working.

For async callers, an `async` entry point is also available:

```python
import asyncio
from sublist3rlib import main_async

subdomains = asyncio.run(main_async('example.com', engines='crtsh,hackertarget'))
```

## 🏗️ Architecture

```
sublist3r.py            # thin shim: preserves the CLI + import sublist3r API
sublist3rlib/           # the package
  core.py               # async orchestrator (gather_passive, main_async)
  http_client.py        # shared httpx.AsyncClient (timeouts, retries, conn cap)
  sources/              # Source base + 8 sources + registry/legacy aliases
  normalize.py          # validation, host cleanup, subdomain sorting
  bruteforce.py         # wrapper around the bundled subbrute module
  output.py / logutil.py
subbrute/               # bundled DNS brute-forcer + wordlists
tests/                  # 26 offline tests + opt-in network tests
```

- Sources run concurrently via `asyncio.gather(return_exceptions=True)`; one failing source can never abort the run.
- Each source fails soft (logs a warning, returns an empty set) and retries rate-limited/transient responses with back-off.

## ✅ Testing

```bash
pip install pytest pytest-asyncio
pytest                 # 26 offline tests (no network)
pytest --run-network   # also run live smoke tests against real APIs
```

## 🛡️ What changed from the original Sublist3r

### ❌ Removed (broken in the original)
- **Search-engine scrapers** (Google, Yahoo, Bing, Ask, Baidu) — bot-blocked / fragile HTML scraping
- **Netcraft, DNSdumpster** — CSRF/JS-challenge protected
- **VirusTotal** — requires an API key
- **PassiveDNS** (`api.sublist3r.com`) — endpoint now serves a JS challenge
- **ThreatCrowd** — service discontinued
- **Python 2 compatibility** and the `multiprocessing.Manager()` source layer

### ✅ Added / improved
- **`asyncio` + `httpx`** concurrent core
- **Cert Spotter** and **Wayback Machine** as new sources
- Per-source **fail-soft** handling, retry/back-off, and a global connection cap
- Centralized normalization: apex exclusion, dot-anchored scope checks (rejects look-alike domains such as `evilexample.com`), URL/port/email cleanup
- A **pytest** suite and a clean, importable package layout

### 📈 Efficacy

In a back-to-back passive-only run against `iana.org`, the 2026 rework returned a **strict superset** of the previous version's results (~2× the subdomains) while correctly excluding the apex domain. Coverage gains come from the two extra sources and improved normalization. (Live counts vary with third-party rate limits.)

## 📄 License

Sublist3r is licensed under the **GNU GPL v3.0**. See [LICENSE](LICENSE) for details.

## 🙏 Credits

- **Original Sublist3r**: [Ahmed Aboul-Ela](https://github.com/aboul3la) — creator of the original tool
- **subbrute**: [TheRook](https://github.com/TheRook) — DNS brute-force module
- **Wordlist research**: [Bitquark](https://github.com/bitquark) — dnspop research
- **2026 rework**: async core, modern sources, and test suite

## ⚠️ Disclaimer

This tool is for **authorized security testing and educational purposes only**. Always ensure you have explicit permission before scanning any domain you do not own. The authors are not responsible for misuse.

## 📈 Version History

- **v2.0** (2026) — async + httpx rework, key-less CT/passive-DNS sources, test suite
- **v1.0** (2016) — original Sublist3r by Ahmed Aboul-Ela

---

**Current Version: 2.0** — async, reliable, and tested ✨
