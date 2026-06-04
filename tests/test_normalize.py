# coding: utf-8
from sublist3rlib.normalize import (
    validate_domain,
    extract_netloc,
    subdomain_sorting_key,
    clean_subdomains,
)


def test_validate_domain_accepts():
    # The legacy regex validates a bare domain (no scheme) — parity with the original tool.
    for d in ['example.com', 'sub.example.com', 'a-b.example.co.uk']:
        assert validate_domain(d), d


def test_validate_domain_rejects():
    for d in ['', 'not a domain', 'example', 'http://', '/etc/passwd', 'http://example.com']:
        assert not validate_domain(d), d


def test_extract_netloc():
    assert extract_netloc('example.com') == 'example.com'
    assert extract_netloc('http://example.com') == 'example.com'
    assert extract_netloc('https://example.com/path?q=1') == 'example.com'


def test_subdomain_sorting_key_orders_correctly():
    # The exact ordering the original docstring promises.
    expected = [
        'example.com',
        'www.example.com',
        'a.example.com',
        'www.a.example.com',
        'b.a.example.com',
        'b.example.com',
        'example.net',
        'www.example.net',
        'a.example.net',
    ]
    shuffled = list(reversed(expected))
    assert sorted(shuffled, key=subdomain_sorting_key) == expected


def test_clean_subdomains_basic_and_apex():
    out = clean_subdomains(['WWW.example.com', 'example.com', 'a.example.com'], 'example.com')
    assert out == {'www.example.com', 'a.example.com'}  # apex dropped, lowercased


def test_clean_subdomains_rejects_lookalike_domain():
    # Dot-anchored containment: evilexample.com must NOT match example.com.
    out = clean_subdomains(['evilexample.com', 'x.evilexample.com', 'x.example.com'], 'example.com')
    assert out == {'x.example.com'}


def test_clean_subdomains_strips_wildcards():
    out = clean_subdomains(['*.example.com', '*wild.example.com', 'ok.example.com'], 'example.com')
    assert out == {'ok.example.com'}  # *.x normalizes to apex(dropped); *wild rejected


def test_clean_subdomains_handles_email_artifact():
    out = clean_subdomains(['admin@mail.example.com'], 'example.com')
    assert out == {'mail.example.com'}


def test_clean_subdomains_handles_urls_and_ports():
    out = clean_subdomains(
        ['https://api.example.com/v1/users', 'web.example.com:8443', 'cdn.example.com.'],
        'example.com',
    )
    assert out == {'api.example.com', 'web.example.com', 'cdn.example.com'}
