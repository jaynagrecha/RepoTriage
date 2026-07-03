"""Conservative CTI query and attribution policy — exact IOC match only."""

from __future__ import annotations

from urllib.parse import urlparse

# Bare hosts we must not wildcard-search (returns unrelated malware on shared platforms).
PLATFORM_HOSTS = frozenset({
    'github.com',
    'www.github.com',
    'raw.githubusercontent.com',
    'objects.githubusercontent.com',
    'gist.githubusercontent.com',
    'codeload.github.com',
    'gitlab.com',
    'www.gitlab.com',
    'bitbucket.org',
    'pastebin.com',
    'google.com',
    'www.google.com',
    'googleapis.com',
    'gstatic.com',
    'cloudflare.com',
    'amazonaws.com',
    'azurewebsites.net',
    'microsoft.com',
    'windows.net',
    'live.com',
    'office.com',
    'discord.com',
    'discordapp.com',
    'cdn.discordapp.com',
})

# Too short / generic to query without a full URL path.
MIN_DOMAIN_QUERY_LEN = 4


def _norm(value: str) -> str:
    return (value or '').strip().lower().rstrip('.,;:!?)"]}')


def host_from_indicator(indicator: str) -> str | None:
    s = _norm(indicator)
    if not s:
        return None
    if s.startswith(('http://', 'https://')):
        try:
            host = (urlparse(s).hostname or '').lower()
            return host or None
        except Exception:
            return None
    if '/' in s:
        return None
    return s.split(':')[0]


def is_platform_host(host: str | None) -> bool:
    if not host:
        return False
    h = host.lower()
    if h in PLATFORM_HOSTS:
        return True
    # Shared CDN / user-content subdomains on major platforms.
    for platform in PLATFORM_HOSTS:
        if h.endswith('.' + platform):
            return True
    return False


def is_full_url(indicator: str) -> bool:
    s = _norm(indicator)
    return s.startswith('http://') or s.startswith('https://')


def should_query_threatfox(indicator: str) -> tuple[bool, str]:
    """Return (allowed, reason)."""
    s = (indicator or '').strip()
    if not s:
        return False, 'empty'
    host = host_from_indicator(s)
    if is_full_url(s):
        if is_platform_host(host) and (urlparse(s).path or '/') in {'', '/'}:
            return False, 'platform_root_url'
        return True, 'exact_url'
    if host and not is_full_url(s):
        if is_platform_host(host):
            return False, 'platform_host'
        if len(host) < MIN_DOMAIN_QUERY_LEN:
            return False, 'too_short'
        return True, 'exact_domain'
    if len(s) in {32, 40, 64} and all(c in '0123456789abcdef' for c in _norm(s)):
        return True, 'hash'
    return False, 'unsupported_indicator'


def should_query_urlhaus(indicator: str) -> tuple[bool, str]:
    """URLHaus: exact full URL only — no host-wide lookups."""
    s = (indicator or '').strip()
    if not is_full_url(s):
        return False, 'urlhaus_requires_full_url'
    host = host_from_indicator(s)
    if is_platform_host(host) and (urlparse(s).path or '/') in {'', '/'}:
        return False, 'platform_root_url'
    return True, 'exact_url'


def threatfox_match_is_exact(indicator: str, match_ioc: str) -> bool:
    """True when ThreatFox returned IOC equals what we queried."""
    return _norm(match_ioc) == _norm(indicator)


def filter_threatfox_matches(indicator: str, matches: list[dict]) -> list[dict]:
    return [m for m in matches if threatfox_match_is_exact(indicator, str(m.get('ioc') or ''))]


def filter_threatfox_found_rows(indicator: str, rows: list[dict]) -> list[dict]:
    """Filter lookup rows so only exact IOC hits remain."""
    out: list[dict] = []
    for row in rows:
        filtered = filter_threatfox_matches(indicator, row.get('matches') or [])
        if not filtered:
            continue
        copy = dict(row)
        copy['matches'] = filtered
        copy['match_count'] = len(filtered)
        copy['exact_match_only'] = True
        out.append(copy)
    return out


def count_exact_cti_anchors(result: dict) -> dict[str, int | bool]:
    """Strong anchors for risk/family — hash or exact IOC only."""
    ti = result.get('threat_intel') or {}
    files = result.get('files') or []
    vt_malicious = sum(1 for f in files if str(f.get('vt_verdict', '')).lower() == 'malicious')
    mb_found = int((ti.get('malwarebazaar') or {}).get('summary', {}).get('found', 0) or 0)
    exact_tf = 0
    exact_uh = 0
    exact_c2 = 0
    for row in (ti.get('threatfox') or {}).get('found') or []:
        for m in row.get('matches') or []:
            if not threatfox_match_is_exact(row.get('indicator', ''), str(m.get('ioc') or '')):
                continue
            exact_tf += 1
            if str(m.get('infrastructure_role') or '').lower() in {'probable c2'} or str(m.get('threat_type') or '').lower() in {'botnet_cc', 'c2', 'cc'}:
                exact_c2 += 1
    for row in (ti.get('urlhaus') or {}).get('results') or []:
        if row.get('found') and is_full_url(str(row.get('indicator') or '')):
            exact_uh += 1
    return {
        'vt_malicious': vt_malicious,
        'malwarebazaar_hash_hits': mb_found,
        'exact_threatfox': exact_tf,
        'exact_urlhaus': exact_uh,
        'exact_probable_c2': exact_c2,
        'has_hash_anchor': mb_found > 0 or vt_malicious > 0,
        'has_exact_ioc_anchor': exact_tf > 0 or exact_uh > 0,
    }
