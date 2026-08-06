"""Conservative CTI query and attribution policy — exact IOC match only."""

from __future__ import annotations

from urllib.parse import urlparse

# Bare hosts we must not query (shared platforms → unrelated malware hits).
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

# Benign / documentation hosts — extracted often, never query CTI.
BENIGN_HOSTS = frozenset({
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    'example.com',
    'example.org',
    'example.net',
    'w3.org',
    'schema.org',
    'python.org',
    'pypi.org',
    'npmjs.org',
    'nodejs.org',
    'unicode.org',
    'ietf.org',
    'iana.org',
    'apache.org',
    'gnu.org',
    'ubuntu.com',
    'debian.org',
    'stackoverflow.com',
    'wikipedia.org',
    'mozilla.org',
    'apple.com',
    'android.com',
})

# Only these extracted buckets are sent to abuse.ch CTI APIs by default.
MALWARE_IOC_BUCKETS = ('urls', 'ips', 'discord_webhooks', 'telegram', 'hashes', 'sha256')

# Bare domains stay display-only unless tagged as high-signal (e.g. VirusTotal contacted_*).
# Emails / wallets remain never-queried.


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
    if all(c.isdigit() or c == '.' for c in s) and s.count('.') == 3:
        return None
    return s.split(':')[0]


def is_platform_host(host: str | None) -> bool:
    if not host:
        return False
    h = host.lower()
    if h in PLATFORM_HOSTS:
        return True
    for platform in PLATFORM_HOSTS:
        if h.endswith('.' + platform):
            return True
    return False


def is_benign_host(host: str | None) -> bool:
    if not host:
        return False
    h = host.lower()
    if h in BENIGN_HOSTS:
        return True
    return any(h.endswith('.' + b) for b in BENIGN_HOSTS)


def is_full_url(indicator: str) -> bool:
    s = _norm(indicator)
    return s.startswith('http://') or s.startswith('https://')


def is_hash_indicator(indicator: str) -> bool:
    s = _norm(indicator)
    return len(s) in {32, 40, 64} and all(c in '0123456789abcdef' for c in s)


def is_public_ip_indicator(indicator: str) -> bool:
    s = _norm(indicator)
    if not (all(c.isdigit() or c == '.' for c in s) and s.count('.') == 3):
        return False
    parts = s.split('.')
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o < 0 or o > 255 for o in octets):
        return False
    if octets[0] == 10:
        return False
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return False
    if octets[0] == 192 and octets[1] == 168:
        return False
    if octets[0] == 127 or s in {'0.0.0.0', '255.255.255.255'}:
        return False
    return True


def is_benign_ioc(indicator: str) -> bool:
    s = (indicator or '').strip()
    if not s:
        return True
    host = host_from_indicator(s)
    if is_benign_host(host):
        return True
    if is_full_url(s):
        lu = _norm(s)
        if any(x in lu for x in ('$schema', 'xmlns', 'w3.org', 'schemas.microsoft.com', 'schemas.openxmlformats.org')):
            return True
    return False


def _sources_for_indicator(iocs: dict, bucket: str, indicator: str) -> list[str]:
    details = (iocs or {}).get('ioc_details') or {}
    rows = details.get(bucket) or []
    needle = _norm(indicator)
    out: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if _norm(str(row.get('indicator') or '')) != needle:
            continue
        for src in row.get('sources') or []:
            s = str(src)
            if s and s not in out:
                out.append(s)
    return out


def is_vt_sourced_indicator(iocs: dict, bucket: str, indicator: str) -> bool:
    return any(str(s).startswith('VirusTotal') for s in _sources_for_indicator(iocs, bucket, indicator))


def vt_sourced_domains(iocs: dict) -> list[str]:
    """High-signal domains from VT contacted_* (and hosts derived from contacted URLs)."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in (iocs or {}).get('domains') or []:
        d = _norm(str(raw))
        if not d or d in seen:
            continue
        if is_platform_host(d) or is_benign_host(d) or is_benign_ioc(d):
            continue
        if not is_vt_sourced_indicator(iocs, 'domains', d):
            continue
        seen.add(d)
        out.append(d)
    return out


def select_malware_ioc_candidates(iocs: dict, *, limit: int = 75, include_vt_domains: bool = True) -> list[str]:
    """Return deduplicated IOCs safe to query — malware CTI + optional VT-contacted domains."""
    out: list[str] = []
    seen: set[str] = set()
    for bucket in MALWARE_IOC_BUCKETS:
        for raw in iocs.get(bucket) or []:
            s = (raw or '').strip()
            if not s:
                continue
            key = s.lower()
            if key in seen:
                continue
            if is_benign_ioc(s):
                continue
            seen.add(key)
            out.append(s)
            if len(out) >= limit:
                return out
    if include_vt_domains:
        for domain in vt_sourced_domains(iocs):
            key = domain.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(domain)
            if len(out) >= limit:
                return out
    return out


def should_query_threatfox(indicator: str, *, allow_domain: bool = False) -> tuple[bool, str]:
    """Malware IOC types: full URL, public IP, file hash, webhook/telegram URL; optional high-signal domain."""
    s = (indicator or '').strip()
    if not s:
        return False, 'empty'
    if is_benign_ioc(s):
        return False, 'benign_ioc'

    host = host_from_indicator(s)
    if is_full_url(s):
        if is_platform_host(host):
            return False, 'platform_url'
        return True, 'exact_url'

    if is_hash_indicator(s):
        return True, 'hash'

    if is_public_ip_indicator(s):
        return True, 'public_ip'

    if host and not is_full_url(s):
        if allow_domain and not is_platform_host(host) and not is_benign_host(host):
            return True, 'high_signal_domain'
        return False, 'domain_only_not_queried'

    return False, 'unsupported_indicator'


def should_query_urlhaus(indicator: str) -> tuple[bool, str]:
    """URLHaus URL API: exact malware-delivery URL only."""
    s = (indicator or '').strip()
    if not is_full_url(s):
        return False, 'urlhaus_requires_full_url'
    if is_benign_ioc(s):
        return False, 'benign_ioc'
    host = host_from_indicator(s)
    if is_platform_host(host):
        return False, 'platform_url'
    return True, 'exact_url'


def should_query_urlhaus_host(host: str) -> tuple[bool, str]:
    """URLHaus host API: high-signal domains (VT contacted) only."""
    h = _norm(host)
    if not h or is_full_url(h) or is_public_ip_indicator(h) or is_hash_indicator(h):
        return False, 'not_a_host'
    if is_benign_host(h) or is_benign_ioc(h):
        return False, 'benign_ioc'
    if is_platform_host(h):
        return False, 'platform_host'
    return True, 'high_signal_host'


def threatfox_match_is_exact(indicator: str, match_ioc: str) -> bool:
    return _norm(match_ioc) == _norm(indicator)


def filter_threatfox_matches(indicator: str, matches: list[dict]) -> list[dict]:
    return [m for m in matches if threatfox_match_is_exact(indicator, str(m.get('ioc') or ''))]


def filter_threatfox_found_rows(indicator: str, rows: list[dict]) -> list[dict]:
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


def count_cti_sourced_infra(infrastructure: dict) -> int:
    """Infrastructure rows confirmed by CTI feeds, not local heuristics."""
    cti_sources = {'ThreatFox', 'URLHaus', 'FeodoTracker', 'SSLBL'}
    count = 0
    for rows in (infrastructure or {}).values():
        if not isinstance(rows, list):
            continue
        for row in rows:
            if isinstance(row, dict) and row.get('source') in cti_sources:
                count += 1
    return count


def count_exact_cti_anchors(result: dict) -> dict[str, int | bool]:
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
        if not row.get('found'):
            continue
        ind = str(row.get('indicator') or row.get('url') or row.get('host') or '')
        # Count exact URL hits and high-signal host hits (VT contacted domains)
        if is_full_url(ind) or row.get('indicator_type') in {'domain/host', 'host', 'domain'}:
            exact_uh += 1
    return {
        'vt_malicious': vt_malicious,
        'malwarebazaar_hash_hits': mb_found,
        'exact_threatfox': exact_tf,
        'exact_urlhaus': exact_uh,
        'exact_probable_c2': exact_c2,
        'cti_sourced_infra': count_cti_sourced_infra(result.get('infrastructure') or {}),
        'has_hash_anchor': mb_found > 0 or vt_malicious > 0,
        'has_exact_ioc_anchor': exact_tf > 0 or exact_uh > 0,
    }
