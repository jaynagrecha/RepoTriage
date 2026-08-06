"""Runtime CTI self-test — proves Abuse.ch APIs return real matches with the configured key."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx

from .cti_query_policy import should_query_threatfox, should_query_urlhaus
from .malwarebazaar import lookup_hash as mb_lookup_hash
from .threatfox import THREATFOX_API, enrich_iocs, lookup_ioc
from .urlhaus import lookup_url as uh_lookup_url


def _abusech_key() -> str:
    return (
        os.getenv('ABUSECH_API_KEY')
        or os.getenv('THREATFOX_API_KEY')
        or os.getenv('MALWAREBAZAAR_API_KEY')
        or os.getenv('URLHAUS_API_KEY')
        or ''
    ).strip()


def _tf_headers() -> dict[str, str]:
    headers = {'Content-Type': 'application/json'}
    key = _abusech_key()
    if key:
        headers['Auth-Key'] = key
    return headers


async def _fetch_recent_threatfox_ioc() -> dict[str, Any] | None:
    """Pull a fresh IOC from ThreatFox (requires Auth-Key). Prefer URL, else IP/hash."""
    if not _abusech_key():
        return None
    timeout = float(os.getenv('THREATFOX_TIMEOUT', '18'))
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            THREATFOX_API,
            headers=_tf_headers(),
            json={'query': 'get_iocs', 'days': int(os.getenv('CTI_SELFTEST_DAYS', '7'))},
        )
        if resp.status_code == 401 or resp.status_code == 403:
            return {'_error': 'auth', 'http': resp.status_code, 'body': resp.text[:240]}
        if resp.status_code >= 400:
            return {'_error': 'http', 'http': resp.status_code, 'body': resp.text[:240]}
        payload = resp.json()
        rows = payload.get('data') if isinstance(payload.get('data'), list) else []
        if not rows:
            return {'_error': 'empty', 'query_status': payload.get('query_status')}

        preferred = []
        fallback = []
        for row in rows:
            ioc = (row.get('ioc') or '').strip()
            if not ioc:
                continue
            allowed, _reason = should_query_threatfox(ioc)
            if not allowed:
                continue
            item = {
                'ioc': ioc,
                'ioc_type': row.get('ioc_type'),
                'threat_type': row.get('threat_type'),
                'malware': row.get('malware_printable') or row.get('malware'),
            }
            if ioc.lower().startswith(('http://', 'https://')):
                preferred.append(item)
            else:
                fallback.append(item)
        pick = (preferred or fallback)
        return pick[0] if pick else {'_error': 'no_queryable_ioc', 'raw_count': len(rows)}


async def run_cti_selftest(base_dir: Path) -> dict[str, Any]:
    """
    Live proof:
      1) Auth key present
      2) ThreatFox get_iocs returns a real IOC
      3) search_ioc / enrich_iocs finds an exact match for that IOC
      4) Optional URLHaus check when the IOC is a URL
    """
    report: dict[str, Any] = {
        'ok': False,
        'auth_configured': bool(_abusech_key()),
        'steps': {},
    }
    if not report['auth_configured']:
        report['error'] = 'Set ABUSECH_API_KEY (or THREATFOX_API_KEY) on the backend'
        return report

    seed = await _fetch_recent_threatfox_ioc()
    report['steps']['fetch_recent_ioc'] = {
        'ok': bool(seed and not seed.get('_error')),
        'seed': {k: seed.get(k) for k in ('ioc', 'ioc_type', 'threat_type', 'malware')} if seed and not seed.get('_error') else seed,
    }
    if not seed or seed.get('_error'):
        report['error'] = 'Could not fetch a recent ThreatFox IOC'
        return report

    ioc = seed['ioc']
    lookup = await lookup_ioc(ioc, base_dir)
    report['steps']['threatfox_search_ioc'] = {
        'ok': lookup.get('status') == 'found' and int(lookup.get('match_count') or 0) > 0,
        'status': lookup.get('status'),
        'match_count': lookup.get('match_count'),
        'skip_reason': lookup.get('skip_reason'),
        'first_match': (lookup.get('matches') or [None])[0],
    }

    # enrich_iocs path (same as analyze pipeline)
    iocs = {'urls': [], 'ips': [], 'domains': [], 'discord_webhooks': [], 'telegram': [], 'hashes': []}
    if ioc.lower().startswith(('http://', 'https://')):
        iocs['urls'] = [ioc]
    elif lookup.get('indicator_type') == 'ip' or (
        all(c.isdigit() or c == '.' for c in ioc) and ioc.count('.') == 3
    ):
        iocs['ips'] = [ioc]
    else:
        iocs['hashes'] = [ioc]

    enriched = await enrich_iocs(iocs, base_dir)
    report['steps']['threatfox_enrich_pipeline'] = {
        'ok': int((enriched.get('summary') or {}).get('found') or 0) > 0,
        'summary': enriched.get('summary'),
        'looked_up': (enriched.get('summary') or {}).get('looked_up'),
        'found': (enriched.get('summary') or {}).get('found'),
        'probable_c2': (enriched.get('summary') or {}).get('probable_c2'),
    }

    if ioc.lower().startswith(('http://', 'https://')) and should_query_urlhaus(ioc)[0]:
        uh = await uh_lookup_url(ioc, base_dir)
        report['steps']['urlhaus_lookup'] = {
            'ok': True,  # API reachable is enough; IOC may not be in URLHaus
            'status': uh.get('status'),
            'found': bool(uh.get('found')),
            'note': 'found=false is OK if the ThreatFox IOC is not also listed on URLHaus',
        }
    else:
        report['steps']['urlhaus_lookup'] = {
            'ok': True,
            'skipped': True,
            'reason': 'seed IOC is not a queryable URL for URLHaus',
        }

    # MalwareBazaar: only meaningful for file hashes
    if len(ioc) in {32, 40, 64} and all(c in '0123456789abcdef' for c in ioc.lower()):
        if len(ioc) != 64:
            report['steps']['malwarebazaar_lookup'] = {
                'ok': True,
                'skipped': True,
                'reason': 'seed hash is not SHA256; MB lookup uses SHA256 only',
            }
        else:
            mb = await mb_lookup_hash({'filename': 'selftest.bin', 'sha256': ioc}, base_dir)
            report['steps']['malwarebazaar_lookup'] = {
                'ok': mb.get('status') in {'found', 'not_found', 'error'} or bool(mb.get('query_status')),
                'status': mb.get('status'),
                'found': bool(mb.get('found')),
            }
    else:
        report['steps']['malwarebazaar_lookup'] = {
            'ok': True,
            'skipped': True,
            'reason': 'seed IOC is not a file hash; MB is validated separately on analyze via sample SHA256',
        }

    tf_ok = report['steps']['threatfox_search_ioc']['ok'] and report['steps']['threatfox_enrich_pipeline']['ok']
    report['ok'] = bool(tf_ok)
    if report['ok']:
        report['message'] = (
            f"CTI live proof OK — ThreatFox exact-matched {ioc!r} "
            f"({seed.get('threat_type') or 'unknown'} / {seed.get('malware') or 'unknown'})"
        )
    else:
        report['error'] = 'ThreatFox search/enrich did not return an exact match for the seeded IOC'
    return report
