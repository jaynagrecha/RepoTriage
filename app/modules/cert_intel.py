from __future__ import annotations

import re
from typing import Any

import httpx


_DOMAIN_RE = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$', re.I)


async def lookup_crtsh(domain: str, limit: int = 5) -> dict[str, Any]:
    domain = domain.strip().lower().rstrip('.')
    if not _DOMAIN_RE.match(domain):
        return {'domain': domain, 'status': 'invalid_domain'}
    url = f'https://crt.sh/?q={domain}&output=json'
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url)
            if resp.status_code >= 400:
                return {'domain': domain, 'status': 'error', 'http': resp.status_code}
            rows = resp.json()
            if not isinstance(rows, list):
                return {'domain': domain, 'status': 'empty'}
            certs = []
            seen: set[str] = set()
            for row in rows[:50]:
                name = (row.get('common_name') or row.get('name_value') or '').split('\n')[0].strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                certs.append({
                    'common_name': name,
                    'issuer': row.get('issuer_name'),
                    'not_before': row.get('not_before'),
                    'not_after': row.get('not_after'),
                })
                if len(certs) >= limit:
                    break
            return {'domain': domain, 'status': 'ok', 'cert_count': len(certs), 'certificates': certs}
    except Exception as exc:
        return {'domain': domain, 'status': 'error', 'error': exc.__class__.__name__}


async def enrich_domains(domains: list[str], limit: int = 8) -> dict[str, Any]:
    unique = []
    for d in domains:
        d = str(d or '').strip().lower()
        if d and d not in unique:
            unique.append(d)
    results = []
    for domain in unique[:limit]:
        results.append(await lookup_crtsh(domain))
    return {'looked_up': len(results), 'results': results}
