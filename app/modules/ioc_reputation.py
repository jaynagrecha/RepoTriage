from __future__ import annotations

import os
from typing import Any

import httpx


async def enrich_url_vt(url: str, base_dir) -> dict[str, Any]:
    api_key = os.getenv('VT_API_KEY', '').strip()
    if not api_key:
        return {'status': 'not_configured', 'url': url}
    headers = {'x-apikey': api_key}
    endpoint = f'https://www.virustotal.com/api/v3/urls/{_vt_url_id(url)}'
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(endpoint, headers=headers)
        if resp.status_code == 404:
            submit = await client.post('https://www.virustotal.com/api/v3/urls', headers=headers, data={'url': url})
            if submit.status_code >= 400:
                return {'status': 'submit_failed', 'url': url, 'http': submit.status_code}
            analysis_id = (submit.json().get('data') or {}).get('id')
            return {'status': 'submitted', 'url': url, 'analysis_id': analysis_id}
        if resp.status_code >= 400:
            return {'status': 'error', 'url': url, 'http': resp.status_code}
        stats = (resp.json().get('data') or {}).get('attributes', {}).get('last_analysis_stats') or {}
        return {
            'status': 'found',
            'url': url,
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
        }


def _vt_url_id(url: str) -> str:
    import base64

    return base64.urlsafe_b64encode(url.encode()).decode().strip('=')


async def enrich_indicators(indicators: dict[str, Any], base_dir, limit: int = 15) -> dict[str, Any]:
    urls = (indicators.get('urls') or [])[:limit]
    results = []
    for url in urls:
        try:
            results.append(await enrich_url_vt(url, base_dir))
        except Exception as exc:
            results.append({'status': 'error', 'url': url, 'error': exc.__class__.__name__})
    malicious = sum(1 for r in results if (r.get('malicious') or 0) > 0)
    return {'looked_up': len(results), 'malicious_urls': malicious, 'results': results}
