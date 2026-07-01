from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

URL_RE = re.compile(r"(?i)\b(?:https?|hxxps?|hxxp)://[^\s'\"<>\)\]\}]+")
DOMAIN_IN_STRING_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|ru|cn|xyz|top|dev|app|cloud|live|site|online|shop|info|biz|cc|me|tk|ml|ga|cf|zip|mov)\b"
)


def _uniq(items: list[str], limit: int = 100) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in items:
        val = (raw or '').strip().strip('.,;:!?)"]}').strip("'")
        if not val:
            continue
        key = val.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(val)
        if len(out) >= limit:
            break
    return out


def _urls_from_text(text: str) -> list[str]:
    if not text:
        return []
    normalized = text.replace('hxxp://', 'http://').replace('hxxps://', 'https://').replace('[.]', '.')
    return _uniq(URL_RE.findall(normalized))


def _domains_from_urls(urls: list[str]) -> list[str]:
    hosts: list[str] = []
    for url in urls:
        try:
            host = urlparse(url).netloc.split('@')[-1].split(':')[0].lower().strip('.')
            if host and host not in {'localhost', '127.0.0.1'}:
                hosts.append(host)
        except Exception:
            continue
    return _uniq(hosts)


def build_extracted_indicators(report: dict[str, Any]) -> dict[str, Any]:
    universal = report.get('universal') or {}
    typed = report.get('typed_analysis') or {}
    deob = report.get('deobfuscation') or {}
    base_iocs = dict(universal.get('iocs') or {})

    urls: list[str] = list(base_iocs.get('urls') or [])
    domains: list[str] = list(base_iocs.get('domains') or [])
    ips: list[str] = list(base_iocs.get('ips') or [])
    emails: list[str] = list(base_iocs.get('emails') or [])
    discord: list[str] = list(base_iocs.get('discord_webhooks') or [])
    telegram: list[str] = list(base_iocs.get('telegram') or [])
    wallets: list[str] = list(base_iocs.get('wallets') or [])

    sources: dict[str, list[str]] = {
        'file_text': [],
        'deobfuscation': [],
        'script_patterns': [],
        'document_links': [],
        'suspicious_strings': [],
    }

    for url in _urls_from_text(' '.join(universal.get('strings_sample') or [])):
        sources['file_text'].append(url)
        urls.append(url)

    for item in deob.get('recovered') or []:
        preview = f"{item.get('decoded_preview') or ''} {item.get('source_preview') or ''}"
        for url in _urls_from_text(preview):
            sources['deobfuscation'].append(url)
            urls.append(url)

    for item in deob.get('xor_candidates') or []:
        for url in _urls_from_text(item.get('decoded_preview') or ''):
            sources['deobfuscation'].append(url)
            urls.append(url)

    for match in typed.get('pattern_matches') or []:
        if match.get('pattern') == 'network_callback':
            for url in _urls_from_text(match.get('match') or match.get('context') or ''):
                sources['script_patterns'].append(url)
                urls.append(url)

    for link in typed.get('links') or []:
        if isinstance(link, str):
            sources['document_links'].append(link)
            urls.append(link)

    for s in universal.get('suspicious_strings') or []:
        for url in _urls_from_text(s):
            sources['suspicious_strings'].append(url)
            urls.append(url)
        for dom in DOMAIN_IN_STRING_RE.findall(s):
            domains.append(dom.lower())

    urls = _uniq(urls, 80)
    domains = _uniq(domains + _domains_from_urls(urls), 80)
    ips = _uniq(ips, 40)
    emails = _uniq(emails, 40)
    discord = _uniq(discord, 20)
    telegram = _uniq(telegram, 20)
    wallets = _uniq(wallets, 20)

    decoded_artifacts = []
    for item in deob.get('recovered') or []:
        decoded_artifacts.append({
            'method': item.get('method'),
            'preview': (item.get('decoded_preview') or item.get('source_preview') or '')[:500],
            'urls_found': _urls_from_text(item.get('decoded_preview') or ''),
        })

    registry_markers = _uniq([
        s for s in (universal.get('suspicious_strings') or [])
        if 'currentversion\\run' in s.lower() or 'runonce' in s.lower() or 'software\\microsoft' in s.lower()
    ], 10)

    file_paths = _uniq([
        s for s in (universal.get('suspicious_strings') or [])
        if re.search(r'[A-Za-z]:\\[^\s"\']+', s) or s.startswith('%') or '/tmp/' in s
    ], 15)

    counts = {
        'urls': len(urls),
        'domains': len(domains),
        'ips': len(ips),
        'emails': len(emails),
        'discord_webhooks': len(discord),
        'telegram': len(telegram),
        'wallets': len(wallets),
        'decoded_artifacts': len(decoded_artifacts),
    }
    total = sum(counts.values())

    return {
        'total': total,
        'counts': counts,
        'urls': urls,
        'domains': domains,
        'ips': ips,
        'emails': emails,
        'discord_webhooks': discord,
        'telegram': telegram,
        'wallets': wallets,
        'decoded_artifacts': decoded_artifacts,
        'registry_markers': registry_markers,
        'file_paths': file_paths,
        'sources': {k: _uniq(v, 30) for k, v in sources.items() if v},
        'has_network_indicators': bool(urls or domains or ips),
    }
