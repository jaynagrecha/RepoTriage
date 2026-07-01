from __future__ import annotations

from typing import Any


def export_blocklist(job_result: dict[str, Any], fmt: str = 'plain') -> str:
    iocs = job_result.get('iocs') or {}
    urls = iocs.get('urls') or []
    domains = iocs.get('domains') or []
    ips = iocs.get('ips') or []
    hashes = []
    for f in job_result.get('files') or []:
        if f.get('sha256'):
            hashes.append(f['sha256'])

    if fmt == 'suricata':
        lines = []
        for ip in ips:
            lines.append(f'alert ip any any -> {ip} any (msg:"RepoTriage block IP {ip}"; sid:9000001; rev:1;)')
        for domain in domains:
            lines.append(f'alert dns any any -> any any (msg:"RepoTriage block {domain}"; dns.query; content:"{domain}"; nocase; sid:9000002; rev:1;)')
        return '\n'.join(lines)
    if fmt == 'hosts':
        return '\n'.join(f'0.0.0.0 {d}' for d in domains)
    lines = ['# RepoTriage blocklist']
    lines.extend(f'url:{u}' for u in urls)
    lines.extend(f'domain:{d}' for d in domains)
    lines.extend(f'ip:{ip}' for ip in ips)
    lines.extend(f'sha256:{h}' for h in hashes)
    return '\n'.join(lines)


def job_diff(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    files_a = {f.get('sha256'): f for f in (a.get('files') or []) if f.get('sha256')}
    files_b = {f.get('sha256'): f for f in (b.get('files') or []) if f.get('sha256')}
    iocs_a = set((a.get('iocs') or {}).get('urls') or [])
    iocs_b = set((b.get('iocs') or {}).get('urls') or [])

    return {
        'files_added': [files_b[h] for h in files_b.keys() - files_a.keys()],
        'files_removed': [files_a[h] for h in files_a.keys() - files_b.keys()],
        'files_common': len(files_a.keys() & files_b.keys()),
        'new_urls': sorted(iocs_b - iocs_a),
        'removed_urls': sorted(iocs_a - iocs_b),
        'vt_root_a': (a.get('vt') or {}).get('verdict'),
        'vt_root_b': (b.get('vt') or {}).get('verdict'),
    }
