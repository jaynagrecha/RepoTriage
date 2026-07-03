from __future__ import annotations

from pathlib import Path
from typing import Any

from .pe_deep import analyze_pe_deep
from .script_deep import analyze_script_deep


SCRIPT_EXTS = {'.js', '.jse', '.vbs', '.vbe', '.wsf', '.ps1', '.psm1', '.bat', '.cmd', '.hta', '.py', '.sh'}
PE_EXTS = {'.exe', '.dll', '.scr', '.sys', '.ocx', '.cpl'}


def _compute_delta(static: dict[str, Any] | None, deep: dict[str, Any]) -> dict[str, Any]:
    static_ind = (static or {}).get('extracted_indicators') or {}
    static_urls = set(static_ind.get('urls') or [])
    static_domains = set(static_ind.get('domains') or [])

    deep_urls = set(deep.get('c2_urls') or deep.get('embedded_urls') or [])
    deep_domains = set(deep.get('c2_domains') or [])

    pe = deep.get('pe') or {}
    script = deep.get('script') or {}

    exclusive: list[dict[str, str]] = []

    for url in sorted(deep_urls - static_urls)[:10]:
        exclusive.append({'type': 'url', 'value': url, 'source': 'deep_pe_strings' if pe else 'deep_script_chain'})
    for domain in sorted(deep_domains - static_domains)[:10]:
        if '.' in domain and not domain.endswith('.post') and domain.count('.') >= 1:
            exclusive.append({'type': 'domain', 'value': domain, 'source': 'deep_script_chain'})

    for hint in pe.get('packer_hints') or []:
        exclusive.append({'type': 'packer', 'value': hint, 'source': 'pe_deep'})
    for risk in pe.get('high_risk_imports') or pe.get('risk_imports') or []:
        exclusive.append({'type': 'risk_import', 'value': risk.get('import', ''), 'source': risk.get('category', 'pe')})
    for info in pe.get('informational_imports') or []:
        exclusive.append({'type': 'info_import', 'value': info.get('import', ''), 'source': 'informational_pe'})
    for phase in script.get('kill_chain_phases') or []:
        exclusive.append({'type': 'kill_chain', 'value': phase.get('label', ''), 'source': phase.get('phase', '')})
    for cmd in script.get('commands_reconstructed') or []:
        if cmd not in str((static or {}).get('typed_analysis') or {}):
            exclusive.append({'type': 'command', 'value': cmd[:200], 'source': 'execution_chain'})

    return {
        'exclusive_findings': exclusive[:30],
        'exclusive_count': len(exclusive),
        'new_urls': sorted(deep_urls - static_urls),
        'new_domains': sorted(deep_domains - static_domains),
    }


def run_deep_exclusive(path: Path, *, filename: str | None = None, static: dict[str, Any] | None = None) -> dict[str, Any]:
    ext = (Path(filename or path.name).suffix or '').lower()
    raw = path.read_bytes()[:4096]
    text_hint = raw.decode('utf-8', errors='ignore').lower()

    result: dict[str, Any] = {'engine': 'repotriage_deep_v1'}

    if ext in SCRIPT_EXTS or any(x in text_hint for x in ('powershell', 'wscript', 'cmd.exe', 'activexobject')):
        result['script'] = analyze_script_deep(path, filename=filename)
        result['primary_mode'] = 'script_deep'
    elif ext in PE_EXTS or raw[:2] == b'MZ':
        result['pe'] = analyze_pe_deep(path)
        result['primary_mode'] = 'pe_deep'
    else:
        result['script'] = analyze_script_deep(path, filename=filename)
        result['pe'] = analyze_pe_deep(path) if raw[:2] == b'MZ' else {}
        result['primary_mode'] = 'generic_deep'

    result['delta'] = _compute_delta(
        static,
        {
            **(result.get('script') or {}),
            **(result.get('pe') or {}),
        },
    )
    return result
