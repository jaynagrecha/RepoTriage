from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

try:
    import pefile  # type: ignore
except Exception:
    pefile = None


# Categories we scan for (shown in UI as "scanned", not "detected")
SCAN_CATEGORIES = ('process_injection', 'anti_analysis', 'network', 'persistence', 'execution', 'crypto')

IMPORT_RULES: list[tuple[str, str, str, str]] = [
    # key, category, severity, description
    ('writeprocessmemory', 'process_injection', 'high', 'Cross-process memory write'),
    ('createremotethread', 'process_injection', 'high', 'Remote thread creation'),
    ('ntcreatethreadex', 'process_injection', 'high', 'Native remote thread creation'),
    ('openprocess', 'process_injection', 'high', 'Open foreign process handle'),
    ('virtualalloc', 'process_injection', 'informational', 'Memory allocation (common in benign DLLs; suspicious with shellcode/injection chain)'),
    ('virtualprotect', 'process_injection', 'informational', 'Memory protection change (common; suspicious with RWX staging)'),
    ('isdebuggerpresent', 'anti_analysis', 'high', 'Debugger detection'),
    ('checkremotedebuggerpresent', 'anti_analysis', 'high', 'Remote debugger check'),
    ('ntqueryinformationprocess', 'anti_analysis', 'high', 'Process debug port query'),
    ('internetopenurl', 'network', 'high', 'HTTP download capability'),
    ('urlmon', 'network', 'high', 'URL moniker / download'),
    ('wininet', 'network', 'high', 'WinINet HTTP client'),
    ('winhttp', 'network', 'high', 'WinHTTP client'),
    ('regsetvalueex', 'persistence', 'high', 'Registry modification'),
    ('createservice', 'persistence', 'high', 'Service installation'),
    ('cryptencrypt', 'crypto', 'informational', 'Encryption API'),
    ('shellexecute', 'execution', 'high', 'Launch secondary process'),
    ('winexec', 'execution', 'high', 'Direct process execution'),
]

STRONG_INJECTION_MARKERS = {
    'writeprocessmemory', 'createremotethread', 'ntcreatethreadex', 'openprocess', 'queueuserapc',
}


def _section_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _classify_imports(imports: list[str], *, packer_hints: list[str]) -> dict[str, Any]:
    imports_blob = ' '.join(imports).lower()
    has_strong_injection = any(marker in imports_blob for marker in STRONG_INJECTION_MARKERS)
    has_packer_signal = bool(packer_hints)

    high_risk: list[dict[str, str]] = []
    informational: list[dict[str, str]] = []
    by_category: dict[str, list[str]] = defaultdict(list)

    seen: set[str] = set()
    for imp in imports:
        imp_l = imp.lower()
        for key, category, severity, desc in IMPORT_RULES:
            if key not in imp_l or imp_l in seen:
                continue
            seen.add(imp_l)
            effective = severity
            if key in {'virtualalloc', 'virtualprotect'} and not (has_strong_injection or has_packer_signal):
                effective = 'informational'
            entry = {
                'import': imp,
                'category': category,
                'severity': effective,
                'risk': desc,
            }
            if effective == 'high':
                high_risk.append(entry)
                by_category[category].append(imp)
            else:
                informational.append(entry)
                if has_strong_injection or has_packer_signal:
                    by_category[category].append(imp)
            break

    categories_detected = {cat: by_category.get(cat, []) for cat in SCAN_CATEGORIES if by_category.get(cat)}
    categories_not_detected = [cat for cat in SCAN_CATEGORIES if cat not in categories_detected]

    return {
        'high_risk_imports': high_risk[:25],
        'informational_imports': informational[:25],
        'risk_imports': high_risk[:25],
        'categories_detected': categories_detected,
        'categories_not_detected': categories_not_detected,
        'categories_scanned': list(SCAN_CATEGORIES),
        'has_strong_injection_chain': has_strong_injection,
    }


def analyze_pe_deep(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {'format': 'pe', 'available': pefile is not None}
    if pefile is None:
        result['note'] = 'pefile not available'
        return result

    try:
        pe = pefile.PE(str(path), fast_load=False)
    except Exception as exc:
        result['error'] = exc.__class__.__name__
        return result

    imports: list[str] = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = (entry.dll or b'').decode('utf-8', errors='ignore').lower()
            for imp in entry.imports[:120]:
                name = imp.name.decode('utf-8', errors='ignore') if imp.name else f'ord_{imp.ordinal}'
                imports.append(f'{dll}:{name.lower()}')

    exports: list[str] = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols[:40]:
            if sym.name:
                exports.append(sym.name.decode('utf-8', errors='ignore'))

    sections = []
    high_entropy = []
    for sec in pe.sections[:25]:
        name = sec.Name.decode('utf-8', errors='ignore').strip('\x00') or 'unknown'
        raw = sec.get_data()[:500_000]
        ent = round(_section_entropy(raw), 2)
        item = {'name': name, 'size': sec.SizeOfRawData, 'entropy': ent, 'characteristics': hex(sec.Characteristics)}
        sections.append(item)
        if ent >= 7.2 and sec.SizeOfRawData > 4096:
            high_entropy.append(name)

    packer_hints = []
    if high_entropy:
        packer_hints.append(f'High-entropy sections: {", ".join(high_entropy[:5])} (possible packer/compression)')
    if len(imports) < 5 and any(s['size'] > 50_000 for s in sections):
        packer_hints.append('Very few imports with large sections — common packed malware pattern')
    if not exports and pe.FILE_HEADER.Machine in {0x8664, 0x14C}:
        packer_hints.append('No exports on executable — typical of dropped payload')

    classified = _classify_imports(imports, packer_hints=packer_hints)

    raw = path.read_bytes()[:2_000_000]
    strings_urls = re.findall(r'https?://[^\s\'\"<>\\]{6,200}', raw.decode('utf-8', errors='ignore'))[:25]
    strings_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw.decode('utf-8', errors='ignore'))[:15]

    high_count = len(classified['high_risk_imports'])
    result.update({
        'imports_total': len(imports),
        'imports_sample': imports[:40],
        **classified,
        'exports': exports[:20],
        'sections': sections,
        'packer_hints': packer_hints,
        'embedded_urls': strings_urls,
        'embedded_ips': strings_ips,
        'risk_score': min(100, high_count * 15 + len(packer_hints) * 12 + len(strings_urls) * 3),
    })
    return result
