from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

try:
    import pefile  # type: ignore
except Exception:
    pefile = None


IMPORT_CATEGORIES: dict[str, tuple[str, str]] = {
    'virtualalloc': ('process_injection', 'Memory allocation for shellcode/injection'),
    'virtualprotect': ('process_injection', 'Memory protection change (RWX pattern)'),
    'writeprocessmemory': ('process_injection', 'Cross-process memory write'),
    'createremotethread': ('process_injection', 'Remote thread creation'),
    'openprocess': ('process_injection', 'Open foreign process handle'),
    'isdebuggerpresent': ('anti_analysis', 'Debugger detection'),
    'checkremotedebuggerpresent': ('anti_analysis', 'Remote debugger check'),
    'internetopenurl': ('network', 'HTTP download capability'),
    'urlmon': ('network', 'URL moniker / download'),
    'wininet': ('network', 'WinINet HTTP client'),
    'regsetvalueex': ('persistence', 'Registry modification'),
    'createservice': ('persistence', 'Service installation'),
    'cryptencrypt': ('crypto', 'Encryption (payload or C2)'),
    'shellexecute': ('execution', 'Launch secondary process'),
    'winexec': ('execution', 'Direct process execution'),
}


def _section_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


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

    categorized: list[dict[str, str]] = []
    for imp in imports:
        for key, (cat, desc) in IMPORT_CATEGORIES.items():
            if key in imp:
                categorized.append({'import': imp, 'category': cat, 'risk': desc})
                break

    packer_hints = []
    if high_entropy:
        packer_hints.append(f'High-entropy sections: {", ".join(high_entropy[:5])} (possible packer/compression)')
    if len(imports) < 5 and any(s['size'] > 50_000 for s in sections):
        packer_hints.append('Very few imports with large sections — common packed malware pattern')
    if not exports and pe.FILE_HEADER.Machine in {0x8664, 0x14C}:
        packer_hints.append('No exports on executable — typical of dropped payload')

    raw = path.read_bytes()[:2_000_000]
    strings_urls = re.findall(r'https?://[^\s\'\"<>\\]{6,200}', raw.decode('utf-8', errors='ignore'))[:25]
    strings_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw.decode('utf-8', errors='ignore'))[:15]

    result.update({
        'imports_total': len(imports),
        'imports_sample': imports[:40],
        'risk_imports': categorized[:25],
        'exports': exports[:20],
        'sections': sections,
        'packer_hints': packer_hints,
        'embedded_urls': strings_urls,
        'embedded_ips': strings_ips,
        'risk_score': min(100, len(categorized) * 8 + len(packer_hints) * 12 + len(strings_urls) * 3),
    })
    return result
