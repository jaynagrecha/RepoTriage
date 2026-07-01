from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from ..ioc_extractor import extract_iocs_from_file


SUSPICIOUS_STRINGS = re.compile(
    r'(powershell|cmd\.exe|rundll32|regsvr32|mshta|wscript|cscript|schtasks|bitsadmin|certutil|'
    r'virtualalloc|writeprocessmemory|createremotethread|ntqueryinformationprocess|isdebuggerpresent|'
    r'shellcode|reflective|inject|downloadstring|invoke-expression|iex\b|frombase64string|'
    r'autoit|mimikatz|lazagne|bloodhound|cobalt|metasploit|reverse_tcp|bind_tcp|'
    r'ransom|encrypt|decrypt|wallet|clipboard|keylog|exfil|beacon|c2|botnet)',
    re.I,
)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_strings(data: bytes, min_len: int = 5, limit: int = 500) -> list[str]:
    ascii_strings = re.findall(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}', data)
    wide_strings = re.findall((rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + rb',}'), data)
    out: list[str] = []
    seen: set[str] = set()
    for raw in ascii_strings + wide_strings:
        try:
            text = raw.decode('utf-16le' if b'\x00' in raw[:2] else 'utf-8', errors='ignore').strip()
        except Exception:
            continue
        if len(text) < min_len or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def analyze_universal(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    size = len(data)
    strings = extract_strings(data)
    suspicious = [s for s in strings if SUSPICIOUS_STRINGS.search(s)][:50]
    iocs = extract_iocs_from_file(str(path))
    return {
        'size_bytes': size,
        'entropy': shannon_entropy(data[:65536]),
        'magic_hex': data[:16].hex(),
        'strings_total': len(strings),
        'strings_sample': strings[:40],
        'suspicious_strings': suspicious,
        'iocs': iocs,
    }
