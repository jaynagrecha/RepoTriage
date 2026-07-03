from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .detection_policy import WEAK_FAMILY_HINTS

_FAMILY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ('asyncrat', re.compile(r'AsyncRAT|AsyncClient|ServerCertificate|GetAsyncKeyState', re.I)),
    ('remcos', re.compile(r'Remcos|remcos[\s_-]?rat|BreakWall', re.I)),
    ('redline', re.compile(r'RedLine|RedLineStealer|redline[\s_-]?stealer', re.I)),
    ('agenttesla', re.compile(r'AgentTesla|Agent[\s_-]?Tesla', re.I)),
    ('formbook', re.compile(r'FormBook|XLoader|Formbook', re.I)),
    ('emotet', re.compile(r'Emotet|epoch[\s_-]?[0-9]|/modules/', re.I)),
    ('qakbot', re.compile(r'QakBot|Qbot|akbot', re.I)),
    ('cobalt_strike', re.compile(r'beacon\.|cobaltstrike|ReflectiveLoader', re.I)),
    ('metasploit', re.compile(r'metasploit|meterpreter|MsfPayload', re.I)),
    ('powershell_dropper', re.compile(r'-EncodedCommand.*DownloadString|DownloadString.*-EncodedCommand', re.I)),
]


def parse_family_indicators(path: Path, *, text: str | None = None) -> dict[str, Any]:
    raw = text if text is not None else path.read_bytes()[:1_500_000].decode('utf-8', errors='ignore')
    matches: list[dict[str, Any]] = []
    for family, pattern in _FAMILY_PATTERNS:
        found = pattern.findall(raw)
        if found:
            matches.append({'family': family, 'hits': len(found), 'sample': found[0][:80] if isinstance(found[0], str) else str(found[0])[:80]})

    strong_matches = [m for m in matches if m.get('family') not in WEAK_FAMILY_HINTS]
    weak_matches = [m for m in matches if m.get('family') in WEAK_FAMILY_HINTS]

    config_blocks: list[dict[str, Any]] = []
    for block in re.findall(r'\{[^{}]{20,800}\}', raw)[:30]:
        if any(k in block.lower() for k in ('host', 'port', 'password', 'mutex', 'key', 'c2', 'server')):
            try:
                parsed = json.loads(block.replace("'", '"'))
                if isinstance(parsed, dict):
                    config_blocks.append({'type': 'json_like', 'keys': list(parsed.keys())[:12]})
            except Exception:
                config_blocks.append({'type': 'kv_block', 'preview': block[:160]})

    primary = strong_matches[0]['family'] if strong_matches else None
    return {
        'primary_family_hint': primary,
        'family_matches': matches,
        'strong_family_matches': strong_matches,
        'weak_family_matches': weak_matches,
        'config_blocks': config_blocks[:8],
        'match_count': len(strong_matches),
        'weak_match_count': len(weak_matches),
    }
