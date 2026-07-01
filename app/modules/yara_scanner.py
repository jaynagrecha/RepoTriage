from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def yara_available() -> bool:
    try:
        import yara  # noqa: F401

        return True
    except Exception:
        return False


def _rules_dir(base_dir: Path) -> Path:
    custom = os.getenv('YARA_RULES_DIR')
    if custom:
        return Path(custom)
    return base_dir / 'data' / 'yara_rules'


def _builtin_rules() -> str:
    return r'''
rule Suspicious_WScript_Dropper {
    meta:
        description = "Windows Script Host dropper patterns"
    strings:
        $w1 = "WScript" nocase
        $w2 = "ActiveXObject" nocase
        $w3 = "Scripting.FileSystemObject" nocase
        $o1 = /_0x[a-fA-F0-9]{4,}/
    condition:
        2 of ($w*) or ($w1 and $o1)
}

rule Suspicious_PowerShell_Encoded {
    strings:
        $a = "-EncodedCommand" nocase
        $b = "FromBase64String" nocase
        $c = "DownloadString" nocase
        $d = "IEX" nocase
    condition:
        2 of them
}

rule Suspicious_PE_AntiAnalysis {
    strings:
        $a = "IsDebuggerPresent" nocase
        $b = "CheckRemoteDebuggerPresent" nocase
        $c = "NtQueryInformationProcess" nocase
    condition:
        any of them
}
'''


def scan_file(path: Path, base_dir: Path) -> dict[str, Any]:
    result: dict[str, Any] = {'engine': 'yara', 'available': yara_available(), 'matches': [], 'rules_loaded': 0}
    if not path.is_file():
        result['error'] = 'file_not_found'
        return result
    if not yara_available():
        result['note'] = 'Install yara-python + libyara in Docker image to enable YARA scanning.'
        return result

    import yara

    rules_paths: list[str] = []
    rules_dir = _rules_dir(base_dir)
    if rules_dir.is_dir():
        rules_paths.extend(str(p) for p in rules_dir.glob('*.yar'))
        rules_paths.extend(str(p) for p in rules_dir.glob('*.yara'))

    compiled = []
    if rules_paths:
        for rp in rules_paths[:50]:
            try:
                compiled.append(yara.compile(filepath=rp))
            except Exception:
                continue
    try:
        compiled.append(yara.compile(source=_builtin_rules()))
    except Exception:
        pass

    if not compiled:
        result['error'] = 'no_rules_loaded'
        return result

    result['rules_loaded'] = len(compiled)
    data = path.read_bytes()
    for rules in compiled:
        try:
            matches = rules.match(data=data)
        except Exception:
            continue
        for match in matches:
            result['matches'].append({
                'rule': match.rule,
                'namespace': match.namespace,
                'tags': list(match.tags or []),
                'meta': dict(match.meta or {}),
                'strings': [f"{s[1]}:{s[2].decode('utf-8', errors='ignore')[:120]}" for s in (match.strings or [])[:8]],
            })
    result['match_count'] = len(result['matches'])
    result['verdict'] = 'malicious' if len(result['matches']) >= 2 else ('suspicious' if result['matches'] else 'clean')
    return result
