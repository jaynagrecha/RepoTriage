from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .static_analysis.script_analyzer import analyze_script


NETWORK_PATTERNS = [
    ('http_request', re.compile(r'https?://[^\s\'\"]+', re.I)),
    ('download', re.compile(r'(?:downloadstring|downloadfile|invoke-webrequest|XMLHTTP|WinHttp)', re.I)),
    ('shell', re.compile(r'(?:cmd\.exe|powershell|wscript|cscript|mshta|rundll32)', re.I)),
    ('persistence', re.compile(r'(?:CurrentVersion\\Run|schtasks|RegWrite)', re.I)),
]


def run_sandbox_lite(path: Path, *, filename: str | None = None) -> dict[str, Any]:
    """Render-safe behavioral analysis without executing malware binaries.

    For scripts: pattern + flow analysis only.
    For binaries: import/string behavior summary (no execution).
    """
    ext = (Path(filename or path.name).suffix or '').lower()
    text = path.read_bytes()[:2_000_000].decode('utf-8', errors='ignore')
    result: dict[str, Any] = {
        'engine': 'repotriage_sandbox_lite',
        'mode': 'static_behavioral',
        'note': 'Render-safe analysis — scripts analysed statically; PE/ELF binaries are not executed.',
        'behaviors': [],
        'network_indicators': [],
        'verdict': 'clean',
    }

    if ext in {'.js', '.jse', '.vbs', '.vbe', '.wsf', '.ps1', '.bat', '.cmd', '.hta'} or 'ActiveXObject' in text:
        script = analyze_script(path)
        result['mode'] = 'script_behavioral'
        result['script'] = {
            'language': script.get('language'),
            'logic_summary': script.get('logic_summary'),
            'pattern_matches': (script.get('pattern_matches') or [])[:20],
        }
        for label, pattern in NETWORK_PATTERNS:
            if pattern.search(text):
                result['behaviors'].append(label)
        result['network_indicators'] = script.get('links') or []
        if len(result['behaviors']) >= 2 or script.get('logic_summary'):
            result['verdict'] = 'malicious' if any(x in result['behaviors'] for x in ('download', 'shell')) else 'suspicious'
        return result

    suspicious = []
    if re.search(r'IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess', text, re.I):
        suspicious.append('anti_debug')
    if re.search(r'WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx', text, re.I):
        suspicious.append('process_injection')
    if re.search(r'https?://', text, re.I):
        suspicious.append('embedded_urls')
        result['network_indicators'] = re.findall(r'https?://[^\s\'\"<>]+', text)[:20]
    result['behaviors'] = suspicious
    if suspicious:
        result['verdict'] = 'suspicious'
    return result
