from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any


SCRIPT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ('powershell_download', re.compile(r'(?:downloadstring|downloadfile|invoke-webrequest|curl\s|wget\s|iwr\b|start-bitstransfer)', re.I)),
    ('powershell_exec', re.compile(r'(?:invoke-expression|iex\b|start-process|&\s*\$)', re.I)),
    ('cmd_exec', re.compile(r'(?:cmd\.exe|/c\s|powershell\s+-|wscript|cscript|mshta|rundll32|regsvr32)', re.I)),
    ('js_eval', re.compile(r'(?:eval\s*\(|Function\s*\(|document\.write|atob\s*\(|fromCharCode)', re.I)),
    ('vbs_exec', re.compile(r'(?:CreateObject\s*\(|WScript\.Shell|Shell\.Application|Execute\s*\()', re.I)),
    ('python_exec', re.compile(r'(?:exec\s*\(|eval\s*\(|subprocess|os\.system|__import__)', re.I)),
    ('network_callback', re.compile(r'https?://[^\s\'"]+', re.I)),
    ('persistence', re.compile(r'(?:schtasks|reg\s+add|RunOnce|Startup|CurrentVersion\\Run)', re.I)),
    ('obfuscation', re.compile(r'(?:base64|frombase64|xor|chr\s*\(|String\.fromCharCode|-EncodedCommand)', re.I)),
    ('credential_theft', re.compile(r'(?:mimikatz|sekurlsa|lsass|samdump|credential|password)', re.I)),
]


def _line_context(text: str, match: re.Match[str], radius: int = 1) -> str:
    lines = text.splitlines()
    idx = text[: match.start()].count('\n')
    start = max(0, idx - radius)
    end = min(len(lines), idx + radius + 1)
    return '\n'.join(lines[start:end])[:500]


def _extract_functions(text: str, language: str) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    patterns: list[tuple[str, re.Pattern[str]]] = []
    if language in {'python'}:
        patterns = [('function', re.compile(r'^\s*def\s+([A-Za-z_][\w]*)\s*\(', re.M))]
    elif language in {'javascript', 'js'}:
        patterns = [('function', re.compile(r'function\s+([A-Za-z_$][\w$]*)\s*\(', re.M)), ('arrow', re.compile(r'(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>', re.M))]
    elif language in {'powershell', 'ps1'}:
        patterns = [('function', re.compile(r'function\s+([A-Za-z_-][\w-]*)\s*\{', re.M))]
    elif language in {'vbscript', 'vbs'}:
        patterns = [('sub', re.compile(r'^\s*(?:Sub|Function)\s+([A-Za-z_][\w_]*)', re.I | re.M))]
    elif language in {'shell', 'sh', 'bash'}:
        patterns = [('function', re.compile(r'^\s*([A-Za-z_][\w]*)\s*\(\)\s*\{', re.M))]
    for kind, pattern in patterns:
        for match in pattern.finditer(text):
            name = match.group(1)
            start = match.start()
            snippet = text[start:start + 1200]
            logic = []
            for label, rx in SCRIPT_PATTERNS:
                if rx.search(snippet):
                    logic.append(label)
            functions.append({
                'name': name,
                'kind': kind,
                'offset': start,
                'logic_tags': sorted(set(logic)),
                'snippet_preview': snippet[:400],
            })
            if len(functions) >= 40:
                return functions
    return functions


def detect_script_language(path: Path, text: str) -> str:
    ext = path.suffix.lower().lstrip('.')
    mapping = {
        'js': 'javascript', 'jsx': 'javascript', 'mjs': 'javascript', 'ts': 'typescript',
        'ps1': 'powershell', 'psm1': 'powershell', 'psd1': 'powershell',
        'vbs': 'vbscript', 'vbe': 'vbscript', 'wsf': 'vbscript',
        'bat': 'batch', 'cmd': 'batch', 'py': 'python', 'php': 'php', 'rb': 'ruby',
        'sh': 'shell', 'bash': 'shell', 'pl': 'perl', 'lua': 'lua', 'hta': 'hta',
    }
    if ext in mapping:
        return mapping[ext]
    if text.startswith('#!'):
        shebang = text.splitlines()[0].lower()
        if 'python' in shebang:
            return 'python'
        if 'bash' in shebang or 'sh' in shebang:
            return 'shell'
        if 'pwsh' in shebang or 'powershell' in shebang:
            return 'powershell'
    if 'function' in text and 'WScript' in text and ('_0x' in text or 'ActiveXObject' in text or 'eval(' in text):
        return 'javascript'
    if 'function' in text and 'WScript' in text:
        return 'vbscript'
    if 'Invoke-Expression' in text or '$' in text:
        return 'powershell'
    return ext or 'script'


def analyze_script(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    text = raw.decode('utf-8', errors='ignore')
    language = detect_script_language(path, text)
    matches: list[dict[str, Any]] = []
    for label, pattern in SCRIPT_PATTERNS:
        for match in pattern.finditer(text):
            matches.append({
                'pattern': label,
                'match': match.group(0)[:200],
                'context': _line_context(text, match),
            })
            if len(matches) >= 60:
                break
    functions = _extract_functions(text, language)
    line_count = text.count('\n') + 1
    logic_summary = _summarize_script_logic(matches, functions)
    if re.search(r'_0x[a-f0-9]{3,}', text, re.I):
        logic_summary.append('Uses hex-variable obfuscation (_0x…) typical of packed JavaScript malware')
    if 'ActiveXObject' in text or 'WScript' in text:
        logic_summary.append('Targets Windows Script Host via ActiveXObject/WScript — often used in document-themed droppers')
    if 'fromCharCode' in text or 'charCodeAt' in text:
        logic_summary.append('Builds strings dynamically to evade static scanners')
    return {
        'language': language,
        'line_count': line_count,
        'char_count': len(text),
        'pattern_matches': matches[:60],
        'functions': functions,
        'logic_summary': logic_summary,
    }


def _summarize_script_logic(matches: list[dict[str, Any]], functions: list[dict[str, Any]]) -> list[str]:
    tags = {m['pattern'] for m in matches}
    for fn in functions:
        tags.update(fn.get('logic_tags') or [])
    summaries = []
    mapping = {
        'powershell_download': 'Downloads remote content via PowerShell/web primitives',
        'powershell_exec': 'Executes dynamic PowerShell commands or expressions',
        'cmd_exec': 'Spawns shell/interpreter execution chains',
        'js_eval': 'Uses dynamic JavaScript evaluation or decoding',
        'vbs_exec': 'Uses VBScript automation objects for execution',
        'python_exec': 'Uses Python dynamic execution or subprocess spawning',
        'network_callback': 'Contains hard-coded network callback URLs',
        'persistence': 'Contains persistence or autorun registry/task patterns',
        'obfuscation': 'Contains obfuscation or encoding primitives',
        'credential_theft': 'References credential theft or secrets harvesting',
    }
    for tag in sorted(tags):
        if tag in mapping:
            summaries.append(mapping[tag])
    return summaries[:20]
