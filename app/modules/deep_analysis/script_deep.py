from __future__ import annotations

import re
from pathlib import Path
from typing import Any


PHASE_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ('initial_access', 'User execution / script launch', re.compile(r'(?:start\s|wscript|cscript|mshta|powershell|cmd\.exe)', re.I)),
    ('download', 'Payload or second-stage download', re.compile(r'(?:downloadstring|downloadfile|invoke-webrequest|XMLHTTP|WinHttp|curl|wget|bitsadmin)', re.I)),
    ('decode', 'De-obfuscation / decoding', re.compile(r'(?:frombase64|base64|xor|chr\s*\(|fromcharcode|decode|decrypt)', re.I)),
    ('execute', 'In-memory or secondary execution', re.compile(r'(?:iex\b|invoke-expression|eval\s*\(|exec\s*\(|start-process|shell\.application)', re.I)),
    ('persistence', 'Persistence mechanism', re.compile(r'(?:CurrentVersion\\Run|schtasks|reg\s+add|RunOnce|Startup)', re.I)),
    ('discovery', 'Environment / host discovery', re.compile(r'(?:get-wmiobject|whoami|hostname|ipconfig|systeminfo)', re.I)),
    ('exfil', 'Data exfiltration channel', re.compile(r'(?:discord\.com/api/webhooks|api\.telegram\.org|pastebin|ngrok)', re.I)),
]


def _reconstruct_commands(text: str) -> list[str]:
    commands: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('::') or line.startswith('#'):
            continue
        if any(x in line.lower() for x in ('powershell', 'cmd', 'wscript', 'curl', 'http', 'reg ', 'schtasks', 'start ', 'rundll32', 'mshta')):
            commands.append(line[:300])
        if len(commands) >= 15:
            break
    return commands


def analyze_script_deep(path: Path, *, filename: str | None = None) -> dict[str, Any]:
    raw = path.read_bytes()[:2_000_000]
    text = raw.decode('utf-8', errors='ignore')
    ext = (Path(filename or path.name).suffix or '').lower()

    phases: list[dict[str, str]] = []
    for phase_id, label, pattern in PHASE_PATTERNS:
        if pattern.search(text):
            phases.append({'phase': phase_id, 'label': label, 'detected': 'yes'})

    obfuscation_score = 0
    for marker in ('base64', '-encodedcommand', 'fromcharcode', 'xor', 'chr(', 'replace(', '\\x'):
        if marker.lower() in text.lower():
            obfuscation_score += 1

    urls = list(dict.fromkeys(re.findall(r'https?://[^\s\'\"<>\\]{6,200}', text, re.I)))[:20]
    domains = list(dict.fromkeys(re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}', text, re.I)))[:20]
    domains = [d for d in domains if not d.endswith(('.dll', '.exe', '.bat', '.cmd'))][:15]

    commands = _reconstruct_commands(text)
    execution_chain: list[dict[str, str]] = []
    for idx, cmd in enumerate(commands, 1):
        step_type = 'command'
        lower = cmd.lower()
        if 'http' in lower or 'download' in lower:
            step_type = 'download'
        elif 'reg ' in lower or 'schtasks' in lower:
            step_type = 'persistence'
        elif 'powershell' in lower or 'iex' in lower or 'eval' in lower:
            step_type = 'execute'
        execution_chain.append({'step': idx, 'type': step_type, 'command': cmd})

    language = 'batch/cmd' if ext in {'.cmd', '.bat'} else ('powershell' if ext == '.ps1' else ('vbscript' if ext in {'.vbs', '.vbe'} else 'script'))

    return {
        'language': language,
        'kill_chain_phases': phases,
        'execution_chain': execution_chain,
        'commands_reconstructed': commands,
        'c2_urls': urls,
        'c2_domains': domains,
        'obfuscation_score': obfuscation_score,
        'obfuscation_level': 'high' if obfuscation_score >= 4 else ('medium' if obfuscation_score >= 2 else 'low'),
        'likely_stages': len(phases),
    }
