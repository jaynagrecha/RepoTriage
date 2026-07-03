from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


from .behavior import is_auth_sms_api_url, is_documentation_url

# Legacy loose pattern — prefer is_auth_sms_api_url() for classification.
AUTH_SMS_PATH = re.compile(
    r'(?:auth/sms|/sms/send|password.?reset|pass-recovery|keycode|profiles/register|sign_up|signup|/register\b)',
    re.I,
)

PHASE_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ('initial_access', 'User execution / script launch', re.compile(r'(?:start\s|wscript|cscript|mshta|powershell|cmd\.exe)', re.I)),
    ('download', 'Payload or second-stage download', re.compile(r'(?:downloadstring|downloadfile|invoke-webrequest|XMLHTTP|WinHttp|curl|wget|bitsadmin)', re.I)),
    ('decode', 'De-obfuscation / decoding', re.compile(r'(?:frombase64|base64|xor|chr\s*\(|fromcharcode|decode|decrypt)', re.I)),
    ('execute', 'In-memory or secondary execution', re.compile(r'(?:iex\b|invoke-expression|eval\s*\(|exec\s*\(|start-process|shell\.application)', re.I)),
    ('persistence', 'Persistence mechanism', re.compile(r'(?:CurrentVersion\\Run|schtasks|reg\s+add|RunOnce|Startup)', re.I)),
    ('discovery', 'Environment / host discovery', re.compile(r'(?:get-wmiobject|whoami|hostname|ipconfig|systeminfo)', re.I)),
    ('exfil', 'Data exfiltration channel', re.compile(r'(?:discord\.com/api/webhooks|api\.telegram\.org|pastebin|ngrok)', re.I)),
]


def _extract_http_calls(text: str) -> list[dict[str, str]]:
    calls: list[dict[str, str]] = []
    patterns = [
        re.compile(r'requests\.(get|post|put|patch|delete)\(\s*[\'"](https?://[^\'"]+)[\'"]', re.I),
        re.compile(r'urllib\.request\.urlopen\(\s*[\'"](https?://[^\'"]+)[\'"]', re.I),
        re.compile(r'(?:curl|wget)\s+(?:[^\n\'"]+)?[\'"](https?://[^\'"]+)[\'"]', re.I),
        re.compile(r'(?:Invoke-WebRequest|Invoke-RestMethod)\s+[^\n\'"]*[\'"](https?://[^\'"]+)[\'"]', re.I),
    ]
    for pat in patterns:
        for match in pat.finditer(text):
            groups = match.groups()
            if len(groups) >= 2:
                method, url = groups[0].upper(), groups[1]
            else:
                method, url = 'GET', groups[0]
            purpose = 'auth/sms/otp' if is_auth_sms_api_url(url) else ('reference' if is_documentation_url(url) else 'http')
            calls.append({'method': method, 'url': url, 'purpose': purpose})
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for c in calls:
        k = c['url'].lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(c)
        if len(out) >= 40:
            break
    return out


def _reconstruct_commands(text: str) -> list[str]:
    commands: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('::'):
            continue
        if line.startswith('#') and 'http' not in line.lower():
            continue
        lower = line.lower()
        if any(x in lower for x in (
            'powershell', 'cmd', 'wscript', 'curl', 'http', 'reg ', 'schtasks', 'start ',
            'rundll32', 'mshta', 'requests.', 'urllib', 'invoke-webrequest', 'download',
        )):
            commands.append(line[:300])
        if len(commands) >= 20:
            break
    return commands


def _domains_from_urls(urls: list[str]) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()
    for url in urls:
        try:
            host = (urlparse(url).hostname or '').lower()
        except Exception:
            continue
        if host and host not in seen:
            seen.add(host)
            domains.append(host)
    return domains[:20]


def _build_execution_chain(http_calls: list[dict[str, str]], commands: list[str]) -> list[dict[str, str]]:
    chain: list[dict[str, str]] = []
    step = 1
    for call in http_calls[:15]:
        label = f"{call['method']} {call['url'][:100]}"
        purpose = call.get('purpose') or 'http'
        if purpose == 'auth/sms/otp':
            label = f"Trigger SMS/OTP via {call['method']} → {call['url'][:90]}"
        elif purpose == 'reference':
            label = f"Reference (privesc/docs): {call['url'][:100]}"
        chain.append({'step': step, 'type': purpose, 'command': label})
        step += 1
    for cmd in commands:
        if step > 20:
            break
        lower = cmd.lower()
        step_type = 'command'
        if 'http' in lower or 'download' in lower:
            step_type = 'download'
        elif 'reg ' in lower or 'schtasks' in lower:
            step_type = 'persistence'
        elif 'powershell' in lower or 'iex' in lower or 'eval' in lower:
            step_type = 'execute'
        chain.append({'step': step, 'type': step_type, 'command': cmd[:300]})
        step += 1
    return chain


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

    http_calls = _extract_http_calls(text)
    url_from_calls = [c['url'] for c in http_calls]
    urls = list(dict.fromkeys(url_from_calls + re.findall(r'https?://[^\s\'\"<>\\]{6,200}', text, re.I)))[:40]
    domains = _domains_from_urls(urls)
    commands = _reconstruct_commands(text)
    execution_chain = _build_execution_chain(http_calls, commands)

    if ext == '.py':
        language = 'python'
    elif ext in {'.cmd', '.bat'}:
        language = 'batch/cmd'
    elif ext == '.ps1':
        language = 'powershell'
    elif ext in {'.vbs', '.vbe'}:
        language = 'vbscript'
    else:
        language = 'script'

    auth_url_count = sum(1 for c in http_calls if c.get('purpose') == 'auth/sms/otp')
    doc_url_count = sum(1 for c in http_calls if c.get('purpose') == 'reference')

    return {
        'language': language,
        'kill_chain_phases': phases,
        'execution_chain': execution_chain,
        'http_calls': http_calls,
        'commands_reconstructed': commands,
        'c2_urls': urls,
        'c2_domains': domains,
        'obfuscation_score': obfuscation_score,
        'obfuscation_level': 'high' if obfuscation_score >= 4 else ('medium' if obfuscation_score >= 2 else 'low'),
        'likely_stages': len(phases),
        'auth_sms_url_count': auth_url_count,
        'documentation_url_count': doc_url_count,
        'unique_service_count': len(domains),
    }
