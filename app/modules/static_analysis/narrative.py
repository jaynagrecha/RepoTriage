from __future__ import annotations

from pathlib import Path
from typing import Any


def _extension_from_name(name: str | None) -> str:
    if not name:
        return ''
    cleaned = name.strip().split('/')[-1].split('\\')[-1]
    if cleaned.lower().endswith('.bin') and name.lower() != cleaned.lower():
        cleaned = name.strip().split('/')[-1]
    suffix = Path(cleaned).suffix.lower().lstrip('.')
    if suffix and suffix != 'bin':
        return suffix
    parts = cleaned.lower().split('.')
    if len(parts) >= 2:
        return parts[-1]
    return ''


def _declared_script_type(declared: str) -> bool:
    declared = (declared or '').lower()
    return any(x in declared for x in ('script', 'javascript', 'js', 'vbs', 'powershell', 'ps1', 'batch', 'python', 'php', 'hta'))


def build_analyst_narrative(report: dict[str, Any]) -> dict[str, Any]:
    filename = report.get('filename') or 'this file'
    typed = report.get('typed_analysis') or {}
    profile = report.get('profile') or {}
    universal = report.get('universal') or {}
    verdict = (report.get('static_verdict') or {}).get('verdict', 'inconclusive')
    suspicious = universal.get('suspicious_strings') or []
    iocs = universal.get('iocs') or {}
    logic = typed.get('logic_summary') or []
    patterns = typed.get('pattern_matches') or []
    language = typed.get('language') or profile.get('extension') or profile.get('category')

    bullets: list[str] = []
    headline = 'Static analysis summary'

    if profile.get('category') == 'script' or typed.get('language'):
        headline = f"This is a {language or 'script'} file, not a raw binary"
        if any('ActiveXObject' in s or 'WScript' in s for s in suspicious):
            bullets.append('Uses Windows Script Host (WScript) and ActiveXObject — common in droppers and downloaders disguised as documents.')
        if any('_0x' in s for s in suspicious):
            bullets.append('Contains JavaScript-style obfuscation (_0x… arrays) used to hide URLs, commands, and payloads.')
        for item in logic:
            bullets.append(item)
        for match in patterns[:5]:
            label = (match.get('pattern') or '').replace('_', ' ')
            if label:
                bullets.append(f"Detected {label}: `{str(match.get('match') or '')[:120]}`")

    elif profile.get('category') == 'pe':
        headline = 'This is a Windows executable (PE file)'
        imports = typed.get('suspicious_imports') or []
        if imports:
            bullets.append(f"Imports suspicious APIs: {', '.join(imports[:4])}.")
        for item in logic:
            bullets.append(item)

    elif profile.get('category') in {'pdf', 'document', 'markup', 'structured_text'}:
        headline = f"This is a {typed.get('format') or profile.get('category')} document"
        if typed.get('macros_detected'):
            bullets.append('Document contains macros or embedded script actions that can execute code.')
        for item in logic:
            bullets.append(item)

    elif profile.get('category') in {'archive', 'java_archive', 'compressed'}:
        headline = 'This is an archive containing other files'
        members = typed.get('suspicious_members') or []
        if members:
            bullets.append(f"Archive includes executable/script members: {', '.join(members[:3])}.")

    elif profile.get('category') == 'image':
        headline = 'This is an image file'
        if typed.get('embedded_payload_hint'):
            bullets.append('Image may contain hidden appended executable or script data.')

    else:
        if profile.get('extension') == 'bin' and _extension_from_name(filename):
            headline = f"File was stored as .bin but original name suggests .{_extension_from_name(filename)}"
            bullets.append('Re-run static analysis after update — script/document routing should now apply from the original filename.')
        elif any('ActiveXObject' in s or 'WScript' in s or '_0x' in s for s in suspicious):
            headline = 'Content looks like obfuscated script malware, not machine code'
            bullets.append('The disassembly shown earlier was misleading — bytes were interpreted as CPU instructions instead of script text.')
            bullets.append('Focus on suspicious strings and script indicators below, not raw hex/disassembly.')
        else:
            headline = 'Binary or unknown file type'

    urls = iocs.get('urls') or []
    domains = iocs.get('domains') or []
    if urls:
        bullets.append(f"Embedded URLs found: {', '.join(urls[:3])}.")
    if domains:
        bullets.append(f"Embedded domains found: {', '.join(domains[:3])}.")

    if verdict == 'malicious':
        assessment = 'RepoTriage assesses this file as likely malicious based on static behavior indicators.'
    elif verdict == 'suspicious':
        assessment = 'RepoTriage assesses this file as suspicious — it contains behavior patterns worth investigating.'
    elif verdict == 'clean':
        assessment = 'RepoTriage did not find strong malicious static indicators, but absence of evidence is not proof of safety.'
    else:
        assessment = 'RepoTriage could not reach a strong static verdict — review the behavior bullets and VT results together.'

    if not bullets:
        bullets.append('No plain-language behavior summary was generated. Check suspicious strings and IOCs, or re-run after the latest update.')

    return {
        'headline': headline,
        'assessment': assessment,
        'what_it_does': bullets[:8],
        'who_should_read_this': 'Written for analysts and incident responders — technical disassembly is optional and collapsed below.',
        'verdict_plain': verdict,
    }
