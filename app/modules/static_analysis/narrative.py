from __future__ import annotations

from typing import Any


def _plain_verdict_label(verdict: str) -> str:
    return {
        'malicious': 'Likely malware',
        'suspicious': 'Suspicious — investigate',
        'needs_review': 'Uncertain — needs review',
        'inconclusive': 'Uncertain — needs review',
        'clean': 'Likely clean',
    }.get(verdict, 'Uncertain — needs review')


def _recommendation(verdict: str, filename: str, has_wsh: bool) -> str:
    if verdict == 'malicious':
        if has_wsh:
            return 'Do not open on Windows. Treat as a malicious script dropper. Block the hash, quarantine affected endpoints, and investigate how it was delivered.'
        return 'Treat as malicious. Block the hash, prevent execution in your environment, and investigate delivery path.'
    if verdict == 'suspicious':
        return 'Do not execute on production systems. Review in an isolated VM/sandbox and correlate with VirusTotal and network logs.'
    if verdict in {'needs_review', 'inconclusive'}:
        return 'Static analysis could not confirm intent with high confidence. Use VirusTotal, sandbox detonation, and analyst review before trusting this file.'
    return 'No strong malicious indicators were found statically, but always validate against your threat model before execution.'


def build_analyst_narrative(report: dict[str, Any], *, vt_verdict: str | None = None) -> dict[str, Any]:
    filename = report.get('filename') or 'this file'
    typed = report.get('typed_analysis') or {}
    profile = report.get('profile') or {}
    universal = report.get('universal') or {}
    static = report.get('static_verdict') or {}
    verdict = static.get('verdict', 'needs_review')
    suspicious = universal.get('suspicious_strings') or []
    iocs = universal.get('iocs') or {}
    extracted = report.get('extracted_indicators') or {}
    logic = typed.get('logic_summary') or []
    patterns = typed.get('pattern_matches') or []
    language = typed.get('language') or profile.get('extension') or profile.get('category')
    has_wsh = any('ActiveXObject' in s or 'WScript' in s for s in suspicious)

    bullets: list[str] = []

    if profile.get('category') == 'script' or typed.get('language'):
        if has_wsh:
            bullets.append('This is a Windows script (JS/VBS-style) that uses WScript and ActiveXObject — a common pattern for malware disguised as invoices, PDFs, or beneficiary forms.')
        elif language:
            bullets.append(f'This is a {language} script file, not a compiled executable.')
        if any('_0x' in s for s in suspicious):
            bullets.append('The code is obfuscated with _0x-style variables to hide what it actually downloads or executes.')
    elif profile.get('category') == 'pe':
        bullets.append('This is a Windows executable (PE file).')
    elif profile.get('category') in {'archive', 'java_archive', 'compressed'}:
        bullets.append('This is an archive that may contain additional payloads inside.')
    elif any('ActiveXObject' in s or 'WScript' in s or '_0x' in s for s in suspicious):
        bullets.append('This looks like obfuscated script malware, not raw machine code — ignore any CPU disassembly output.')

    for item in logic[:4]:
        if item not in bullets:
            bullets.append(item)

    urls = iocs.get('urls') or []
    domains = iocs.get('domains') or []
    extracted = report.get('extracted_indicators') or {}
    ext_urls = extracted.get('urls') or urls
    ext_domains = extracted.get('domains') or domains
    ext_ips = extracted.get('ips') or iocs.get('ips') or []

    if ext_urls:
        bullets.append(f'Contains {len(ext_urls)} URL(s) — e.g. {ext_urls[0]}')
    if ext_domains and not ext_urls:
        bullets.append(f'Contains {len(ext_domains)} domain(s) — e.g. {ext_domains[0]}')
    if ext_ips:
        bullets.append(f'Contains {len(ext_ips)} IP address(es) — e.g. {ext_ips[0]}')
    if extracted.get('discord_webhooks'):
        bullets.append(f'Contains Discord webhook(s) — potential exfil/C2 channel.')
    if extracted.get('decoded_artifacts'):
        bullets.append(f'De-obfuscation recovered {len(extracted["decoded_artifacts"])} hidden string(s) that may contain payloads or URLs.')

    if not bullets:
        bullets.append('No clear behavior summary was extracted. Check VirusTotal and consider sandbox analysis.')

    vt_note = None
    if vt_verdict:
        vt_lower = str(vt_verdict).lower()
        if 'malicious' in vt_lower and verdict in {'malicious', 'suspicious'}:
            vt_note = f'VirusTotal and static analysis agree: this file is malicious ({vt_verdict}).'
        elif 'malicious' in vt_lower and verdict in {'needs_review', 'inconclusive', 'clean'}:
            vt_note = f'VirusTotal flags this as {vt_verdict}, but static analysis is less certain — re-run analysis or treat as malicious given VT.'
        elif verdict == 'malicious':
            vt_note = f'Static analysis flags likely malware; VirusTotal reports: {vt_verdict}.'

    label = static.get('verdict_label') or _plain_verdict_label(verdict)

    return {
        'headline': label,
        'assessment': _recommendation(verdict, filename, has_wsh),
        'what_it_does': bullets[:6],
        'vt_note': vt_note,
        'verdict_plain': verdict,
        'confidence_plain': f"{static.get('confidence', 0)}% confidence",
        'indicator_summary': extracted.get('counts') or {},
    }
