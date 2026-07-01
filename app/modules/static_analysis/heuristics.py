from __future__ import annotations

from typing import Any


def collect_signals(report: dict[str, Any]) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []

    def add(category: str, label: str, weight: int, evidence: str) -> None:
        signals.append({'category': category, 'label': label, 'weight': weight, 'evidence': evidence[:500]})

    universal = report.get('universal') or {}
    typed = report.get('typed_analysis') or {}
    suspicious = universal.get('suspicious_strings') or []
    suspicious_blob = ' '.join(suspicious).lower()
    raw_text = suspicious_blob

    # High-confidence malware combinations (avoid weak "inconclusive" on obvious droppers).
    if 'wscript' in suspicious_blob and 'activexobject' in suspicious_blob:
        add('malware', 'windows_script_dropper', 45, 'WScript + ActiveXObject — classic script-based dropper/downloader pattern')
    if '_0x' in suspicious_blob and ('wscript' in suspicious_blob or 'activexobject' in suspicious_blob):
        add('malware', 'obfuscated_script_dropper', 40, 'Obfuscated script (_0x…) with Windows Script Host execution primitives')
    if 'invoke-expression' in suspicious_blob or 'downloadstring' in suspicious_blob or 'iex' in suspicious_blob.split():
        add('malware', 'powershell_downloader', 42, 'PowerShell download/execute pattern detected')

    if universal.get('entropy', 0) >= 7.2:
        add('packing', 'high_entropy', 15, f"Entropy {universal.get('entropy')}")
    if suspicious:
        add('behavior', 'suspicious_strings', 20, '; '.join(suspicious[:5]))
    iocs = universal.get('iocs') or {}
    if iocs.get('urls') or iocs.get('ips') or iocs.get('discord_webhooks'):
        add('network', 'embedded_iocs', 18, f"URLs={len(iocs.get('urls') or [])}, IPs={len(iocs.get('ips') or [])}")

    deob = report.get('deobfuscation') or {}
    if (deob.get('attempts') or 0) > 0 or deob.get('xor_candidates'):
        add('obfuscation', 'decoded_hidden_content', 22, f"Recovered {deob.get('attempts', 0)} decoded artifact(s)")

    for summary in typed.get('logic_summary') or []:
        add('typed', 'logic_summary', 12, summary)
    if typed.get('macros_detected'):
        add('document', 'macro_content', 25, 'Macro or JavaScript action detected')
    if typed.get('suspicious_members'):
        add('archive', 'suspicious_members', 20, ', '.join(typed['suspicious_members'][:5]))
    if typed.get('embedded_payload_hint'):
        add('stego', 'embedded_payload', 18, 'Image trailing payload markers')

    for fn in typed.get('functions') or report.get('functions') or []:
        tags = fn.get('logic_tags') or fn.get('logic_summary') or []
        if tags:
            add('function', fn.get('name') or 'function', 10, ', '.join(tags))

    for match in typed.get('pattern_matches') or []:
        add('script', match.get('pattern') or 'pattern', 8, match.get('match') or '')

    for imp in typed.get('suspicious_imports') or []:
        add('binary', 'suspicious_import', 14, imp)

    r2 = typed.get('r2') or {}
    for fn in r2.get('functions') or []:
        for tag in fn.get('logic_summary') or []:
            add('r2', fn.get('name') or 'fn', 12, tag)

    return signals
