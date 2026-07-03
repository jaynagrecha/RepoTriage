from __future__ import annotations

from typing import Any

from app.modules.detection_policy import HIGH_CONFIDENCE_IMPORT_MARKERS


def collect_signals(report: dict[str, Any]) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []

    def add(category: str, label: str, weight: int, evidence: str) -> None:
        signals.append({'category': category, 'label': label, 'weight': weight, 'evidence': evidence[:500]})

    universal = report.get('universal') or {}
    typed = report.get('typed_analysis') or {}
    suspicious = universal.get('suspicious_strings') or []
    suspicious_blob = ' '.join(suspicious).lower()

    # High-confidence malware combinations only.
    if 'wscript' in suspicious_blob and 'activexobject' in suspicious_blob:
        add('malware', 'windows_script_dropper', 45, 'WScript + ActiveXObject — classic script-based dropper/downloader pattern')
    if '_0x' in suspicious_blob and ('wscript' in suspicious_blob or 'activexobject' in suspicious_blob):
        add('malware', 'obfuscated_script_dropper', 40, 'Obfuscated script (_0x…) with Windows Script Host execution primitives')
    if 'invoke-expression' in suspicious_blob or 'downloadstring' in suspicious_blob:
        add('malware', 'powershell_downloader', 42, 'PowerShell download/execute pattern detected')
    elif re_iex_with_download(suspicious_blob):
        add('malware', 'powershell_downloader', 42, 'PowerShell IEX combined with download primitive')

    entropy = float(universal.get('entropy') or 0)
    if entropy >= 7.8:
        add('packing', 'high_entropy', 8, f'High entropy ({entropy:.2f}) — may indicate packing; verify with other signals')
    elif entropy >= 7.4:
        add('packing', 'moderate_entropy', 3, f'Moderate entropy ({entropy:.2f})')

    strong_string_markers = (
        'activexobject', 'wscript', 'downloadstring', 'invoke-expression', 'writeprocessmemory',
        'createremotethread', 'isdebuggerpresent', '-encodedcommand',
    )
    strong_hits = sum(1 for m in strong_string_markers if m in suspicious_blob)
    if strong_hits >= 2:
        add('behavior', 'suspicious_strings', 12, '; '.join(suspicious[:5]))
    elif suspicious and strong_hits == 1:
        add('behavior', 'weak_suspicious_strings', 5, '; '.join(suspicious[:3]))

    iocs = universal.get('iocs') or {}
    if iocs.get('discord_webhooks'):
        add('network', 'discord_webhook', 28, iocs['discord_webhooks'][0])
    if iocs.get('urls') or iocs.get('ips'):
        add('network', 'embedded_iocs', 6, f"URLs={len(iocs.get('urls') or [])}, IPs={len(iocs.get('ips') or [])}")

    extracted = report.get('extracted_indicators') or {}
    if extracted.get('urls'):
        add('network', 'extracted_urls', 4, f"URLs extracted: {', '.join(extracted['urls'][:3])}")
    if extracted.get('discord_webhooks'):
        add('network', 'discord_webhook', 28, extracted['discord_webhooks'][0])

    deob = report.get('deobfuscation') or {}
    if (deob.get('attempts') or 0) > 0 and (deob.get('xor_candidates') or deob.get('recovered')):
        add('obfuscation', 'decoded_hidden_content', 18, f"Recovered {deob.get('attempts', 0)} decoded artifact(s)")

    for summary in typed.get('logic_summary') or []:
        add('typed', 'logic_summary', 8, summary)
    if typed.get('macros_detected'):
        add('document', 'macro_content', 25, 'Macro or JavaScript action detected')
    if typed.get('suspicious_members'):
        add('archive', 'suspicious_members', 16, ', '.join(typed['suspicious_members'][:5]))
    if typed.get('embedded_payload_hint'):
        add('stego', 'embedded_payload', 12, 'Image trailing payload markers')

    for fn in typed.get('functions') or report.get('functions') or []:
        tags = fn.get('logic_tags') or fn.get('logic_summary') or []
        if tags:
            add('function', fn.get('name') or 'function', 6, ', '.join(tags))

    for match in typed.get('pattern_matches') or []:
        add('script', match.get('pattern') or 'pattern', 4, match.get('match') or '')

    for imp in typed.get('suspicious_imports') or []:
        imp_l = imp.lower()
        if any(marker in imp_l for marker in HIGH_CONFIDENCE_IMPORT_MARKERS):
            add('binary', 'high_confidence_import', 22, imp)
        elif any(x in imp_l for x in ('virtualalloc', 'virtualprotect', 'cryptencrypt')):
            add('binary', 'informational_import', 2, imp)

    r2 = typed.get('r2') or {}
    for fn in r2.get('functions') or []:
        for tag in fn.get('logic_summary') or []:
            add('r2', fn.get('name') or 'fn', 8, tag)

    return signals


def re_iex_with_download(blob: str) -> bool:
    return ('iex' in blob.split() or 'invoke-expression' in blob) and any(
        x in blob for x in ('downloadstring', 'downloadfile', 'invoke-webrequest', '-encodedcommand')
    )
