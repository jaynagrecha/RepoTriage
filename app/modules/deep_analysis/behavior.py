from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


# URL path hints for dynamic behavior classification (not file-specific).
AUTH_SMS_PATH = re.compile(
    r'(?:register|signup|sign_up|sign-up|auth/sms|/sms|send.?code|otp|verify|verification|'
    r'password.?reset|pass-recovery|keycode|getcode|confirm)',
    re.I,
)
PHONE_FIELD = re.compile(r'(?:phone|phoneNumber|phone_number|mobile|msisdn|_phone\d*)', re.I)
DOWNLOAD_EXEC = re.compile(r'(?:downloadstring|downloadfile|invoke-webrequest|curl\s|wget\s|iex\b|eval\s*\()', re.I)
WEBHOOK_EXFIL = re.compile(r'discord(?:app)?\.com/api/webhooks|api\.telegram\.org', re.I)
PERSISTENCE = re.compile(r'CurrentVersion\\Run|schtasks|reg\s+add', re.I)
THREADING = re.compile(r'\b(?:threading|ThreadPool|multiprocessing|Process\s*\(|asyncio\.gather)\b', re.I)
CRYPTO_WALLET = re.compile(r'bc1[a-z0-9]{20,}|0x[a-fA-F0-9]{40}', re.I)

BEHAVIOR_LABELS = {
    'sms_otp_abuse': 'SMS / OTP abuse tool',
    'script_dropper': 'Script-based dropper / downloader',
    'credential_stealer': 'Credential / data theft',
    'persistence_tool': 'Persistence mechanism',
    'remote_access': 'Remote access / backdoor behavior',
    'packed_loader': 'Packed binary / loader',
    'process_injection': 'Process injection capability',
    'generic_network_tool': 'Automated multi-service network tool',
    'unknown_script': 'Script behavior — review manually',
    'unknown_binary': 'Binary behavior — review manually',
}


def _service_name_from_url(url: str) -> str:
    try:
        host = (urlparse(url).hostname or '').lower()
        if not host:
            return url[:40]
        parts = host.split('.')
        if len(parts) >= 2:
            return parts[-2].replace('-', ' ').title()
        return host
    except Exception:
        return url[:40]


def _unique_preserve(items: list[str], limit: int = 12) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for x in items:
        k = x.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
        if len(out) >= limit:
            break
    return out


def _score_profiles(signals: dict[str, Any]) -> list[tuple[str, int, list[str]]]:
    """Return ranked (profile_id, score, evidence_lines)."""
    profiles: list[tuple[str, int, list[str]]] = []

    auth_urls = signals.get('auth_sms_urls') or []
    unique_hosts = signals.get('unique_http_hosts') or []
    http_count = int(signals.get('http_call_count') or 0)
    has_phone = bool(signals.get('has_phone_fields'))
    has_threading = bool(signals.get('has_threading'))

    if len(auth_urls) >= 2 or (http_count >= 4 and len(auth_urls) >= 1):
        score = len(auth_urls) * 3 + (5 if has_phone else 0) + (4 if has_threading else 0) + min(http_count, 10)
        ev = [
            f"{len(auth_urls)} URL(s) target registration, SMS, OTP, or password-recovery endpoints",
        ]
        if has_phone:
            ev.append('Code references phone numbers as the primary input variable')
        if has_threading:
            ev.append('Uses threading or multiprocessing to parallelize requests')
        if unique_hosts:
            ev.append(f"Contacts {len(unique_hosts)} distinct third-party service(s): {', '.join(unique_hosts[:6])}{'…' if len(unique_hosts) > 6 else ''}")
        profiles.append(('sms_otp_abuse', score, ev))

    if signals.get('download_exec'):
        profiles.append(('script_dropper', 8 + int(signals.get('obfuscation_score') or 0), [
            'Contains download-and-execute patterns (PowerShell/curl/wscript style)',
        ]))

    if signals.get('webhook_exfil'):
        profiles.append(('credential_stealer', 10, [
            'References Discord/Telegram webhook or bot endpoints (common exfil channels)',
        ]))

    if signals.get('persistence'):
        profiles.append(('persistence_tool', 9, [
            'Implements or references registry Run keys, scheduled tasks, or similar persistence',
        ]))

    if signals.get('high_risk_pe_imports'):
        profiles.append(('process_injection', 10 + len(signals.get('high_risk_pe_imports') or []), [
            'PE imports indicate cross-process manipulation or injection primitives',
        ]))

    if signals.get('packer_hints'):
        profiles.append(('packed_loader', 7 + len(signals.get('packer_hints') or []), [
            'Binary packing or protection indicators present',
        ]))

    if http_count >= 3 and not auth_urls:
        profiles.append(('generic_network_tool', http_count, [
            f'Makes {http_count} automated HTTP call(s) to external services',
        ]))

    profiles.sort(key=lambda x: x[1], reverse=True)
    return profiles


def _confidence(score: int) -> str:
    if score >= 14:
        return 'high'
    if score >= 8:
        return 'medium'
    return 'low'


def _threat_category(profile_id: str) -> str:
    if profile_id in {'sms_otp_abuse', 'generic_network_tool'}:
        return 'abuse_tool'
    if profile_id in {'script_dropper', 'credential_stealer', 'persistence_tool', 'remote_access', 'packed_loader', 'process_injection'}:
        return 'malware'
    return 'unknown'


def _build_summary(profile_id: str, signals: dict[str, Any], services: list[str]) -> str:
    if profile_id == 'sms_otp_abuse':
        svc = ', '.join(services[:8]) if services else 'multiple online services'
        extra = f" including {svc}" if services else ''
        parallel = ' in parallel' if signals.get('has_threading') else ''
        return (
            f"This appears to be an SMS or OTP abuse tool — not traditional C2 malware. "
            f"It automates HTTP requests{parallel} to third-party registration, login, or password-reset APIs{extra}, "
            f"likely to flood victims with verification SMS messages (SMS bombing). "
            f"VirusTotal may report clean because the file does not contain a known malware signature — "
            f"the harm is abusive traffic against legitimate services, not host compromise."
        )
    if profile_id == 'script_dropper':
        return (
            "This script behaves like a dropper or staged downloader: it retrieves external content "
            "and is structured to execute or invoke a follow-on payload. Treat as malicious delivery "
            "infrastructure until proven otherwise."
        )
    if profile_id == 'credential_stealer':
        return (
            "Behavior suggests credential theft or data exfiltration — webhook or messaging endpoints "
            "are referenced alongside sensitive collection patterns."
        )
    if profile_id == 'process_injection':
        return (
            "This binary exposes process manipulation imports consistent with injection, staging, "
            "or in-memory execution — review as potential malware loader or implant."
        )
    if profile_id == 'packed_loader':
        return "Packed or protected binary — often used to hide a second-stage payload. Sandbox detonation recommended."
    if profile_id == 'generic_network_tool':
        return (
            f"Automated network client contacting {len(signals.get('unique_http_hosts') or [])} external host(s). "
            "Review whether this is operational tooling, abuse software, or malware staging."
        )
    return "Automated behavior analysis could not classify intent with high confidence — use execution chain and IOCs below."


def _recommended_action(profile_id: str, threat_category: str, combined_verdict: str) -> str:
    if profile_id == 'sms_otp_abuse':
        return (
            "Do not run against phone numbers you do not own. Block or remove if found in your environment — "
            "this is harassment/abuse tooling. Report to platform abuse teams if deployed; VT clean does not mean benign."
        )
    if threat_category == 'malware' or combined_verdict in {'malicious', 'suspicious'}:
        return "Do not execute on production systems. Quarantine, block hash, and investigate delivery path."
    if combined_verdict == 'needs_review':
        return "Run only in an isolated VM if dynamic behavior is required. Correlate URLs and hashes with CTI before closing."
    return "Review findings below before execution. No strong malware anchor was confirmed."


def extract_script_signals(text: str, script_deep: dict[str, Any] | None = None) -> dict[str, Any]:
    script_deep = script_deep or {}
    urls = list(script_deep.get('c2_urls') or [])
    for call in script_deep.get('http_calls') or []:
        u = call.get('url')
        if u and u not in urls:
            urls.append(u)

    auth_sms_urls = [u for u in urls if AUTH_SMS_PATH.search(u)]
    hosts = [_service_name_from_url(u) for u in urls]
    unique_hosts = _unique_preserve(hosts)

    return {
        'http_call_count': len(script_deep.get('http_calls') or []) or len(urls),
        'auth_sms_urls': auth_sms_urls,
        'unique_http_hosts': unique_hosts,
        'has_phone_fields': bool(PHONE_FIELD.search(text)),
        'has_threading': bool(THREADING.search(text)),
        'download_exec': bool(DOWNLOAD_EXEC.search(text)),
        'webhook_exfil': bool(WEBHOOK_EXFIL.search(text)),
        'persistence': bool(PERSISTENCE.search(text)),
        'obfuscation_score': int(script_deep.get('obfuscation_score') or 0),
        'language': script_deep.get('language') or 'script',
    }


def interpret_behavior(
    bundle: dict[str, Any],
    *,
    static: dict[str, Any] | None = None,
    sample_text: str | None = None,
) -> dict[str, Any]:
    """Dynamic plain-English behavior interpretation for deep analysis."""
    deep = bundle.get('deep_exclusive') or {}
    script = deep.get('script') or {}
    pe = deep.get('pe') or {}
    combined = bundle.get('combined_verdict') or 'unknown'

    text = sample_text or ''
    if not text and script.get('commands_reconstructed'):
        text = '\n'.join(script.get('commands_reconstructed') or [])

    signals: dict[str, Any] = extract_script_signals(text, script)
    signals['high_risk_pe_imports'] = pe.get('high_risk_imports') or []
    signals['packer_hints'] = pe.get('packer_hints') or []

    profiles = _score_profiles(signals)
    if profiles:
        profile_id, score, evidence = profiles[0]
    else:
        profile_id = 'unknown_script' if script else 'unknown_binary'
        score, evidence = 0, ['No strong behavioral template matched — see technical chain below.']

    services = _unique_preserve([_service_name_from_url(u) for u in signals.get('auth_sms_urls') or []])
    if not services:
        services = signals.get('unique_http_hosts') or []

    threat_category = _threat_category(profile_id)
    conf = _confidence(score)

    what_it_does = list(evidence)
    if profile_id == 'sms_otp_abuse' and services:
        what_it_does.append(
            f"Primary effect: trigger SMS/OTP messages via legitimate APIs operated by {', '.join(services[:10])}."
        )
    if script.get('execution_chain'):
        what_it_does.append(
            f"Technical execution: {len(script['execution_chain'])} reconstructed step(s) — see chain below for raw commands."
        )

    network_label = 'Third-party API endpoints (not C2)' if profile_id == 'sms_otp_abuse' else 'Network endpoints'
    if threat_category == 'abuse_tool':
        network_label = 'Abuse targets (third-party services)'

    return {
        'behavior_class': profile_id,
        'behavior_title': BEHAVIOR_LABELS.get(profile_id, profile_id),
        'confidence': conf,
        'confidence_score': min(100, score * 6),
        'threat_category': threat_category,
        'summary': _build_summary(profile_id, signals, services),
        'what_it_does': what_it_does,
        'notable_services': services,
        'network_label': network_label,
        'evidence': evidence,
        'signals': {
            'http_calls': signals.get('http_call_count'),
            'auth_sms_urls': len(signals.get('auth_sms_urls') or []),
            'unique_services': len(services),
            'has_phone_fields': signals.get('has_phone_fields'),
            'has_threading': signals.get('has_threading'),
        },
        'recommended_action': _recommended_action(profile_id, threat_category, combined),
        'vt_context': (
            'VT often marks abuse tools as undetected — absence of detections does not imply safe or authorized use.'
            if threat_category == 'abuse_tool'
            else None
        ),
    }
