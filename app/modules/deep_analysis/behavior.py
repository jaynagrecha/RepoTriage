from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


# Strict API-style paths only — avoids doc URLs like ".../signature-verification-failed".
STRICT_AUTH_SMS_API = re.compile(
    r'(?:'
    r'auth/sms|/sms/send|/v\d+/auth/sms|send.?code|/otp\b|password.?reset|pass-recovery|'
    r'keycode\.html|profiles/register|sign_up\b|signup\b|/register\b'
    r')',
    re.I,
)

# Substrings that indicate documentation / pentest reference, not live abuse APIs.
DOC_URL_MARKERS = re.compile(
    r'(?:hacktricks|gtfobins|privilege-escalation|privesc|checklist|forensics|'
    r'securitytracker|stackexchange|stackoverflow|togaware|github\.com/.+/tree/)',
    re.I,
)

DOC_HOST_FRAGMENTS = (
    'hacktricks', 'gtfobins', 'stackoverflow', 'stackexchange', 'securitytracker',
    'togaware', 'github.com', 'wikimedia', 'wikipedia', 'mozilla.org',
)

PRIVESC_MARKERS = re.compile(
    r'(?:'
    r'linpeas|peass-ng|peass\b|linux.?privilege.?escalation|privilege.?escalation|privesc|'
    r'gtfobins|/suid\b|suid\.|sudoers|/etc/shadow|/etc/passwd|capabilities|capsh|'
    r'cron\.d|ld\.so|ld_preload|writable\.path|kernel.?exploit'
    r')',
    re.I,
)

METASPLOIT_MARKERS = re.compile(
    r'(?:'
    r'metasploit|meterpreter|msfvenom|msfpayload|Msf::|MetasploitModule|'
    r"require\s+['\"]msf/core|module\s+requires\s+metasploit|rapid7/metasploit-framework"
    r')',
    re.I,
)

METASPLOIT_MODULE_HEADER = re.compile(
    r'module\s+requires\s+metasploit|rapid7/metasploit-framework|class\s+MetasploitModule',
    re.I,
)

PHONE_FIELD = re.compile(r'(?:\bphone_number\b|\bphoneNumber\b|\bphone_number\b|_phone\d*\s*=|\bmsisdn\b)', re.I)
DOWNLOAD_EXEC = re.compile(r'(?:downloadstring|downloadfile|invoke-webrequest|curl\s|wget\s|iex\b|eval\s*\()', re.I)
WEBHOOK_EXFIL = re.compile(r'discord(?:app)?\.com/api/webhooks|api\.telegram\.org', re.I)
PERSISTENCE = re.compile(r'CurrentVersion\\Run|schtasks|reg\s+add', re.I)
THREADING = re.compile(r'\b(?:threading|ThreadPool|multiprocessing|Process\s*\(|asyncio\.gather)\b', re.I)

BEHAVIOR_LABELS = {
    'sms_otp_abuse': 'SMS / OTP abuse tool',
    'linux_privesc_enum': 'Linux privilege-escalation enumerator',
    'metasploit_module': 'Metasploit Framework module',
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


def _norm_url(url: str) -> str:
    return (url or '').strip().lower()


def _url_host_path(url: str) -> tuple[str, str]:
    try:
        p = urlparse(url)
        return (p.hostname or '').lower(), (p.path or '').lower()
    except Exception:
        return '', ''


def is_documentation_url(url: str) -> bool:
    u = _norm_url(url)
    host, path = _url_host_path(url)
    if DOC_URL_MARKERS.search(u):
        return True
    if any(frag in host for frag in DOC_HOST_FRAGMENTS):
        return True
    if any(x in path for x in ('/wiki/', '/tree/', 'checklist', 'privilege-escalation', 'forensics')):
        return True
    return False


def is_auth_sms_api_url(url: str) -> bool:
    if is_documentation_url(url):
        return False
    u = _norm_url(url)
    if re.search(r'(?:signature-verification|verification-failed|/email|/docs/)', u):
        return False
    return bool(STRICT_AUTH_SMS_API.search(u))


def _service_name_from_url(url: str) -> str:
    try:
        host = (urlparse(url).hostname or '').lower()
        if not host:
            return url[:40]
        if 'hacktricks' in host:
            return 'HackTricks (documentation)'
        if 'gtfobins' in host:
            return 'GTFOBins (documentation)'
        if 'metasploit' in host or 'metasploit-framework' in (urlparse(url).path or '').lower():
            return 'Metasploit Framework (Rapid7)'
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


def _privesc_signal_strength(text: str, urls: list[str]) -> tuple[int, list[str]]:
    evidence: list[str] = []
    score = 0
    markers = set(m.lower() for m in PRIVESC_MARKERS.findall(text))
    if markers:
        score += min(20, len(markers) * 3)
        evidence.append(f"References privilege-escalation enumeration patterns ({', '.join(sorted(markers)[:6])})")
    if re.search(r'\blinpeas\b', text, re.I):
        score += 15
        evidence.append('Identifies as or implements LinPEAS-style local enumeration')
    doc_urls = [u for u in urls if is_documentation_url(u)]
    privesc_docs = [u for u in doc_urls if re.search(r'privilege-escalation|gtfobins|linux-unix', u, re.I)]
    if privesc_docs:
        score += min(15, len(privesc_docs) * 2)
        evidence.append(f"Embeds {len(privesc_docs)} pentest reference URL(s) (HackTricks/GTFOBins-style guides)")
    if re.search(r'\bsidG\d|\bsudoVB|\bsudocaps|INTERESTING.*FILES|SUID', text, re.I):
        score += 8
        evidence.append('Contains SUID/sudo/capability enumeration logic typical of post-exploitation scripts')
    return score, evidence


def _infer_msf_module_role(filename: str, text: str) -> str | None:
    name = (filename or '').lower()
    if re.search(r'bf[_-]?xor|brute.?force.*xor|xor.*brute', name + ' ' + text[:2000], re.I):
        return 'brute-force XOR / decode auxiliary'
    if re.search(r'exploit/|/exploits/', text[:4000], re.I):
        return 'exploit module'
    if re.search(r'auxiliary/|/auxiliary/', text[:4000], re.I):
        return 'auxiliary module'
    if re.search(r'post/|/post/', text[:4000], re.I):
        return 'post-exploitation module'
    if re.search(r'payload/|/payloads/', text[:4000], re.I):
        return 'payload module'
    if re.search(r'class\s+MetasploitModule', text, re.I):
        return 'Metasploit module class'
    return None


def _metasploit_signal_strength(
    text: str,
    urls: list[str],
    family_hints: dict[str, Any] | None,
    *,
    filename: str | None = None,
) -> tuple[int, list[str], str | None]:
    evidence: list[str] = []
    score = 0
    family_hints = family_hints or {}

    msf_family = next(
        (m for m in family_hints.get('family_matches') or [] if m.get('family') == 'metasploit'),
        None,
    )
    if msf_family:
        hits = int(msf_family.get('hits') or 0)
        score += min(18, 6 + hits * 3)
        evidence.append(f"Family parser matched Metasploit framework strings ({hits} hit(s))")

    markers = set(m.lower() for m in METASPLOIT_MARKERS.findall(text))
    if markers:
        score += min(12, len(markers) * 4)
        evidence.append(
            f"Contains Metasploit module markers ({', '.join(sorted(markers)[:5])})"
        )

    if METASPLOIT_MODULE_HEADER.search(text):
        score += 10
        evidence.append('Standard Metasploit module header (requires Metasploit / Rapid7 upstream source)')

    msf_urls = [
        u for u in urls
        if re.search(r'metasploit|rapid7/metasploit-framework', u, re.I)
    ]
    if msf_urls:
        score += min(8, len(msf_urls) * 4)
        evidence.append(f"References Metasploit upstream URL(s) ({len(msf_urls)})")

    module_role = _infer_msf_module_role(filename or '', text)
    if module_role:
        score += 4
        evidence.append(f"Inferred module role: {module_role}")

    return score, evidence, module_role


def _score_profiles(signals: dict[str, Any]) -> list[tuple[str, int, list[str]]]:
    profiles: list[tuple[str, int, list[str]]] = []

    auth_urls = signals.get('auth_sms_api_urls') or []
    doc_urls = signals.get('documentation_urls') or []
    unique_hosts = signals.get('unique_http_hosts') or []
    http_count = int(signals.get('http_call_count') or 0)
    has_phone = bool(signals.get('has_phone_fields'))
    has_threading = bool(signals.get('has_threading'))
    privesc_score = int(signals.get('privesc_score') or 0)
    privesc_evidence = list(signals.get('privesc_evidence') or [])
    metasploit_score = int(signals.get('metasploit_score') or 0)
    metasploit_evidence = list(signals.get('metasploit_evidence') or [])

    if metasploit_score >= 8:
        profiles.append(('metasploit_module', metasploit_score, metasploit_evidence or [
            'Metasploit Framework module source detected',
        ]))

    if privesc_score >= 10:
        profiles.append(('linux_privesc_enum', privesc_score, privesc_evidence or [
            'Local enumeration / privilege-escalation hunting behavior detected',
        ]))

    # SMS abuse requires API-like endpoints AND phone usage — docs alone must not trigger.
    if len(auth_urls) >= 2 and has_phone and privesc_score < 10:
        score = len(auth_urls) * 4 + (4 if has_threading else 0) + min(http_count, 8)
        ev = [f"{len(auth_urls)} live API URL(s) for registration/SMS/OTP/password-reset (excluding documentation links)"]
        if has_phone:
            ev.append('Uses phone number variables as primary input')
        if has_threading:
            ev.append('Parallelizes requests with threading/multiprocessing')
        if unique_hosts:
            ev.append(f"Targets {len(unique_hosts)} distinct service(s): {', '.join(unique_hosts[:6])}")
        profiles.append(('sms_otp_abuse', score, ev))
    elif len(auth_urls) >= 3 and has_phone and privesc_score < 8:
        profiles.append(('sms_otp_abuse', len(auth_urls) * 3 + 5, [
            f"{len(auth_urls)} SMS/OTP-related API endpoints with phone-field usage",
        ]))

    if signals.get('download_exec') and privesc_score < 12:
        profiles.append(('script_dropper', 8 + int(signals.get('obfuscation_score') or 0), [
            'Contains download-and-execute patterns (PowerShell/curl/wscript style)',
        ]))

    if signals.get('webhook_exfil'):
        profiles.append(('credential_stealer', 10, [
            'References Discord/Telegram webhook or bot endpoints (common exfil channels)',
        ]))

    if signals.get('persistence'):
        profiles.append(('persistence_tool', 9, [
            'References registry Run keys, scheduled tasks, or similar persistence',
        ]))

    if signals.get('high_risk_pe_imports'):
        profiles.append(('process_injection', 10 + len(signals.get('high_risk_pe_imports') or []), [
            'PE imports indicate cross-process manipulation or injection primitives',
        ]))

    if signals.get('packer_hints'):
        profiles.append(('packed_loader', 7 + len(signals.get('packer_hints') or []), [
            'Binary packing or protection indicators present',
        ]))

    if http_count >= 3 and not auth_urls and privesc_score < 8:
        label = 'reference URLs' if doc_urls else 'external endpoints'
        profiles.append(('generic_network_tool', http_count, [
            f"References or contacts {http_count} HTTP {label}",
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
    if profile_id == 'sms_otp_abuse':
        return 'abuse_tool'
    if profile_id == 'linux_privesc_enum':
        return 'dual_use_security_tool'
    if profile_id == 'metasploit_module':
        return 'dual_use_security_tool'
    if profile_id in {'script_dropper', 'credential_stealer', 'persistence_tool', 'remote_access', 'packed_loader', 'process_injection'}:
        return 'malware'
    if profile_id == 'generic_network_tool':
        return 'unknown'
    return 'unknown'


def _build_summary(profile_id: str, signals: dict[str, Any], services: list[str]) -> str:
    if profile_id == 'linux_privesc_enum':
        return (
            "This behaves like a Linux privilege-escalation enumeration script (e.g. LinPEAS/PEASS-style). "
            "It hunts for misconfigurations, SUID binaries, sudo rules, cron jobs, capabilities, and credential paths, "
            "and embeds HackTricks/GTFOBins-style reference links for the analyst. "
            "Dual-use: legitimate in scoped pentests; hostile if run without authorization on production hosts."
        )
    if profile_id == 'metasploit_module':
        role = signals.get('metasploit_module_role')
        role_line = f" Inferred role: {role}." if role else ''
        lang = signals.get('language') or 'script'
        return (
            f"This is Metasploit Framework module source ({lang}), meant to run inside msfconsole — "
            f"not a standalone implant or C2 beacon.{role_line} "
            "Headers reference the official Metasploit project and Rapid7 upstream repository. "
            "Dual-use: legitimate in authorized penetration tests; investigate delivery context if found outside scope."
        )
    if profile_id == 'sms_otp_abuse':
        svc = ', '.join(services[:8]) if services else 'multiple online services'
        parallel = ' in parallel' if signals.get('has_threading') else ''
        return (
            f"This appears to be an SMS or OTP abuse tool — not traditional C2 malware. "
            f"It automates HTTP requests{parallel} to third-party registration or password-reset APIs "
            f"({svc}), likely to flood phone numbers with verification SMS. "
            f"VirusTotal may still show clean if the file has no known malware signature."
        )
    if profile_id == 'script_dropper':
        return (
            "This script behaves like a dropper or staged downloader: it retrieves external content "
            "and is structured to execute or invoke a follow-on payload."
        )
    if profile_id == 'credential_stealer':
        return "Behavior suggests credential theft or data exfiltration via messaging/webhook channels."
    if profile_id == 'process_injection':
        return "PE imports indicate process manipulation or injection — review as potential loader/implant."
    if profile_id == 'packed_loader':
        return "Packed or protected binary — often hides a second-stage payload."
    if profile_id == 'generic_network_tool':
        doc_n = len(signals.get('documentation_urls') or [])
        if doc_n:
            return (
                f"Script embeds {doc_n} documentation or reference URL(s) alongside local enumeration logic. "
                "Review the attack chain to determine if this is a security tool, installer, or something else."
            )
        return f"Automated network client referencing {len(signals.get('unique_http_hosts') or [])} external host(s)."
    return "Behavior could not be classified with high confidence — use the execution chain and IOC sections below."


def _recommended_action(profile_id: str, threat_category: str, combined_verdict: str) -> str:
    if profile_id == 'linux_privesc_enum':
        return (
            "Treat as offensive-security / post-exploitation enumeration. Authorized pentest use only — "
            "if found unmanaged on servers, investigate as unauthorized recon and rotate exposed credentials."
        )
    if profile_id == 'metasploit_module':
        return (
            "Treat as exploit-framework module source. Run only in isolated lab or authorized engagement — "
            "correlate with sibling files and delivery path if found on production endpoints."
        )
    if profile_id == 'sms_otp_abuse':
        return (
            "Do not run against phone numbers you do not own. Block or remove if deployed for harassment; "
            "report to platform abuse teams. VT clean does not mean benign."
        )
    if threat_category == 'malware' or combined_verdict in {'malicious', 'suspicious'}:
        return "Do not execute on production systems. Quarantine, block hash, and investigate delivery path."
    if combined_verdict == 'needs_review':
        return "Run only in an isolated VM if dynamic behavior is required. Correlate with scope and sibling files."
    return "Review findings below before execution."


def extract_script_signals(
    text: str,
    script_deep: dict[str, Any] | None = None,
    *,
    family_hints: dict[str, Any] | None = None,
    filename: str | None = None,
) -> dict[str, Any]:
    script_deep = script_deep or {}
    urls = list(script_deep.get('c2_urls') or [])
    for call in script_deep.get('http_calls') or []:
        u = call.get('url')
        if u and u not in urls:
            urls.append(u)

    auth_sms_api_urls = [u for u in urls if is_auth_sms_api_url(u)]
    documentation_urls = [u for u in urls if is_documentation_url(u)]
    privesc_score, privesc_evidence = _privesc_signal_strength(text, urls)
    metasploit_score, metasploit_evidence, module_role = _metasploit_signal_strength(
        text, urls, family_hints, filename=filename,
    )

    hosts = [_service_name_from_url(u) for u in urls if not is_documentation_url(u)]
    if not hosts:
        hosts = [_service_name_from_url(u) for u in urls[:8]]
    unique_hosts = _unique_preserve(hosts)

    return {
        'http_call_count': len(script_deep.get('http_calls') or []) or len(urls),
        'auth_sms_api_urls': auth_sms_api_urls,
        'documentation_urls': documentation_urls,
        'unique_http_hosts': unique_hosts,
        'has_phone_fields': bool(PHONE_FIELD.search(text)),
        'has_threading': bool(THREADING.search(text)),
        'download_exec': bool(DOWNLOAD_EXEC.search(text)),
        'webhook_exfil': bool(WEBHOOK_EXFIL.search(text)),
        'persistence': bool(PERSISTENCE.search(text)),
        'obfuscation_score': int(script_deep.get('obfuscation_score') or 0),
        'language': script_deep.get('language') or 'script',
        'privesc_score': privesc_score,
        'privesc_evidence': privesc_evidence,
        'metasploit_score': metasploit_score,
        'metasploit_evidence': metasploit_evidence,
        'metasploit_module_role': module_role,
    }


def interpret_behavior(
    bundle: dict[str, Any],
    *,
    static: dict[str, Any] | None = None,
    sample_text: str | None = None,
) -> dict[str, Any]:
    deep = bundle.get('deep_exclusive') or {}
    script = deep.get('script') or {}
    pe = deep.get('pe') or {}
    combined = bundle.get('combined_verdict') or 'unknown'

    text = sample_text or ''
    if not text and script.get('commands_reconstructed'):
        text = '\n'.join(script.get('commands_reconstructed') or [])

    signals: dict[str, Any] = extract_script_signals(
        text,
        script,
        family_hints=bundle.get('family_hints'),
        filename=bundle.get('filename'),
    )
    signals['high_risk_pe_imports'] = pe.get('high_risk_imports') or []
    signals['packer_hints'] = pe.get('packer_hints') or []

    profiles = _score_profiles(signals)
    if profiles:
        profile_id, score, evidence = profiles[0]
    else:
        profile_id = 'unknown_script' if script else 'unknown_binary'
        score, evidence = 0, ['No strong behavioral template matched — see technical chain below.']

    if profile_id == 'sms_otp_abuse':
        services = _unique_preserve([_service_name_from_url(u) for u in signals.get('auth_sms_api_urls') or []])
    elif profile_id == 'linux_privesc_enum':
        services = _unique_preserve(['HackTricks', 'GTFOBins'] + (signals.get('unique_http_hosts') or [])[:6])
    elif profile_id == 'metasploit_module':
        services = _unique_preserve(
            ['Metasploit Framework (Rapid7)', 'Metasploit.com']
            + (signals.get('unique_http_hosts') or [])[:6]
        )
    else:
        services = signals.get('unique_http_hosts') or []

    threat_category = _threat_category(profile_id)
    conf = _confidence(score)

    what_it_does = list(evidence)
    if profile_id == 'sms_otp_abuse' and services:
        what_it_does.append(
            f"Primary effect: trigger SMS/OTP via APIs operated by {', '.join(services[:10])}."
        )
    if profile_id == 'linux_privesc_enum':
        what_it_does.append(
            "Primary effect: enumerate the local Linux host for privilege-escalation paths."
        )
    if profile_id == 'metasploit_module':
        role = signals.get('metasploit_module_role')
        role_suffix = f" ({role})" if role else ''
        what_it_does.append(
            f"Primary effect: extend Metasploit Framework with module capability{role_suffix} — runs inside msfconsole, not standalone."
        )
    if script.get('execution_chain'):
        what_it_does.append(
            f"Technical detail: {len(script['execution_chain'])} reconstructed step(s) in the chain below."
        )

    if profile_id == 'sms_otp_abuse':
        network_label = 'Third-party API endpoints (not C2)'
    elif profile_id == 'linux_privesc_enum':
        network_label = 'Pentest reference links (documentation)'
    elif profile_id == 'metasploit_module':
        network_label = 'Framework source / reference links'
    elif signals.get('documentation_urls'):
        network_label = 'Reference / documentation URLs'
    else:
        network_label = 'Network endpoints'

    vt_context = None
    if profile_id == 'sms_otp_abuse':
        vt_context = 'VT often marks abuse tools as undetected — absence of detections does not imply safe use.'
    elif profile_id == 'linux_privesc_enum':
        vt_context = 'VT may flag LinPEAS as malicious or hacktool — that reflects dual-use offensive security tooling.'
    elif profile_id == 'metasploit_module':
        vt_context = (
            'VT often marks upstream Metasploit module source as undetected or hacktool — '
            'expected for dual-use exploit framework code pulled from Rapid7 repositories.'
        )

    return {
        'behavior_class': profile_id,
        'behavior_title': BEHAVIOR_LABELS.get(profile_id, profile_id),
        'confidence': conf,
        'confidence_score': min(100, score * 6),
        'threat_category': threat_category,
        'summary': _build_summary(profile_id, signals, services),
        'what_it_does': what_it_does,
        'notable_services': services[:12],
        'network_label': network_label,
        'evidence': evidence,
        'signals': {
            'http_calls': signals.get('http_call_count'),
            'auth_sms_api_urls': len(signals.get('auth_sms_api_urls') or []),
            'documentation_urls': len(signals.get('documentation_urls') or []),
            'privesc_score': signals.get('privesc_score'),
            'metasploit_score': signals.get('metasploit_score'),
            'unique_services': len(services),
            'has_phone_fields': signals.get('has_phone_fields'),
            'has_threading': signals.get('has_threading'),
        },
        'recommended_action': _recommended_action(profile_id, threat_category, combined),
        'vt_context': vt_context,
    }
