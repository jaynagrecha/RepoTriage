from __future__ import annotations

from typing import Any

# Static analysis score thresholds (conservative — prefer needs_review over suspicious)
STATIC_MALICIOUS_SCORE = 65
STATIC_SUSPICIOUS_SCORE = 38
STATIC_REVIEW_SCORE = 15

# Labels/signal categories treated as high-confidence on their own
HIGH_CONFIDENCE_STATIC_LABELS = frozenset({
    'windows_script_dropper',
    'obfuscated_script_dropper',
    'powershell_downloader',
    'discord_webhook',
})

HIGH_CONFIDENCE_YARA_RULES = frozenset({
    'Suspicious_WScript_Dropper',
    'Suspicious_PowerShell_Encoded',
})

# PE / binary imports — high confidence only (not VirtualAlloc alone)
HIGH_CONFIDENCE_IMPORT_MARKERS = frozenset({
    'writeprocessmemory',
    'createremotethread',
    'ntcreatethreadex',
    'openprocess',
    'queueuserapc',
    'isdebuggerpresent',
    'checkremotedebuggerpresent',
    'ntqueryinformationprocess',
})

# Family string hints — weak patterns excluded from verdict escalation
WEAK_FAMILY_HINTS = frozenset({
    'powershell_dropper',
    'metasploit',
})

MALICIOUS_SCRIPT_PHASES = frozenset({'download', 'execute', 'persistence', 'exfil'})


def static_verdict_from_score(signals: list[dict[str, Any]], score: int) -> str:
    high = [s for s in signals if int(s.get('weight') or 0) >= 35 or s.get('label') in HIGH_CONFIDENCE_STATIC_LABELS]
    medium = [s for s in signals if 18 <= int(s.get('weight') or 0) < 35]

    if score >= STATIC_MALICIOUS_SCORE and (high or len(medium) >= 2):
        return 'malicious'
    if score >= STATIC_SUSPICIOUS_SCORE and (high or medium):
        return 'suspicious'
    if score >= STATIC_REVIEW_SCORE:
        return 'needs_review'
    return 'clean'


def static_malicious_justified(static_verdict: dict[str, Any] | None) -> bool:
    if not static_verdict:
        return False
    if static_verdict.get('verdict') != 'malicious':
        return False
    signals = static_verdict.get('signals') or []
    return any(s.get('label') in HIGH_CONFIDENCE_STATIC_LABELS for s in signals) or int(static_verdict.get('score') or 0) >= STATIC_MALICIOUS_SCORE


def yara_verdict(matches: list[dict[str, Any]]) -> str:
    if not matches:
        return 'clean'
    rules = {m.get('rule') for m in matches}
    if rules & HIGH_CONFIDENCE_YARA_RULES:
        return 'malicious'
    if len(matches) >= 2:
        return 'suspicious'
    return 'needs_review'


def sandbox_lite_verdict(result: dict[str, Any]) -> str:
    behaviors = set(result.get('behaviors') or [])
    mode = result.get('mode') or ''

    if mode == 'script_behavioral':
        has_download = 'download' in behaviors
        has_shell = 'shell' in behaviors
        has_persist = 'persistence' in behaviors
        if has_download and (has_shell or 'execute' in str(result.get('script') or {})):
            return 'malicious'
        if has_download and has_persist:
            return 'malicious'
        if len(behaviors) >= 3 and has_download:
            return 'suspicious'
        if len(behaviors) >= 2 and (has_download or has_shell):
            return 'needs_review'
        return 'clean'

    # PE/binary — do not elevate on embedded URLs or single string hit alone
    if 'process_injection' in behaviors and 'anti_debug' in behaviors:
        return 'suspicious'
    if 'process_injection' in behaviors:
        return 'needs_review'
    if 'anti_debug' in behaviors:
        return 'needs_review'
    return 'clean'


def family_verdict(family_hints: dict[str, Any] | None) -> str | None:
    if not family_hints:
        return None
    strong = [
        m for m in family_hints.get('family_matches') or []
        if m.get('family') not in WEAK_FAMILY_HINTS and int(m.get('hits') or 0) >= 1
    ]
    if not strong:
        return None
    if len(strong) >= 2:
        return 'suspicious'
    fam = strong[0].get('family')
    if fam in {'asyncrat', 'remcos', 'redline', 'agenttesla', 'formbook', 'qakbot', 'cobalt_strike'}:
        return 'suspicious'
    return 'needs_review'


def script_malicious_stage_count(script_deep: dict[str, Any] | None) -> int:
    if not script_deep:
        return 0
    phases = {p.get('phase') for p in script_deep.get('kill_chain_phases') or []}
    return len(phases & MALICIOUS_SCRIPT_PHASES)


def vt_url_verdict(ioc_reputation: dict[str, Any] | None) -> str | None:
    if not ioc_reputation:
        return None
    results = ioc_reputation.get('results') or []
    strong = [r for r in results if int(r.get('malicious') or 0) >= 3]
    weak = [r for r in results if int(r.get('malicious') or 0) >= 1]
    if strong:
        return 'malicious'
    if weak:
        return 'suspicious'
    return None


def combine_deep_verdict(
    *,
    static: dict[str, Any] | None,
    yara: dict[str, Any] | None,
    sandbox_lite: dict[str, Any] | None,
    file_intel: dict[str, Any] | None,
    ioc_reputation: dict[str, Any] | None,
    family_hints: dict[str, Any] | None,
    deep_exclusive: dict[str, Any] | None,
) -> tuple[str, list[dict[str, str]]]:
    """Return combined verdict + evidence list. Conservative: 2 strong OR 1 strong + 1 moderate for malicious."""
    strong: list[tuple[str, str]] = []
    moderate: list[tuple[str, str]] = []
    weak: list[tuple[str, str]] = []

    static_v = (static or {}).get('static_verdict') or {}
    sv = static_v.get('verdict')
    if sv == 'malicious' and static_malicious_justified(static_v):
        strong.append(('static', 'High-confidence static signals'))
    elif sv == 'suspicious' and int(static_v.get('score') or 0) >= STATIC_SUSPICIOUS_SCORE:
        moderate.append(('static', f"Static score {static_v.get('score')}"))
    elif sv == 'needs_review':
        weak.append(('static', 'Static needs review'))

    mb = (file_intel or {}).get('malwarebazaar') or {}
    if mb.get('found'):
        strong.append(('malwarebazaar', f"Known sample ({mb.get('family') or 'listed'})"))

    vt_v = vt_url_verdict(ioc_reputation)
    if vt_v == 'malicious':
        strong.append(('vt_url', 'VT URL detections >= 3'))
    elif vt_v == 'suspicious':
        moderate.append(('vt_url', 'VT URL flagged'))

    yv = yara_verdict((yara or {}).get('matches') or [])
    if yv == 'malicious':
        strong.append(('yara', 'Dropper/YARA rule match'))
    elif yv == 'suspicious':
        moderate.append(('yara', 'Multiple YARA matches'))
    elif yv == 'needs_review':
        weak.append(('yara', 'Single low-context YARA hit'))

    sbv = sandbox_lite_verdict(sandbox_lite or {})
    if sbv == 'malicious':
        strong.append(('sandbox_lite', 'Script behavioral chain'))
    elif sbv == 'suspicious':
        moderate.append(('sandbox_lite', 'Behavioral markers'))
    elif sbv == 'needs_review':
        weak.append(('sandbox_lite', 'Weak behavioral hint'))

    fv = family_verdict(family_hints)
    if fv == 'suspicious':
        moderate.append(('family', 'Family string hints'))
    elif fv == 'needs_review':
        weak.append(('family', 'Weak family hint'))

    script = (deep_exclusive or {}).get('script') or {}
    mstages = script_malicious_stage_count(script)
    if mstages >= 3:
        strong.append(('script_chain', f'{mstages} attack phases'))
    elif mstages == 2:
        moderate.append(('script_chain', f'{mstages} attack phases'))

    pe = (deep_exclusive or {}).get('pe') or {}
    if pe.get('high_risk_imports'):
        moderate.append(('pe_imports', 'High-confidence PE imports'))
    elif pe.get('informational_imports'):
        weak.append(('pe_imports', 'Informational PE imports only'))

    evidence = [
        {'tier': tier, 'source': src, 'detail': detail}
        for tier, items in [('strong', strong), ('moderate', moderate), ('weak', weak)]
        for src, detail in items
    ]

    if len(strong) >= 2 or (len(strong) >= 1 and len(moderate) >= 1):
        return 'malicious', evidence
    if len(strong) >= 1 or len(moderate) >= 2:
        return 'suspicious', evidence
    if moderate or (weak and sv in {'suspicious', 'needs_review'}):
        return 'needs_review', evidence
    if sv == 'clean':
        return 'clean', evidence
    return sv or 'clean', evidence
