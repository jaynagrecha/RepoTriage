from __future__ import annotations

from typing import Any

from .behavior import interpret_behavior


def build_attack_chain(bundle: dict[str, Any]) -> list[dict[str, str]]:
    chain: list[dict[str, str]] = []
    behavior = bundle.get('behavior') or {}
    script = (bundle.get('deep_exclusive') or {}).get('script') or {}
    sandbox = bundle.get('sandbox_lite') or {}
    yara = bundle.get('yara') or {}
    mb = (bundle.get('file_intel') or {}).get('malwarebazaar') or {}

    if behavior.get('behavior_title'):
        chain.append({
            'stage': 'behavior',
            'title': f"{behavior.get('behavior_title')} ({behavior.get('confidence', 'unknown')} confidence)",
            'source': 'behavior_interpreter',
        })

    for call in (script.get('http_calls') or [])[:12]:
        purpose = call.get('purpose') or 'http'
        title = f"{call.get('method', 'HTTP')} → {call.get('url', '')[:100]}"
        if purpose == 'auth/sms/otp':
            title = f"SMS/OTP trigger: {call.get('method')} {call.get('url', '')[:90]}"
        elif purpose == 'reference':
            title = f"Pentest reference link: {call.get('url', '')[:100]}"
        chain.append({'stage': purpose, 'title': title, 'source': 'http_call'})

    for phase in script.get('kill_chain_phases') or []:
        chain.append({'stage': phase.get('phase', ''), 'title': phase.get('label', ''), 'source': 'script_deep'})

    for step in script.get('execution_chain') or []:
        if step.get('type') in {'http', 'auth/sms/otp'}:
            continue
        chain.append({
            'stage': step.get('type', 'command'),
            'title': f"Step {step.get('step')}: {step.get('command', '')[:120]}",
            'source': 'reconstructed_command',
        })

    for behavior_label in sandbox.get('behaviors') or []:
        chain.append({'stage': 'behavior', 'title': behavior_label.replace('_', ' ').title(), 'source': 'sandbox_lite'})

    for match in (yara.get('matches') or [])[:5]:
        chain.append({'stage': 'signature', 'title': f"YARA: {match.get('rule')}", 'source': 'yara'})

    if mb.get('found'):
        fam = mb.get('family') or 'Known malware'
        chain.append({'stage': 'intel', 'title': f"MalwareBazaar: {fam}", 'source': 'malwarebazaar'})

    if not chain:
        chain.append({'stage': 'review', 'title': 'No automated kill chain — manual review recommended', 'source': 'system'})

    return chain[:24]


def build_deep_narrative(bundle: dict[str, Any]) -> dict[str, Any]:
    deep = bundle.get('deep_exclusive') or {}
    script = deep.get('script') or {}
    pe = deep.get('pe') or {}
    mb = (bundle.get('file_intel') or {}).get('malwarebazaar') or {}
    yara = bundle.get('yara') or {}
    ioc_rep = bundle.get('ioc_reputation') or {}
    family = bundle.get('family_hints') or {}
    delta = deep.get('delta') or {}
    combined = bundle.get('combined_verdict') or 'unknown'
    behavior = bundle.get('behavior') or interpret_behavior(bundle)

    headline_parts = []
    if behavior.get('behavior_title'):
        headline_parts.append(behavior['behavior_title'])
    if mb.get('found'):
        headline_parts.append(f"Known sample ({mb.get('family')})")
    elif family.get('primary_family_hint'):
        headline_parts.append(f"Likely {family.get('primary_family_hint')} family")
    if pe.get('packer_hints'):
        headline_parts.append('packed binary')
    headline = ' — '.join(headline_parts) if headline_parts else f'Deep investigation: {combined}'

    bullets: list[str] = []
    if behavior.get('summary'):
        bullets.append(behavior['summary'])
    semantic = bundle.get('semantic') or behavior.get('semantic') or {}
    if semantic.get('capabilities'):
        cap_preview = ', '.join(
            c.get('label', c.get('id', '')) for c in semantic['capabilities'][:5]
        )
        bullets.append(f"Code understanding: {cap_preview}.")
    for item in behavior.get('what_it_does') or []:
        if item not in bullets:
            bullets.append(item)
    if script.get('http_calls') and not behavior.get('summary'):
        bullets.append(
            f"Identified {len(script['http_calls'])} HTTP call(s) to external services — see behavior interpretation and attack chain."
        )
    if pe.get('high_risk_imports'):
        cats = ', '.join(sorted((pe.get('categories_detected') or {}).keys())) or 'none'
        bullets.append(f"High-confidence PE imports: {len(pe['high_risk_imports'])} in {cats}.")
    elif pe.get('informational_imports'):
        names = ', '.join(i['import'].split(':')[-1] for i in pe['informational_imports'][:4])
        bullets.append(f"Informational PE imports only ({names}) — common in legitimate DLLs.")
    if (yara.get('matches') or []):
        bullets.append(f"YARA matched {len(yara['matches'])} rule(s): {', '.join(m['rule'] for m in yara['matches'][:3])}")
    if ioc_rep.get('malicious_urls', 0) > 0:
        bullets.append(f"Live VirusTotal URL reputation: {ioc_rep['malicious_urls']} malicious URL(s).")
    if delta.get('exclusive_count', 0) > 0:
        bullets.append(f"Found {delta['exclusive_count']} technical indicator(s) beyond fast static analysis.")
    if mb.get('found'):
        tags = ', '.join((mb.get('tags') or [])[:5])
        bullets.append(f"MalwareBazaar tags: {tags or 'none listed'}")
    if not bullets:
        bullets.append('Deep modules ran but found limited additional signal beyond static analysis.')

    assessment = behavior.get('recommended_action') or 'Review findings before execution.'
    if behavior.get('vt_context'):
        assessment = f"{assessment} {behavior['vt_context']}"

    return {
        'headline': headline,
        'summary_bullets': bullets[:8],
        'assessment': assessment,
        'behavior': behavior,
        'static_vs_deep': (
            'Static analysis = fast RE and verdict. Deep analysis adds behavioral interpretation, '
            'execution chain reconstruction, PE import risk, and CTI — not just raw IOC lists.'
        ),
    }
