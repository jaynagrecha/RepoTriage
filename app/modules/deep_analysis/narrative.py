from __future__ import annotations

from typing import Any


def build_attack_chain(bundle: dict[str, Any]) -> list[dict[str, str]]:
    chain: list[dict[str, str]] = []
    script = (bundle.get('deep_exclusive') or {}).get('script') or {}
    sandbox = bundle.get('sandbox_lite') or {}
    yara = bundle.get('yara') or {}
    mb = (bundle.get('file_intel') or {}).get('malwarebazaar') or {}

    for phase in script.get('kill_chain_phases') or []:
        chain.append({'stage': phase.get('phase', ''), 'title': phase.get('label', ''), 'source': 'script_deep'})

    for step in script.get('execution_chain') or []:
        chain.append({
            'stage': step.get('type', 'command'),
            'title': f"Step {step.get('step')}: {step.get('command', '')[:120]}",
            'source': 'reconstructed_command',
        })

    for behavior in sandbox.get('behaviors') or []:
        chain.append({'stage': 'behavior', 'title': behavior.replace('_', ' ').title(), 'source': 'sandbox_lite'})

    for match in (yara.get('matches') or [])[:5]:
        chain.append({'stage': 'signature', 'title': f"YARA: {match.get('rule')}", 'source': 'yara'})

    if mb.get('found'):
        fam = mb.get('family') or 'Known malware'
        chain.append({'stage': 'intel', 'title': f"MalwareBazaar: {fam}", 'source': 'malwarebazaar'})

    if not chain:
        chain.append({'stage': 'review', 'title': 'No automated kill chain — manual review recommended', 'source': 'system'})

    return chain[:20]


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

    headline_parts = []
    if mb.get('found'):
        headline_parts.append(f"Known sample ({mb.get('family')})")
    elif family.get('primary_family_hint'):
        headline_parts.append(f"Likely {family.get('primary_family_hint')} family")
    if script.get('likely_stages', 0) >= 3:
        headline_parts.append('multi-stage script')
    if pe.get('packer_hints'):
        headline_parts.append('packed binary')
    headline = ' — '.join(headline_parts) if headline_parts else f'Deep investigation: {combined}'

    bullets: list[str] = []
    if script.get('execution_chain'):
        bullets.append(f"Reconstructed {len(script['execution_chain'])} execution step(s) showing how the payload chains commands.")
    if script.get('c2_urls'):
        bullets.append(f"Identified {len(script['c2_urls'])} network callback URL(s) from deep script/PE string analysis.")
    if pe.get('high_risk_imports'):
        cats = ', '.join(sorted((pe.get('categories_detected') or {}).keys())) or 'none'
        bullets.append(
            f"High-confidence PE imports: {len(pe['high_risk_imports'])} "
            f"in category/categories: {cats}."
        )
    elif pe.get('informational_imports'):
        names = ', '.join(i['import'].split(':')[-1] for i in pe['informational_imports'][:4])
        not_found = ', '.join(pe.get('categories_not_detected') or [])
        bullets.append(
            f"Informational PE imports only ({names}) — common in legitimate DLLs. "
            f"No high-confidence anti-debug, network, or persistence imports detected"
            f"{(' (scanned, not found: ' + not_found + ')' if not_found else '')}."
        )
    if pe.get('packer_hints'):
        bullets.append(f"Packer/protection indicators: {'; '.join(pe['packer_hints'][:2])}")
    if (yara.get('matches') or []):
        bullets.append(f"YARA matched {len(yara['matches'])} rule(s): {', '.join(m['rule'] for m in yara['matches'][:3])}")
    if ioc_rep.get('malicious_urls', 0) > 0:
        bullets.append(f"Live VirusTotal URL reputation: {ioc_rep['malicious_urls']} malicious URL(s) in this file.")
    if delta.get('exclusive_count', 0) > 0:
        bullets.append(f"Found {delta['exclusive_count']} indicator(s) and behaviors not surfaced by fast static analysis alone.")
    if mb.get('found'):
        tags = ', '.join((mb.get('tags') or [])[:5])
        bullets.append(f"MalwareBazaar tags: {tags or 'none listed'}")
    if not bullets:
        bullets.append('Deep modules ran but found limited additional signal beyond static analysis — try Re-analyse static first, then Deep again.')

    assessment = 'Treat as hostile infrastructure. Block hashes/URLs, isolate host, and hunt for sibling files in the same job.'
    if combined == 'suspicious':
        assessment = 'Multiple moderate signals detected — investigate in isolation before execution; do not treat as confirmed malware on a single weak indicator.'
    elif combined in {'clean', 'needs_review'}:
        assessment = 'Deep modules did not add strong malicious signal. Correlate with VT and sibling files before closing.'

    return {
        'headline': headline,
        'summary_bullets': bullets,
        'assessment': assessment,
        'static_vs_deep': 'Static analysis = fast RE and verdict. Deep analysis adds execution chain reconstruction, PE import risk, live URL/hash intel, YARA, similarity, and CTI enrichment.',
    }
