from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from .cti_query_policy import count_exact_cti_anchors


def _uniq(items):
    out=[]; seen=set()
    for x in items or []:
        if x is None: continue
        s=str(x).strip()
        if not s or s.lower() in seen: continue
        seen.add(s.lower()); out.append(s)
    return out


def _safe(v, default='Unknown'):
    if v is None: return default
    s=str(v).strip()
    return s if s else default


def _families(result: dict) -> list[str]:
    fams=[]
    vt_fam=((result.get('vt') or {}).get('family') or {}).get('name')
    if vt_fam and vt_fam.lower() not in {'unknown','none',''}:
        fams.append(vt_fam)
    ti=result.get('threat_intel') or {}
    tf_sum=((ti.get('threatfox') or {}).get('summary') or {})
    fams += tf_sum.get('malware_families') or []
    mb_sum=((ti.get('malwarebazaar') or {}).get('summary') or {})
    fams += mb_sum.get('families') or []
    uh_sum=((ti.get('urlhaus') or {}).get('summary') or {})
    fams += uh_sum.get('families') or []
    return _uniq([f for f in fams if str(f).lower() not in {'unknown','none'}])


def _malicious_files(result: dict):
    rows=[]
    for f in result.get('files') or []:
        verdict=str(f.get('vt_verdict') or '').lower()
        if verdict == 'malicious':
            rows.append({
                'name': f.get('original_name') or f.get('filename') or f.get('path') or 'unknown',
                'sha256': f.get('sha256'),
                'vt_link': f.get('vt_link'),
                'type': f.get('file_type'),
                'parent_archive': f.get('parent_archive'),
            })
    return rows


def _suspicious_files(result: dict):
    rows=[]
    for f in result.get('files') or []:
        verdict=str(f.get('vt_verdict') or '').lower()
        if verdict == 'suspicious':
            rows.append({
                'name': f.get('original_name') or f.get('filename') or f.get('path') or 'unknown',
                'sha256': f.get('sha256'),
                'vt_link': f.get('vt_link'),
                'type': f.get('file_type'),
            })
    return rows


def _infra_counts(result: dict) -> dict:
    infra=result.get('infrastructure') or {}
    return {
        'probable_c2': len(infra.get('probable_c2') or []),
        'payload_delivery': len(infra.get('payload_delivery') or []),
        'malware_downloads': len(infra.get('malware_downloads') or []),
        'control_channels': len(infra.get('control_channels') or []),
        'exfil_channels': len(infra.get('exfil_channels') or []),
        'config_sources': len(infra.get('config_sources') or []),
        'known_bad_infrastructure': len(infra.get('known_bad_infrastructure') or []),
    }


def _top_infra(result: dict, limit=8):
    infra=result.get('infrastructure') or {}
    rows=[]
    for bucket,label in [
        ('probable_c2','Probable C2'),
        ('payload_delivery','Payload Delivery'),
        ('malware_downloads','Malware Download'),
        ('exfil_channels','Exfiltration Channel'),
        ('control_channels','Control Channel'),
        ('config_sources','Config Source'),
        ('known_bad_infrastructure','Known Bad Infrastructure'),
    ]:
        for item in infra.get(bucket) or []:
            if isinstance(item, dict):
                rows.append({
                    'indicator': item.get('indicator'),
                    'role': label,
                    'confidence': item.get('confidence') or item.get('confidence_level') or 'Medium',
                    'source': item.get('source') or 'RepoTriage',
                    'malware': item.get('malware') or item.get('families') or item.get('threat'),
                    'reference': item.get('reference'),
                })
    return rows[:limit]


def _mitre_highlights(result: dict, limit=8):
    rows=[]
    for t in ((result.get('mitre') or {}).get('techniques') or []):
        rows.append({
            'id': t.get('id'),
            'name': t.get('name'),
            'tactic': t.get('tactic'),
            'confidence': t.get('confidence'),
            'sources': t.get('sources') or [],
        })
    order={'High':0,'Medium':1,'Low':2}
    rows.sort(key=lambda x: (order.get(x.get('confidence'), 1), x.get('id') or ''))
    return rows[:limit]


def _risk_level(result: dict) -> str:
    malicious = len(_malicious_files(result))
    suspicious = len(_suspicious_files(result))
    anchors = count_exact_cti_anchors(result)
    exact_c2 = int(anchors.get('exact_probable_c2') or 0)
    mb = int(anchors.get('malwarebazaar_hash_hits') or 0)
    exact_ioc = int(anchors.get('exact_threatfox') or 0) + int(anchors.get('exact_urlhaus') or 0)

    if malicious >= 2 or mb >= 1 or (malicious >= 1 and exact_c2 >= 1):
        return 'Critical'
    if malicious == 1 or suspicious or exact_c2 >= 1 or exact_ioc >= 2:
        return 'High'
    if exact_ioc >= 1 or (result.get('file_stats') or {}).get('iocs'):
        return 'Medium'
    return 'Low'


def generate_attack_narrative(result: dict) -> dict:
    source=result.get('source') or {}
    root=result.get('root_file') or {}
    stats=result.get('file_stats') or {}
    extraction=result.get('extraction') or {}
    families=_families(result)
    malicious=_malicious_files(result)
    suspicious=_suspicious_files(result)
    infra_counts=_infra_counts(result)
    infra_rows=_top_infra(result)
    mitre_rows=_mitre_highlights(result)
    risk=_risk_level(result)
    family_text=', '.join(families) if families else 'Unknown / not confidently attributed'
    total_files=stats.get('total_listed') or len(result.get('files') or [])
    children=stats.get('extracted_children') or 0
    iocs=stats.get('iocs') or 0

    likely=[]
    if infra_counts['probable_c2']:
        likely.append('command-and-control communication')
    if infra_counts['payload_delivery'] or infra_counts['malware_downloads']:
        likely.append('payload delivery or follow-on download')
    if infra_counts['exfil_channels']:
        likely.append('data exfiltration channel usage')
    if any('steal' in f.lower() or 'lumma' in f.lower() or 'redline' in f.lower() for f in families):
        likely.append('credential or browser-data theft')
    if not likely and malicious:
        likely.append('malicious payload staging and execution support')
    if not likely:
        likely.append('unknown objective based on currently available static evidence')

    bullets=[]
    bullets.append(f"The submitted GitHub-hosted file `{_safe(root.get('filename'))}` was acquired server-side and analyzed without returning sample bytes to the browser.")
    if extraction.get('root_is_archive') or children:
        bullets.append(f"The root file appears to be an archive or container. RepoTriage listed {children} extracted child file(s) from {total_files} total analyzed file record(s).")
    else:
        bullets.append('The submitted item was analyzed as a standalone file with no extracted child archive contents detected.')
    if malicious:
        bullets.append(f"VirusTotal marked {len(malicious)} file(s) as malicious. These files should be treated as confirmed malicious indicators for triage purposes.")
    elif suspicious:
        bullets.append(f"VirusTotal marked {len(suspicious)} file(s) as suspicious, but no file was classified as malicious from the current enrichment set.")
    else:
        bullets.append('No file was marked malicious by VirusTotal in the current enrichment result. Continue reviewing CTI and IOC context before closing as benign.')
    if families:
        bullets.append(f"Observed family/signature evidence points to: {family_text}.")
    if iocs:
        bullets.append(f"Static IOC extraction found {iocs} indicator(s), which were enriched against configured CTI sources.")
    if sum(infra_counts.values()):
        bullets.append(f"Infrastructure classification identified {infra_counts['probable_c2']} probable C2 item(s), {infra_counts['payload_delivery']} payload delivery item(s), and {infra_counts['exfil_channels']} exfil/control-channel item(s).")
    if mitre_rows:
        bullets.append(f"MITRE ATT&CK mapping produced {len((result.get('mitre') or {}).get('techniques') or [])} technique candidate(s), led by {', '.join(_uniq([m.get('id') for m in mitre_rows[:4]]))}.")

    recommended=[]
    if malicious:
        recommended += ['Block or monitor all malicious file hashes in endpoint, proxy, EDR and SIEM controls.', 'Escalate malicious child payloads to malware analysis or sandboxing workflow if dynamic behavior is required.']
    if infra_rows:
        recommended += ['Review and block high-confidence infrastructure indicators where operationally appropriate.', 'Pivot on the listed infrastructure in VT Enterprise, DNS logs, proxy logs and endpoint telemetry.']
    if source.get('display_url'):
        recommended.append('Preserve the original GitHub URL, commit/file path, hashes and CTI enrichment as investigation evidence.')
    if not recommended:
        recommended.append('Continue manual review; current static evidence is limited.')

    system_notes=[]
    if extraction.get('errors'):
        system_notes.append('One or more files could not be fully processed by the backend extraction layer. This is an operational processing note, not an analyst action. Review the Extraction Issues section for details.')

    markdown=[]
    markdown.append('# RepoTriage Attack Narrative')
    markdown.append('')
    markdown.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    markdown.append(f"Source: {source.get('display_url') or source.get('url') or 'Unknown'}")
    markdown.append(f"Overall Risk: **{risk}**")
    markdown.append(f"Family / Signature: **{family_text}**")
    markdown.append('')
    markdown.append('## Narrative')
    markdown += [f"- {b}" for b in bullets]
    markdown.append('')
    markdown.append('## Likely Objective')
    markdown += [f"- {x}" for x in _uniq(likely)]
    if malicious:
        markdown.append('')
        markdown.append('## Malicious Files')
        for f in malicious[:12]:
            markdown.append(f"- `{f.get('name')}` — SHA256 `{f.get('sha256') or 'unknown'}`" + (f" — [VT]({f.get('vt_link')})" if f.get('vt_link') else ''))
    if infra_rows:
        markdown.append('')
        markdown.append('## Observed Infrastructure')
        for row in infra_rows:
            markdown.append(f"- `{row.get('indicator')}` — {row.get('role')} — confidence: {row.get('confidence')} — source: {row.get('source')}")
    if mitre_rows:
        markdown.append('')
        markdown.append('## MITRE ATT&CK Highlights')
        for m in mitre_rows:
            markdown.append(f"- {m.get('id')} — {m.get('name')} ({m.get('tactic')}) — {m.get('confidence')}")
    markdown.append('')
    markdown.append('## Recommended Analyst Actions')
    markdown += [f"- {r}" for r in recommended]
    if system_notes:
        markdown.append('')
        markdown.append('## System Notes')
        markdown += [f"- {x}" for x in system_notes]

    return {
        'risk': risk,
        'family': family_text,
        'likely_objectives': _uniq(likely),
        'narrative_bullets': bullets,
        'malicious_files': malicious,
        'suspicious_files': suspicious,
        'infrastructure_highlights': infra_rows,
        'mitre_highlights': mitre_rows,
        'recommended_actions': recommended,
        'system_notes': system_notes,
        'markdown': '\n'.join(markdown),
    }
