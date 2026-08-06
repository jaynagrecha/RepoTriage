from __future__ import annotations

import csv
import io
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone

from .cti_query_policy import count_cti_sourced_infra, count_exact_cti_anchors, threatfox_match_is_exact


def _as_list(v):
    return v if isinstance(v, list) else []


def _uniq(seq):
    out=[]; seen=set()
    for x in seq:
        if x is None: continue
        s=str(x).strip()
        if not s: continue
        k=s.lower()
        if k not in seen:
            seen.add(k); out.append(s)
    return out


def _family_candidates(result: dict) -> list[dict]:
    c = []
    anchors = count_exact_cti_anchors(result)
    vt = result.get('vt') or {}
    vt_family = vt.get('family') if isinstance(vt.get('family'), dict) else {}
    if anchors.get('vt_malicious'):
        popular = vt.get('popular_threat_label') or vt_family.get('popular_threat_label')
        primary = vt_family.get('primary_family') or vt_family.get('name')
        labels = vt.get('family_labels') or vt_family.get('family_labels') or []
        conf = vt_family.get('confidence', 0) or (result.get('family') or {}).get('confidence', 0)
        if popular and str(popular).lower() not in {'unknown', 'none', ''}:
            c.append({'family': popular, 'source': 'VirusTotal', 'confidence': max(int(conf or 0), 85)})
        if primary and str(primary).lower() not in {'unknown', 'none', ''}:
            c.append({'family': primary, 'source': 'VirusTotal', 'confidence': conf})
        for label in labels:
            if label and str(label).lower() not in {'unknown', 'none', ''}:
                c.append({'family': label, 'source': 'VirusTotal', 'confidence': conf or 70})

    ti = result.get('threat_intel') or {}
    mb = (ti.get('malwarebazaar') or {}).get('results') or []
    for r in mb:
        if not r.get('found'):
            continue
        for key in ('family', 'signature'):
            v = r.get(key)
            if v and str(v).lower() not in {'unknown', 'none'}:
                c.append({'family': v, 'source': 'MalwareBazaar', 'confidence': 90})

    tf = (ti.get('threatfox') or {}).get('found') or []
    for row in tf:
        queried = row.get('indicator') or ''
        for m in row.get('matches') or []:
            if not threatfox_match_is_exact(queried, str(m.get('ioc') or '')):
                continue
            v = m.get('malware') or m.get('malware_printable')
            if v and str(v).lower() not in {'unknown', 'none'}:
                c.append({'family': v, 'source': 'ThreatFox', 'confidence': m.get('confidence_level') or 60})

    uh = (ti.get('urlhaus') or {}).get('results') or []
    for r in uh:
        if not r.get('found'):
            continue
        for v in _as_list(r.get('families')):
            if v and str(v).lower() not in {'unknown', 'none'}:
                c.append({'family': v, 'source': 'URLHaus', 'confidence': 75})
    return c


def build_cti_dashboard(result: dict) -> dict:
    ti=result.get('threat_intel') or {}
    infra=result.get('infrastructure') or {}
    mitre=result.get('mitre') or {}
    iocs=result.get('iocs') or {}
    fams=_family_candidates(result)
    fam_counter=Counter([x['family'] for x in fams])
    primary=fam_counter.most_common(1)[0][0] if fam_counter else 'Unknown'
    anchors = count_exact_cti_anchors(result)
    sources=sorted(set([x.get('source') for x in fams if x.get('source')]))
    return {
        'primary_family': primary,
        'families': [{'name':k,'count':v,'sources': sorted(set(x['source'] for x in fams if x['family']==k))} for k,v in fam_counter.most_common()],
        'source_count': len(sources),
        'sources': sources,
        'threatfox_matches': anchors.get('exact_threatfox', 0),
        'malwarebazaar_matches': (ti.get('malwarebazaar') or {}).get('summary',{}).get('found',0),
        'urlhaus_matches': anchors.get('exact_urlhaus', 0),
        'feodo_matches': (ti.get('feodo') or {}).get('summary',{}).get('matches',0),
        'sslbl_matches': (ti.get('sslbl') or {}).get('summary',{}).get('matches',0),
        'ioc_count': sum(len(v) for k,v in iocs.items() if k != 'ioc_details' and isinstance(v,list)),
        'infrastructure_count': sum(len(v) for v in infra.values() if isinstance(v,list)),
        'mitre_count': (mitre.get('summary') or {}).get('count',0),
        'cti_anchors': anchors,
        'attribution_policy': 'exact_ioc_or_hash_only',
        'risk': _cti_risk_level(result, anchors),
    }


def _cti_risk_level(result: dict, anchors: dict | None = None) -> str:
    """Conservative dashboard risk — hash or exact IOC anchors only."""
    anchors = anchors or count_exact_cti_anchors(result)
    vt_m = int(anchors.get('vt_malicious') or 0)
    mb = int(anchors.get('malwarebazaar_hash_hits') or 0)
    exact_c2 = int(anchors.get('exact_probable_c2') or 0)
    exact_ioc = int(anchors.get('exact_threatfox') or 0) + int(anchors.get('exact_urlhaus') or 0)
    if vt_m >= 2 or mb >= 1 or (vt_m >= 1 and exact_c2 >= 1):
        return 'Critical'
    if vt_m >= 1 or exact_c2 >= 1 or (exact_ioc >= 2 and mb == 0):
        return 'High'
    if exact_ioc >= 1 or int((result.get('file_stats') or {}).get('suspicious') or 0) >= 1:
        return 'Medium'
    if int((result.get('file_stats') or {}).get('iocs') or 0) > 0:
        return 'Low'
    return 'Low'


def _ioc_canonical_id(value: str) -> tuple[str, str]:
    """Return (node_id, node_type) for an indicator string."""
    s = str(value or '').strip()
    low = s.lower()
    if low.startswith(('http://', 'https://')):
        return f'ioc:url:{low}', 'url'
    if all(c.isdigit() or c == '.' for c in low) and low.count('.') == 3:
        return f'ioc:ip:{low}', 'ip'
    if '/' not in low and ' ' not in low and '.' in low:
        return f'ioc:domain:{low}', 'domain'
    return f'ioc:other:{low}', 'ioc'


def _cti_status_index(result: dict) -> dict[str, dict]:
    """Map indicator → CTI query/match status for graph node meta."""
    ti = result.get('threat_intel') or {}
    out: dict[str, dict] = {}

    def touch(ind: str, **fields):
        key = str(ind or '').strip().lower()
        if not key:
            return
        row = out.setdefault(key, {'indicator': ind, 'sources': [], 'status': 'not_queried', 'matched': False})
        for src in fields.pop('sources', []) or []:
            if src and src not in row['sources']:
                row['sources'].append(src)
        for k, v in fields.items():
            if v is None:
                continue
            if k == 'status' and row.get('matched') and v != 'matched':
                continue
            row[k] = v
        if fields.get('matched'):
            row['matched'] = True
            row['status'] = 'matched'

    for row in (ti.get('threatfox') or {}).get('lookups') or []:
        ind = row.get('indicator')
        if row.get('status') == 'found':
            touch(ind, sources=['ThreatFox'], status='matched', matched=True, threatfox=row.get('match_count') or 1)
        elif row.get('status') == 'skipped':
            touch(ind, sources=['ThreatFox'], status='skipped', skip_reason=row.get('skip_reason'))
        elif row.get('status') in {'not_found', 'ok'}:
            touch(ind, sources=['ThreatFox'], status='queried_not_found')
        elif row.get('status'):
            touch(ind, sources=['ThreatFox'], status=str(row.get('status')))

    for row in (ti.get('urlhaus') or {}).get('results') or []:
        ind = row.get('indicator') or row.get('url') or row.get('host')
        if row.get('found'):
            touch(ind, sources=['URLHaus'], status='matched', matched=True, families=row.get('families') or [])
        elif row.get('status') == 'skipped':
            touch(ind, sources=['URLHaus'], status='skipped', skip_reason=row.get('skip_reason'))
        elif row.get('status') in {'not_found', 'ok'}:
            touch(ind, sources=['URLHaus'], status='queried_not_found')

    for row in (ti.get('feodo') or {}).get('matches') or []:
        touch(row.get('ip'), sources=['FeodoTracker'], status='matched', matched=True, malware=row.get('malware'))
    for row in (ti.get('sslbl') or {}).get('matches') or []:
        touch(row.get('ip'), sources=['SSLBL'], status='matched', matched=True)

    # Mark public IPs as feed-checked even without a hit (Feodo/SSLBL are set intersections)
    for ip in _as_list((result.get('iocs') or {}).get('ips'))[:200]:
        key = str(ip).strip().lower()
        if key and key not in out:
            touch(ip, sources=['FeodoTracker', 'SSLBL'], status='queried_not_found')
        elif key:
            touch(ip, sources=['FeodoTracker', 'SSLBL'])
    return out


def build_infrastructure_graph(result: dict) -> dict:
    """Build a UI-friendly relationship graph with VT/CTI provenance."""
    nodes = []
    edges = []
    seen = set()
    edge_seen = set()
    node_by_id: dict[str, dict] = {}

    def add_node(nid, label, typ, meta=None, severity='neutral'):
        if not nid:
            return
        if nid in seen:
            # Merge meta / escalate severity when revisiting canonical IOC nodes
            existing = node_by_id.get(nid)
            if existing and isinstance(meta, dict):
                merged = dict(existing.get('meta') or {})
                for k, v in meta.items():
                    if k == 'sources' and isinstance(v, list):
                        cur = list(merged.get('sources') or [])
                        for item in v:
                            if item not in cur:
                                cur.append(item)
                        merged['sources'] = cur
                    elif v not in (None, '', [], {}):
                        merged[k] = v
                existing['meta'] = merged
                rank = {'neutral': 0, 'info': 1, 'warning': 2, 'critical': 3}
                if rank.get(severity, 0) > rank.get(existing.get('severity'), 0):
                    existing['severity'] = severity
            return
        seen.add(nid)
        node = {'id': nid, 'label': label, 'type': typ, 'meta': meta or {}, 'severity': severity}
        nodes.append(node)
        node_by_id[nid] = node

    def add_edge(src, dst, label, source=None):
        if not src or not dst or src == dst:
            return
        key = (src, dst, label, source)
        if key in edge_seen:
            return
        edge_seen.add(key)
        edges.append({'from': src, 'to': dst, 'label': label, 'source': source})

    cti_idx = _cti_status_index(result)
    root = result.get('root_file') or {}
    sample_id = 'sample:' + str(root.get('sha256') or root.get('filename') or 'root')
    add_node(
        sample_id,
        root.get('filename') or 'Root Sample',
        'sample',
        {'sha256': root.get('sha256'), 'role': 'Analyzed root file'},
        'critical' if (result.get('file_stats') or {}).get('malicious') else 'neutral',
    )

    for f in result.get('files') or []:
        fid = 'file:' + str(f.get('sha256') or f.get('filename'))
        sev = (
            'critical' if str(f.get('vt_verdict', '')).lower() == 'malicious'
            else ('warning' if str(f.get('vt_verdict', '')).lower() == 'suspicious' else 'neutral')
        )
        add_node(
            fid,
            f.get('original_name') or f.get('filename') or 'file',
            'file',
            {'verdict': f.get('vt_verdict'), 'sha256': f.get('sha256'), 'type': f.get('file_type')},
            sev,
        )
        add_edge(sample_id, fid, 'contains')

    family_nodes: dict[str, str] = {}
    for fam in (build_cti_dashboard(result).get('families') or []):
        nid = 'family:' + fam['name']
        family_nodes[str(fam['name']).lower()] = nid
        add_node(nid, fam['name'], 'family', fam, 'warning')
        add_edge(sample_id, nid, 'associated family', ', '.join(fam.get('sources') or []))

    iocs = result.get('iocs') or {}
    details = iocs.get('ioc_details') or {}
    detail_maps = {
        'urls': {str(r.get('indicator', '')).lower(): r for r in (details.get('urls') or []) if isinstance(r, dict)},
        'domains': {str(r.get('indicator', '')).lower(): r for r in (details.get('domains') or []) if isinstance(r, dict)},
        'ips': {str(r.get('indicator', '')).lower(): r for r in (details.get('ips') or []) if isinstance(r, dict)},
    }
    kind_labels = {
        'urls': 'URL', 'domains': 'Domain', 'ips': 'IP', 'emails': 'Email',
        'discord_webhooks': 'Discord Webhook', 'telegram': 'Telegram', 'wallets': 'Wallet',
    }

    for typ in ('urls', 'domains', 'ips', 'emails', 'discord_webhooks', 'telegram', 'wallets'):
        for val in _as_list(iocs.get(typ))[:200]:
            nid, node_type = _ioc_canonical_id(val) if typ in {'urls', 'domains', 'ips'} else (f'ioc:{typ}:{str(val).lower()}', 'ioc')
            drow = detail_maps.get(typ, {}).get(str(val).lower(), {})
            sources = list(drow.get('sources') or [])
            cti = cti_idx.get(str(val).strip().lower()) or {}
            vt_sourced = any(str(s).startswith('VirusTotal') for s in sources)
            sev = 'critical' if cti.get('matched') else ('warning' if vt_sourced else 'info')
            meta = {
                'kind': kind_labels.get(typ, typ),
                'sources': sources or (['static extraction'] if not vt_sourced else []),
                'vt_contacted': vt_sourced,
                'cti_status': cti.get('status') or ('not_queried' if typ in {'emails', 'wallets'} else 'not_queried'),
                'cti_sources': cti.get('sources') or [],
                'skip_reason': cti.get('skip_reason'),
            }
            add_node(nid, str(val), node_type, meta, sev)
            edge_label = 'vt contacted' if vt_sourced else ('extracts ' + kind_labels.get(typ, typ))
            add_edge(sample_id, nid, edge_label, 'VirusTotal' if vt_sourced else 'extraction')

    role_labels = {
        'probable_c2': 'Probable C2',
        'payload_delivery': 'Payload Delivery',
        'malware_downloads': 'Malware Download',
        'control_channels': 'Control Channel',
        'exfil_channels': 'Exfil Channel',
        'config_sources': 'Config Source',
        'known_bad_infrastructure': 'Known Bad Infrastructure',
        'vt_contacted': 'VT Contacted',
    }
    for bucket, rows in (result.get('infrastructure') or {}).items():
        if not isinstance(rows, list):
            continue
        for r in rows:
            if not isinstance(r, dict):
                continue
            ind = r.get('indicator')
            if not ind:
                continue
            nid, node_type = _ioc_canonical_id(str(ind))
            # Prefer typed IOC nodes over a separate infra duplicate
            if node_type == 'ioc':
                nid = 'infra:' + str(ind).lower()
                node_type = 'infrastructure'
            cti = cti_idx.get(str(ind).strip().lower()) or {}
            sev = (
                'critical' if bucket in {'probable_c2', 'malware_downloads', 'known_bad_infrastructure'} or cti.get('matched')
                else ('warning' if bucket in {'vt_contacted', 'payload_delivery', 'control_channels', 'exfil_channels'} else 'info')
            )
            meta = dict(r)
            meta['role'] = role_labels.get(bucket, bucket.replace('_', ' '))
            meta['bucket'] = bucket
            meta['cti_status'] = cti.get('status') or meta.get('cti_status')
            meta['cti_sources'] = cti.get('sources') or []
            sources = list(meta.get('sources') or [])
            if r.get('source') and r['source'] not in sources:
                sources.append(r['source'])
            meta['sources'] = sources
            add_node(nid, str(ind), node_type if node_type != 'ioc' else 'infrastructure', meta, sev)
            add_edge(sample_id, nid, role_labels.get(bucket, bucket.replace('_', ' ')), r.get('source'))
            # Link confirmed infra to malware family nodes
            for fam in _as_list(r.get('families')) + ([r.get('malware')] if r.get('malware') else []):
                fid = family_nodes.get(str(fam).lower())
                if fid:
                    add_edge(nid, fid, 'associated with', r.get('source'))

    # ThreatFox / URLHaus family ↔ IOC edges from exact matches
    ti = result.get('threat_intel') or {}
    for item in (ti.get('threatfox') or {}).get('found') or []:
        ind = item.get('indicator')
        nid, _ = _ioc_canonical_id(str(ind or ''))
        for m in item.get('matches') or []:
            fam = m.get('malware') or m.get('malware_printable')
            fid = family_nodes.get(str(fam or '').lower())
            if fid and nid in seen:
                add_edge(nid, fid, 'ThreatFox family', 'ThreatFox')
    for row in (ti.get('urlhaus') or {}).get('results') or []:
        if not row.get('found'):
            continue
        ind = row.get('indicator') or row.get('url') or row.get('host')
        nid, _ = _ioc_canonical_id(str(ind or ''))
        for fam in row.get('families') or []:
            fid = family_nodes.get(str(fam).lower())
            if fid and nid in seen:
                add_edge(nid, fid, 'URLHaus family', 'URLHaus')

    by_type: dict[str, int] = {}
    matched = queried = skipped = vt_n = 0
    for n in nodes:
        by_type[n['type']] = by_type.get(n['type'], 0) + 1
        meta = n.get('meta') or {}
        st = str(meta.get('cti_status') or '')
        if st == 'matched' or meta.get('matched'):
            matched += 1
        elif st in {'queried_not_found'}:
            queried += 1
        elif st == 'skipped':
            skipped += 1
        if meta.get('vt_contacted') or meta.get('source') == 'VirusTotal' or meta.get('bucket') == 'vt_contacted':
            vt_n += 1

    return {
        'nodes': nodes,
        'edges': edges,
        'summary': {
            'nodes': len(nodes),
            'edges': len(edges),
            'by_type': by_type,
            'vt_contacted_nodes': vt_n,
            'cti_matched_nodes': matched,
            'cti_queried_no_hit': queried,
            'cti_skipped_nodes': skipped,
        },
        'policy_note': (
            'CTI is query-only (ThreatFox / URLHaus / Feodo / SSLBL / MalwareBazaar). '
            'RepoTriage does not submit IOCs or samples to those feeds. '
            'VT contacted domains are queried on ThreatFox + URLHaus host; Feodo/SSLBL require IPs.'
        ),
    }

def discover_related_samples(result: dict) -> dict:
    related=[]
    ti=result.get('threat_intel') or {}
    # MalwareBazaar matches are closest thing to known samples in community APIs
    for r in (ti.get('malwarebazaar') or {}).get('results') or []:
        if r.get('found'):
            related.append({
                'sha256': r.get('sha256'),
                'file': r.get('file') or r.get('file_name'),
                'family': r.get('family') or r.get('signature') or 'Unknown',
                'source':'MalwareBazaar',
                'first_seen': r.get('first_seen'),
                'link': r.get('link'),
                'reason':'Exact hash found in MalwareBazaar',
            })
    fams=[x['family'] for x in _family_candidates(result)]
    shared_domains=_as_list((result.get('iocs') or {}).get('domains'))
    shared_urls=_as_list((result.get('iocs') or {}).get('urls'))
    return {
        'count': len(related),
        'related_samples': related,
        'families': _uniq(fams),
        'shared_domains': shared_domains[:100],
        'shared_urls': shared_urls[:100],
        'note': 'Community APIs expose exact known-sample matches and shared family/infrastructure clues. Broader fuzzy similarity requires VT Enterprise or sandbox similarity APIs.',
    }




# -----------------------------
# v2.2B CTI Correlation Engine
# -----------------------------

_ACTOR_HINTS = (
    'apt', 'ta', 'unc', 'fin', 'lazarus', 'kimsuky', 'sandworm', 'turla',
    'muddywater', 'mustang panda', 'scattered spider', 'wizard spider',
    'lockbit', 'black basta', 'clop', 'conti', 'qakbot', 'emotet', 'trickbot'
)


def _confidence_band(score: int) -> str:
    if score >= 86:
        return 'Very High'
    if score >= 61:
        return 'High'
    if score >= 31:
        return 'Medium'
    return 'Low'


def _first_nonempty(*vals):
    for v in vals:
        if v not in (None, '', [], {}):
            return v
    return None


def _collect_tags_and_refs(result: dict) -> list[str]:
    out=[]
    ti=result.get('threat_intel') or {}
    for src in ('threatfox','malwarebazaar','urlhaus'):
        obj=ti.get(src) or {}
        for key in ('found','results','matches'):
            for row in _as_list(obj.get(key)):
                if isinstance(row, dict):
                    for k in ('tags','reference','link','reporter','threat_type','malware','family','signature'):
                        v=row.get(k)
                        if isinstance(v, list): out.extend(str(x) for x in v)
                        elif v: out.append(str(v))
                    for m in _as_list(row.get('matches')):
                        if isinstance(m, dict):
                            for k in ('tags','reference','reporter','threat_type','malware','malware_printable'):
                                v=m.get(k)
                                if isinstance(v, list): out.extend(str(x) for x in v)
                                elif v: out.append(str(v))
    return _uniq(out)


def build_campaign_analysis(result: dict) -> dict:
    """Evidence-based campaign correlation without claiming named campaigns unless supported."""
    dash=result.get('cti_dashboard') or build_cti_dashboard(result)
    related=result.get('related_samples') or discover_related_samples(result)
    infra=result.get('infrastructure') or {}
    files=result.get('files') or []
    iocs=result.get('iocs') or {}
    mitre=(result.get('mitre') or {}).get('techniques') or []
    ti=result.get('threat_intel') or {}

    family=dash.get('primary_family') or 'Unknown'
    anchors = count_exact_cti_anchors(result)
    score=0
    evidence=[]

    if family and family != 'Unknown' and (anchors.get('has_hash_anchor') or anchors.get('has_exact_ioc_anchor')):
        score += 20
        evidence.append({'signal':'Malware family/signature observed (exact hash or IOC)','detail':family,'weight':20,'source':'CTI fusion'})
    if (result.get('file_stats') or {}).get('malicious',0) >= 2:
        score += 15
        evidence.append({'signal':'Multiple malicious files in same package','detail':str((result.get('file_stats') or {}).get('malicious')),'weight':15,'source':'VirusTotal'})
    if related.get('count',0) > 0:
        score += 15
        evidence.append({'signal':'Known sample overlap','detail':f"{related.get('count')} MalwareBazaar exact match(es)",'weight':15,'source':'MalwareBazaar'})
    infra_count = count_cti_sourced_infra(infra)
    if infra_count:
        score += min(20, infra_count * 8)
        evidence.append({'signal': 'CTI-confirmed infrastructure', 'detail': f'{infra_count} exact feed match(es)', 'weight': min(20, infra_count * 8), 'source': 'AbuseCH'})
    tf_matches=int(anchors.get('exact_threatfox') or 0)
    uh_matches=int(anchors.get('exact_urlhaus') or 0)
    if tf_matches:
        score += min(15, tf_matches * 8)
        evidence.append({'signal':'Exact ThreatFox IOC match(es)','detail':str(tf_matches),'weight':min(15, tf_matches * 8),'source':'ThreatFox'})
    if uh_matches:
        score += min(10, uh_matches * 8)
        evidence.append({'signal':'Exact URLHaus URL match(es)','detail':str(uh_matches),'weight':min(10, uh_matches * 8),'source':'URLHaus'})
    if mitre:
        score += min(10, len(mitre)*3)
        evidence.append({'signal':'ATT&CK behavioral clues','detail':f'{len(mitre)} mapped technique(s)','weight':min(10, len(mitre)*3),'source':'MITRE mapper'})

    score=min(100, score)

    # Do not invent named campaigns. Use conservative campaign label.
    if family and family != 'Unknown' and (anchors.get('has_hash_anchor') or anchors.get('has_exact_ioc_anchor')):
        if any(x in str(family).lower() for x in ('usb','runner','worm')):
            candidate='USB / removable-media malware distribution cluster'
        elif any(x in str(family).lower() for x in ('stealer','lumma','redline','rhadamanthys')):
            candidate=f'{family} credential-theft delivery cluster'
        elif any(x in str(family).lower() for x in ('rat','remcos','async','xworm')):
            candidate=f'{family} remote-access malware delivery cluster'
        else:
            candidate=f'{family} malware distribution cluster'
    else:
        candidate='Unknown campaign / insufficient evidence'

    delivery=[]
    exts=Counter((str(f.get('original_name') or f.get('filename') or '').split('.')[-1].lower()) for f in files if f.get('original_name') or f.get('filename'))
    for ext,count in exts.most_common(5):
        if ext:
            delivery.append({'mechanism':ext.upper()+' file', 'count':count})
    if _as_list(iocs.get('urls')):
        delivery.append({'mechanism':'Embedded URL / staging reference','count':len(_as_list(iocs.get('urls')))})

    timeline=[]
    for src, obj in (ti or {}).items():
        for key in ('found','results','matches'):
            for row in _as_list((obj or {}).get(key)):
                if isinstance(row, dict):
                    ts=_first_nonempty(row.get('first_seen'), row.get('first_seen_utc'), row.get('date_added'), row.get('last_seen'))
                    if ts:
                        timeline.append({'time':ts,'event':f'{src} observation','detail': _first_nonempty(row.get('indicator'), row.get('url'), row.get('sha256'), row.get('ip'), row.get('malware'), row.get('family'))})
                    for m in _as_list(row.get('matches')):
                        if isinstance(m, dict):
                            ts=_first_nonempty(m.get('first_seen'), m.get('last_seen'))
                            if ts:
                                timeline.append({'time':ts,'event':f'{src} match','detail': _first_nonempty(m.get('ioc'), m.get('malware'), m.get('threat_type'))})
    timeline=timeline[:30]

    return {
        'candidate': candidate,
        'confidence_score': score,
        'confidence_band': _confidence_band(score),
        'evidence': evidence,
        'delivery_mechanisms': delivery,
        'timeline': timeline,
        'summary': f'{candidate} with {score}% confidence ({_confidence_band(score)}). This is correlation, not definitive attribution.',
        'disclaimer': 'Campaign correlation requires exact hash or exact IOC match. Platform-wide CTI pivots are not used.',
    }


def build_threat_actor_assessment(result: dict) -> dict:
    """Strict threat actor assessment. Defaults to Unknown unless explicit actor-like evidence exists."""
    tags=_collect_tags_and_refs(result)
    candidates=[]
    for t in tags:
        low=t.lower()
        if any(h in low for h in _ACTOR_HINTS):
            # Extract a readable short candidate from the tag/ref string.
            val=t.strip()
            if len(val) > 80:
                val=val[:80]+'…'
            candidates.append({'actor':val,'source':'CTI tag/reference','evidence':t,'weight':35})

    # Deduplicate by actor text
    dedup=[]; seen=set()
    for c in candidates:
        k=c['actor'].lower()
        if k not in seen:
            seen.add(k); dedup.append(c)

    if not dedup:
        return {
            'known_attribution':'None',
            'primary_assessment':'Unknown',
            'confidence_score':0,
            'confidence_band':'Low',
            'potential_associations':[],
            'evidence':[{'signal':'No explicit actor/campaign attribution found in available sources','detail':'RepoTriage will not infer an actor from family alone.','weight':0,'source':'Correlation engine'}],
            'analyst_note':'No defensible threat actor attribution is available from the current evidence.',
            'disclaimer':'Actor attribution requires explicit source evidence. Malware family overlap alone is not enough.',
        }

    score=min(70, sum(c.get('weight',0) for c in dedup[:2]))
    primary=dedup[0]['actor']
    return {
        'known_attribution':'Potential association only',
        'primary_assessment':primary,
        'confidence_score':score,
        'confidence_band':_confidence_band(score),
        'potential_associations':dedup,
        'evidence':[{'signal':'Actor-like reference observed','detail':c['evidence'],'weight':c['weight'],'source':c['source']} for c in dedup],
        'analyst_note':'Treat this as a lead for CTI review, not confirmed attribution.',
        'disclaimer':'Potential associations are not definitive without corroborating reporting, infrastructure overlap, and campaign context.',
    }


def build_correlation_matrix(result: dict) -> dict:
    dash=result.get('cti_dashboard') or build_cti_dashboard(result)
    campaign=result.get('campaign_analysis') or build_campaign_analysis(result)
    actor=result.get('threat_actor_assessment') or build_threat_actor_assessment(result)
    rows=[]
    def row(entity, related, relationship, confidence, evidence):
        rows.append({'entity':entity,'related_to':related,'relationship':relationship,'confidence':confidence,'evidence':evidence})
    root=(result.get('root_file') or {}).get('filename') or 'Root sample'
    fam=dash.get('primary_family') or 'Unknown'
    row(root,fam,'family/signature',dash.get('risk','Unknown'),'VT/CTI family evidence')
    row(root,campaign.get('candidate'),'campaign correlation',campaign.get('confidence_band'),campaign.get('summary'))
    row(root,actor.get('primary_assessment'),'threat actor assessment',actor.get('confidence_band'),actor.get('analyst_note'))
    for bucket, items in (result.get('infrastructure') or {}).items():
        if isinstance(items,list):
            for item in items[:25]:
                ind=item.get('indicator') if isinstance(item,dict) else str(item)
                row(root,ind,bucket.replace('_',' '), (item or {}).get('confidence','Medium') if isinstance(item,dict) else 'Medium', (item or {}).get('source','RepoTriage') if isinstance(item,dict) else 'RepoTriage')
    for t in (result.get('mitre') or {}).get('techniques') or []:
        row(root,t.get('id'), 'MITRE ATT&CK technique', t.get('confidence'), t.get('name'))
    return {'rows':rows, 'summary':{'count':len(rows)}}


def build_analyst_report(result: dict) -> dict:
    """Build a clean analyst report without duplicating the attack narrative sections."""
    dash=result.get('cti_dashboard') or build_cti_dashboard(result)
    n=result.get('attack_narrative') or {}
    root=result.get('root_file') or {}
    stats=result.get('file_stats') or {}
    lines=[]
    lines.append('# RepoTriage Analyst Report')
    lines.append('')
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Source URL: {(result.get('source') or {}).get('display_url') or (result.get('source') or {}).get('url') or '-'}")
    lines.append(f"Root file: {root.get('filename') or '-'}")
    lines.append(f"SHA256: {root.get('sha256') or '-'}")
    lines.append('')
    lines.append('## Executive Summary')
    lines.append(f"- Overall risk: **{dash.get('risk')}**")
    lines.append(f"- Primary family/signature: **{dash.get('primary_family')}**")
    lines.append(f"- Malicious files: **{stats.get('malicious',0)}** of {stats.get('total_listed',0)} listed file(s)")
    lines.append(f"- Extracted IOCs: **{dash.get('ioc_count',0)}**")
    lines.append(f"- MITRE ATT&CK mappings: **{dash.get('mitre_count',0)}**")
    camp=result.get('campaign_analysis') or build_campaign_analysis(result)
    actor=result.get('threat_actor_assessment') or build_threat_actor_assessment(result)
    lines.append(f"- Campaign correlation: **{camp.get('candidate')}** ({camp.get('confidence_band')} / {camp.get('confidence_score')}%)")
    lines.append(f"- Threat actor assessment: **{actor.get('primary_assessment')}** ({actor.get('confidence_band')} / {actor.get('confidence_score')}%)")
    lines.append('')
    lines.append('## Campaign Correlation')
    lines.append(f"- Assessment: {camp.get('candidate')}")
    lines.append(f"- Confidence: {camp.get('confidence_band')} ({camp.get('confidence_score')}%)")
    for e in camp.get('evidence') or []:
        lines.append(f"- Evidence: {e.get('signal')} — {e.get('detail')} [{e.get('source')}]")
    lines.append('')
    lines.append('## Threat Actor Assessment')
    lines.append(f"- Assessment: {actor.get('primary_assessment')}")
    lines.append(f"- Confidence: {actor.get('confidence_band')} ({actor.get('confidence_score')}%)")
    lines.append(f"- Analyst note: {actor.get('analyst_note')}")
    for e in actor.get('evidence') or []:
        lines.append(f"- Evidence: {e.get('signal')} — {e.get('detail')} [{e.get('source')}]")
    lines.append('')
    lines.append('## Attack Narrative')
    for b in n.get('narrative_bullets') or []:
        lines.append(f"- {b}")
    if not n.get('narrative_bullets'):
        lines.append('- No attack narrative generated.')
    lines.append('')
    lines.append('## Likely Objective')
    for x in n.get('likely_objectives') or ['Unknown based on current static evidence']:
        lines.append(f"- {x}")
    lines.append('')
    lines.append('## Malicious Files')
    malicious=False
    for f in result.get('files') or []:
        if str(f.get('vt_verdict','')).lower() == 'malicious':
            malicious=True
            lines.append(f"- {f.get('original_name') or f.get('filename')} — SHA256: `{f.get('sha256')}`" + (f" — VT: {f.get('vt_link')}" if f.get('vt_link') else ''))
    if not malicious:
        lines.append('- None observed from current enrichment results.')
    lines.append('')
    lines.append('## Infrastructure')
    any_infra=False
    for bucket, rows in (result.get('infrastructure') or {}).items():
        if isinstance(rows,list) and rows:
            any_infra=True
            lines.append(f"### {bucket.replace('_',' ').title()}")
            for r in rows:
                if isinstance(r,dict): lines.append(f"- {r.get('indicator')} ({r.get('source','RepoTriage')}, confidence: {r.get('confidence','Unknown')})")
                else: lines.append(f"- {r}")
    if not any_infra:
        lines.append('- No enriched infrastructure highlights observed.')
    lines.append('')
    lines.append('## MITRE ATT&CK')
    techniques=(result.get('mitre') or {}).get('techniques') or []
    if techniques:
        for t in techniques:
            lines.append(f"- {t.get('id')} {t.get('name')} — {t.get('tactic')} — {t.get('confidence')}")
    else:
        lines.append('- No ATT&CK mappings generated.')
    lines.append('')
    lines.append('## Recommended Analyst Actions')
    for a in n.get('recommended_actions') or ['Continue manual review.']:
        lines.append(f"- {a}")
    if n.get('system_notes'):
        lines.append('')
        lines.append('## System Notes')
        for note in n.get('system_notes') or []:
            lines.append(f"- {note}")
    md='\n'.join(lines)
    html='<html><head><title>RepoTriage Analyst Report</title><style>body{font-family:Arial,sans-serif;max-width:1100px;margin:40px auto;line-height:1.55}code,pre{background:#f4f4f4;padding:4px}h1,h2{color:#123}</style></head><body>'+md.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('\n','<br>')+'</body></html>'
    return {'markdown':md,'html':html}

def export_csv(result: dict) -> str:
    out=io.StringIO(); w=csv.writer(out)
    w.writerow(['type','value','source','detail'])
    for f in result.get('files') or []:
        w.writerow(['file', f.get('original_name') or f.get('filename'), 'RepoTriage', f.get('sha256')])
    for k,v in (result.get('iocs') or {}).items():
        if isinstance(v,list) and k!='ioc_details':
            for x in v: w.writerow(['ioc:'+k, x, 'extraction', ''])
    for t in (result.get('mitre') or {}).get('techniques') or []:
        w.writerow(['mitre', t.get('id'), ','.join(t.get('sources') or []), t.get('name')])
    return out.getvalue()


def export_stix(result: dict) -> dict:
    objs=[]
    ts=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    for f in result.get('files') or []:
        if f.get('sha256'):
            objs.append({
                'type': 'file',
                'spec_version': '2.1',
                'id': 'file--' + uuid_like(f.get('sha256')),
                'hashes': {'SHA-256': f.get('sha256')},
                'name': f.get('original_name') or f.get('filename'),
            })
    for typ in ('domains','ips','urls'):
        for val in _as_list((result.get('iocs') or {}).get(typ)):
            stix_type={'domains':'domain-name','ips':'ipv4-addr','urls':'url'}[typ]
            key='value'
            objs.append({'type':stix_type,'spec_version':'2.1','id':stix_type+'--'+uuid_like(val),'value':val})
    return {'type':'bundle','id':'bundle--'+uuid_like(ts),'objects':objs}


def uuid_like(seed: str) -> str:
    import hashlib
    h=hashlib.sha256(str(seed).encode()).hexdigest()
    return f'{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}'


def export_misp(result: dict) -> dict:
    attrs=[]
    for f in result.get('files') or []:
        if f.get('sha256'): attrs.append({'type':'sha256','category':'Payload delivery','value':f.get('sha256'),'comment':f.get('original_name') or f.get('filename')})
    for d in _as_list((result.get('iocs') or {}).get('domains')): attrs.append({'type':'domain','category':'Network activity','value':d})
    for ip in _as_list((result.get('iocs') or {}).get('ips')): attrs.append({'type':'ip-dst','category':'Network activity','value':ip})
    for u in _as_list((result.get('iocs') or {}).get('urls')): attrs.append({'type':'url','category':'Network activity','value':u})
    return {'Event':{'info':'RepoTriage analysis - '+str((result.get('root_file') or {}).get('filename') or 'sample'),'threat_level_id':'1' if (result.get('file_stats') or {}).get('malicious') else '3','analysis':'1','Attribute':attrs}}
