from collections import defaultdict

TECHNIQUES = {
    'T1105': {'id':'T1105','name':'Ingress Tool Transfer','tactic':'Command and Control','reason':'Payload delivery, malware download, or remote tool transfer infrastructure observed.'},
    'T1071.001': {'id':'T1071.001','name':'Application Layer Protocol: Web Protocols','tactic':'Command and Control','reason':'HTTP/HTTPS URLs or web-based infrastructure observed.'},
    'T1095': {'id':'T1095','name':'Non-Application Layer Protocol','tactic':'Command and Control','reason':'Botnet/C2 IP infrastructure observed.'},
    'T1041': {'id':'T1041','name':'Exfiltration Over C2 Channel','tactic':'Exfiltration','reason':'Discord/Telegram/webhook-style exfiltration or control channel observed.'},
    'T1567.002': {'id':'T1567.002','name':'Exfiltration to Cloud Storage','tactic':'Exfiltration','reason':'Cloud/web service exfiltration channel observed.'},
    'T1059': {'id':'T1059','name':'Command and Scripting Interpreter','tactic':'Execution','reason':'Script or command launcher file observed.'},
    'T1059.001': {'id':'T1059.001','name':'PowerShell','tactic':'Execution','reason':'PowerShell script/indicator observed.'},
    'T1059.003': {'id':'T1059.003','name':'Windows Command Shell','tactic':'Execution','reason':'CMD/BAT launcher observed.'},
    'T1059.005': {'id':'T1059.005','name':'Visual Basic','tactic':'Execution','reason':'VBS/VBA-style script observed.'},
    'T1059.007': {'id':'T1059.007','name':'JavaScript','tactic':'Execution','reason':'JavaScript/JScript payload or launcher observed.'},
    'T1204.002': {'id':'T1204.002','name':'User Execution: Malicious File','tactic':'Execution','reason':'Malicious archive/executable payload likely requires user execution.'},
    'T1027': {'id':'T1027','name':'Obfuscated Files or Information','tactic':'Defense Evasion','reason':'Packed/encoded/archive-delivered payload or suspicious strings observed.'},
    'T1140': {'id':'T1140','name':'Deobfuscate/Decode Files or Information','tactic':'Defense Evasion','reason':'Archive, encoded, or staged payload pattern observed.'},
    'T1555': {'id':'T1555','name':'Credentials from Password Stores','tactic':'Credential Access','reason':'Infostealer family or credential-theft indicators observed.'},
    'T1005': {'id':'T1005','name':'Data from Local System','tactic':'Collection','reason':'Infostealer/file collection behavior inferred from family or labels.'},
    'T1119': {'id':'T1119','name':'Automated Collection','tactic':'Collection','reason':'Infostealer/collection malware family observed.'},
    'T1566.001': {'id':'T1566.001','name':'Phishing: Spearphishing Attachment','tactic':'Initial Access','reason':'Archive/document attachment delivery pattern observed.'},
    'T1583.001': {'id':'T1583.001','name':'Acquire Infrastructure: Domains','tactic':'Resource Development','reason':'Suspicious domains or payload delivery hosts observed.'},
    'T1584.008': {'id':'T1584.008','name':'Compromise Infrastructure: Network Devices','tactic':'Resource Development','reason':'Known malicious infrastructure source observed; validate manually.'},
}

FAMILY_HINTS = {
    'lumma': ['T1555','T1005','T1119','T1041','T1105'],
    'redline': ['T1555','T1005','T1119','T1041','T1105'],
    'rhadamanthys': ['T1555','T1005','T1119','T1041','T1105'],
    'agenttesla': ['T1059','T1555','T1005','T1041','T1105'],
    'agent_tesla': ['T1059','T1555','T1005','T1041','T1105'],
    'remcos': ['T1059','T1105','T1095','T1041'],
    'asyncrat': ['T1059','T1105','T1095','T1041'],
    'async_rat': ['T1059','T1105','T1095','T1041'],
    'xworm': ['T1059','T1105','T1095','T1041'],
    'njrat': ['T1059','T1105','T1095','T1041'],
    'quasar': ['T1059','T1105','T1095','T1041'],
    'formbook': ['T1555','T1005','T1041','T1105'],
    'darkgate': ['T1059','T1105','T1027','T1140'],
}

def _add(out, tid, source, evidence, confidence='Medium'):
    if tid not in TECHNIQUES:
        return
    item = dict(TECHNIQUES[tid])
    item['sources'] = sorted(set(item.get('sources', []) + [source])) if item.get('sources') else [source]
    item['evidence'] = [evidence] if evidence else []
    item['confidence'] = confidence
    out.setdefault(tid, item)
    if tid in out and out[tid] is not item:
        if source not in out[tid]['sources']:
            out[tid]['sources'].append(source)
        if evidence and evidence not in out[tid]['evidence']:
            out[tid]['evidence'].append(evidence)
        ranks = {'Low':1,'Medium':2,'High':3}
        if ranks.get(confidence,2) > ranks.get(out[tid].get('confidence','Medium'),2):
            out[tid]['confidence'] = confidence

def _contains(text, words):
    s = str(text or '').lower()
    return any(w in s for w in words)

def map_mitre(files, iocs, threat_intel, infra, family):
    techniques = {}
    # File/script based mappings
    for f in files or []:
        name = str(f.get('filename') or f.get('path') or '').lower()
        ftype = str(f.get('file_type') or '').lower()
        verdict = str(f.get('vt_verdict') or '').lower()
        if any(name.endswith(ext) for ext in ['.cmd','.bat']):
            _add(techniques, 'T1059.003', 'File Inventory', f.get('path') or f.get('filename'), 'High' if verdict=='malicious' else 'Medium')
        if name.endswith('.ps1') or 'powershell' in name:
            _add(techniques, 'T1059.001', 'File Inventory', f.get('path') or f.get('filename'), 'High' if verdict=='malicious' else 'Medium')
        if any(name.endswith(ext) for ext in ['.js','.jse']):
            _add(techniques, 'T1059.007', 'File Inventory', f.get('path') or f.get('filename'), 'High' if verdict=='malicious' else 'Medium')
        if any(name.endswith(ext) for ext in ['.vbs','.vba','.vbe']):
            _add(techniques, 'T1059.005', 'File Inventory', f.get('path') or f.get('filename'), 'High' if verdict=='malicious' else 'Medium')
        if f.get('is_archive') or 'archive' in ftype or any(name.endswith(ext) for ext in ['.zip','.rar','.7z','.iso']):
            _add(techniques, 'T1566.001', 'File Inventory', f.get('path') or f.get('filename'), 'Medium')
            _add(techniques, 'T1140', 'File Inventory', f.get('path') or f.get('filename'), 'Medium')
        if verdict == 'malicious' and ('pe executable' in ftype or any(name.endswith(ext) for ext in ['.exe','.dll','.scr'])):
            _add(techniques, 'T1204.002', 'VirusTotal/File Inventory', f.get('path') or f.get('filename'), 'Medium')

    # IOC based mappings
    urls = (iocs or {}).get('urls') or []
    domains = (iocs or {}).get('domains') or []
    ips = (iocs or {}).get('ipv4') or (iocs or {}).get('ips') or []
    if urls:
        _add(techniques, 'T1071.001', 'IOC Extraction', f'{len(urls)} URL(s) extracted', 'Medium')
        _add(techniques, 'T1105', 'IOC Extraction', f'{len(urls)} URL(s) may support payload transfer', 'Medium')
    if domains:
        _add(techniques, 'T1583.001', 'IOC Extraction', f'{len(domains)} domain(s) extracted', 'Low')
    if ips:
        _add(techniques, 'T1095', 'IOC Extraction', f'{len(ips)} public IP(s) extracted', 'Low')
    if (iocs or {}).get('discord_webhooks'):
        _add(techniques, 'T1041', 'IOC Extraction', 'Discord webhook observed', 'High')
    if (iocs or {}).get('telegram'):
        _add(techniques, 'T1041', 'IOC Extraction', 'Telegram channel/link observed', 'Medium')

    # ThreatFox / URLHaus / Feodo / SSLBL infrastructure mappings
    tf = (threat_intel or {}).get('threatfox') or {}
    for item in tf.get('found', []) or []:
        for m in item.get('matches', []) or []:
            tt = str(m.get('threat_type') or '').lower()
            role = str(m.get('infrastructure_role') or '').lower()
            evidence = m.get('ioc') or item.get('indicator')
            conf = 'High' if int(m.get('confidence_level') or 0) >= 75 else 'Medium'
            if 'botnet_cc' in tt or 'c2' in role:
                _add(techniques, 'T1105', 'ThreatFox', evidence, conf)
                _add(techniques, 'T1071.001', 'ThreatFox', evidence, conf)
            if 'payload' in tt or 'delivery' in role or 'download' in tt:
                _add(techniques, 'T1105', 'ThreatFox', evidence, conf)
            if 'phishing' in tt:
                _add(techniques, 'T1566.001', 'ThreatFox', evidence, conf)
            malware = m.get('malware') or ''
            for hint, tids in FAMILY_HINTS.items():
                if hint in str(malware).lower().replace(' ',''):
                    for tid in tids:
                        _add(techniques, tid, 'ThreatFox Malware Family', malware, conf)

    mb = (threat_intel or {}).get('malwarebazaar') or {}
    for row in mb.get('results', []) or []:
        if not row.get('found'):
            continue
        fam = ' '.join([str(row.get('family') or ''), str(row.get('signature') or ''), ' '.join(row.get('tags') or [])])
        for hint, tids in FAMILY_HINTS.items():
            if hint in fam.lower().replace(' ',''):
                for tid in tids:
                    _add(techniques, tid, 'MalwareBazaar Family/Signature', row.get('file') or row.get('sha256'), 'High')

    uh = (threat_intel or {}).get('urlhaus') or {}
    for row in uh.get('results', []) or []:
        if row.get('found'):
            _add(techniques, 'T1105', 'URLHaus', row.get('url') or row.get('indicator'), 'High')
            _add(techniques, 'T1071.001', 'URLHaus', row.get('url') or row.get('indicator'), 'High')

    feodo = (threat_intel or {}).get('feodo') or {}
    for row in feodo.get('matches', []) or []:
        _add(techniques, 'T1105', 'FeodoTracker', row.get('ip'), 'High')
        _add(techniques, 'T1095', 'FeodoTracker', row.get('ip'), 'High')

    sslbl = (threat_intel or {}).get('sslbl') or {}
    for row in sslbl.get('matches', []) or []:
        _add(techniques, 'T1071.001', 'SSLBL', row.get('ip') or row.get('ja3'), 'Medium')

    fam_name = ''
    if isinstance(family, dict):
        fam_name = family.get('name') or ''
    else:
        fam_name = str(family or '')
    for hint, tids in FAMILY_HINTS.items():
        if hint in fam_name.lower().replace(' ',''):
            for tid in tids:
                _add(techniques, tid, 'VirusTotal Family Label', fam_name, 'Medium')

    rows = list(techniques.values())
    tactic_order = ['Initial Access','Execution','Defense Evasion','Credential Access','Collection','Command and Control','Exfiltration','Resource Development']
    rows.sort(key=lambda x: (tactic_order.index(x['tactic']) if x['tactic'] in tactic_order else 99, x['id']))
    by_tactic = defaultdict(list)
    for r in rows:
        by_tactic[r['tactic']].append(r)
    confidence_counts = defaultdict(int)
    for r in rows:
        confidence_counts[r.get('confidence','Medium')] += 1
    return {
        'techniques': rows,
        'by_tactic': dict(by_tactic),
        'summary': {
            'count': len(rows),
            'tactics': len(by_tactic),
            'high_confidence': confidence_counts.get('High',0),
            'medium_confidence': confidence_counts.get('Medium',0),
            'low_confidence': confidence_counts.get('Low',0),
        }
    }
