"""Templated HTML export for RepoTriage Analyst Report downloads."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from .filename_signals import detect_dual_extension


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ''), quote=True)


def _risk_class(risk: str | None) -> str:
    r = (risk or '').strip().lower()
    if r in {'critical', 'high'}:
        return 'bad'
    if r == 'medium':
        return 'warn'
    return 'ok'


def _badge(text: str, cls: str = '') -> str:
    return f'<span class="badge {cls}">{_e(text)}</span>'


def _dual(name: str | None) -> str:
    hit = detect_dual_extension(name)
    if not hit:
        return ''
    return _badge(hit.get('label') or 'dual-extension', 'warn')


def _link(href: str | None, label: str) -> str:
    if not href:
        return '—'
    return f'<a href="{_e(href)}" target="_blank" rel="noopener">{_e(label)}</a>'


def _kv_table(rows: list[tuple[str, str]]) -> str:
    body = ''.join(f'<tr><th>{_e(k)}</th><td>{v}</td></tr>' for k, v in rows)
    return f'<table class="kv">{body}</table>'


def _section(title: str, body: str) -> str:
    return f'<section class="section"><h2>{_e(title)}</h2>{body}</section>'


def _bullets(items: list[Any], empty: str = 'None observed.', *, raw: bool = False) -> str:
    clean = [x for x in items if x not in (None, '')]
    if not clean:
        return f'<p class="muted">{_e(empty)}</p>'
    lis = []
    for x in clean:
        lis.append(f'<li>{x}</li>' if raw else f'<li>{_e(x)}</li>')
    return '<ul>' + ''.join(lis) + '</ul>'


def render_analyst_report_html(result: dict[str, Any], *, generated_at: str | None = None) -> str:
    """Return a complete standalone HTML document for the analyst report download."""
    from .cti_fusion import (
        build_campaign_analysis,
        build_cti_dashboard,
        build_threat_actor_assessment,
    )

    dash = result.get('cti_dashboard') or build_cti_dashboard(result)
    narrative = result.get('attack_narrative') or {}
    root = result.get('root_file') or {}
    source = result.get('source') or {}
    stats = result.get('file_stats') or {}
    vt = result.get('vt') or {}
    camp = result.get('campaign_analysis') or build_campaign_analysis(result)
    actor = result.get('threat_actor_assessment') or build_threat_actor_assessment(result)
    rel = result.get('relations') or {}
    graph = rel.get('graph_summary') or {}
    generated = generated_at or datetime.now(timezone.utc).isoformat()

    risk = dash.get('risk') or narrative.get('risk') or 'Unknown'
    family = dash.get('primary_family') or vt.get('popular_threat_label') or 'Unknown'
    source_url = source.get('display_url') or source.get('url') or '—'
    root_name = root.get('filename') or source.get('filename') or '—'
    sha = root.get('sha256') or '—'

    vt_contacted_n = len((result.get('infrastructure') or {}).get('vt_contacted') or [])
    cards = [
        ('Overall Risk', risk, _risk_class(risk)),
        ('Family / Label', family, 'bad' if family and family != 'Unknown' else ''),
        ('Malicious Files', f"{stats.get('malicious', 0)} / {stats.get('total_listed', 0)}", 'bad' if stats.get('malicious') else ''),
        ('IOCs', str(dash.get('ioc_count', 0)), ''),
        ('MITRE', str(dash.get('mitre_count', 0)), ''),
        ('VT Contacted', str(vt_contacted_n), 'warn' if vt_contacted_n else ''),
    ]
    cards_html = ''.join(
        f'<div class="card"><div class="k">{_e(k)}</div><div class="v {_e(cls)}">{_e(v)}</div></div>'
        for k, v, cls in cards
    )

    meta = _kv_table([
        ('Generated', _e(generated)),
        ('Source', _link(source_url if source_url != '—' else None, source_url) if source_url != '—' else '—'),
        ('Owner / Repo', _e(f"{source.get('owner') or '—'}/{source.get('repo') or '—'}")),
        ('Root file', f'{_e(root_name)} {_dual(str(root_name))}'),
        ('SHA256', f'<code>{_e(sha)}</code>'),
        ('VT verdict', f'{_badge(str(vt.get("verdict") or "unknown"), "bad" if str(vt.get("verdict","")).lower()=="malicious" else "")} {_e(vt.get("detections_summary") or "")}'),
        ('Popular threat label', _e(vt.get('popular_threat_label') or '—')),
        ('Family labels', ' '.join(_badge(x, 'bad') for x in (vt.get('family_labels') or [])[:12]) or '—'),
        ('Campaign', _e(f"{camp.get('candidate')} · {camp.get('confidence_band')} ({camp.get('confidence_score')}%)")),
        ('Threat actor', _e(f"{actor.get('primary_assessment')} · {actor.get('confidence_band')} ({actor.get('confidence_score')}%)")),
    ])

    narrative_html = _bullets(narrative.get('narrative_bullets') or [], 'No attack narrative generated.')
    objectives_html = _bullets(narrative.get('likely_objectives') or ['Unknown based on current static evidence'])

    # Malicious files table
    mal_rows = []
    for f in result.get('files') or []:
        if str(f.get('vt_verdict', '')).lower() != 'malicious':
            continue
        name = f.get('original_name') or f.get('filename') or '—'
        mal_rows.append(
            f'<tr><td>{_e(name)} {_dual(str(name))}</td>'
            f'<td>{_e(f.get("file_type") or "—")}</td>'
            f'<td><code>{_e(f.get("sha256") or "—")}</code></td>'
            f'<td>{_badge(str(f.get("vt_verdict") or "malicious"), "bad")}</td>'
            f'<td>{_link(f.get("vt_link"), "VT")}</td></tr>'
        )
    mal_table = (
        '<table class="data"><thead><tr><th>File</th><th>Type</th><th>SHA256</th><th>VT</th><th>Link</th></tr></thead>'
        f'<tbody>{"".join(mal_rows)}</tbody></table>'
        if mal_rows else '<p class="muted">None observed from current enrichment results.</p>'
    )

    # Infrastructure
    infra_blocks = []
    role_order = (
        'vt_contacted', 'probable_c2', 'payload_delivery', 'malware_downloads',
        'known_bad_infrastructure', 'control_channels', 'exfil_channels', 'config_sources',
    )
    infra = result.get('infrastructure') or {}
    for bucket in role_order:
        rows = infra.get(bucket) or []
        if not isinstance(rows, list) or not rows:
            continue
        title = bucket.replace('_', ' ').title()
        items = []
        for r in rows:
            if isinstance(r, dict):
                items.append(
                    f'<tr><td><code>{_e(r.get("indicator"))}</code></td>'
                    f'<td>{_e(r.get("type") or title)}</td>'
                    f'<td>{_e(r.get("confidence") or "—")}</td>'
                    f'<td>{_e(r.get("source") or "—")}</td>'
                    f'<td>{_e(r.get("malware") or (", ".join(r.get("families") or []) if r.get("families") else "—"))}</td></tr>'
                )
            else:
                items.append(f'<tr><td colspan="5"><code>{_e(r)}</code></td></tr>')
        infra_blocks.append(
            f'<h3>{_e(title)} <span class="count">{len(rows)}</span></h3>'
            f'<table class="data"><thead><tr><th>Indicator</th><th>Type</th><th>Confidence</th><th>Source</th><th>Detail</th></tr></thead>'
            f'<tbody>{"".join(items)}</tbody></table>'
        )
    infra_html = ''.join(infra_blocks) or '<p class="muted">No enriched infrastructure highlights observed.</p>'

    # Relations snapshot
    rel_cards = ''
    if graph:
        keys = (
            ('execution_parents', 'Exec Parents'),
            ('dropped_files', 'Dropped'),
            ('bundled_files', 'Bundled'),
            ('extracted_children', 'Extracted'),
            ('dual_extensions', 'Dual-Ext'),
            ('itw_urls', 'ITW URLs'),
        )
        rel_cards = '<div class="cards">' + ''.join(
            f'<div class="card"><div class="k">{_e(label)}</div><div class="v">{_e(graph.get(key, 0))}</div></div>'
            for key, label in keys
        ) + '</div>'
        duals = rel.get('dual_extensions') or []
        if duals:
            rel_cards += '<ul>' + ''.join(
                f'<li><code>{_e(d.get("filename"))}</code> — {_e(d.get("label"))}</li>'
                for d in duals[:20] if isinstance(d, dict)
            ) + '</ul>'
    else:
        rel_cards = '<p class="muted">No relations graph available for this job.</p>'

    # MITRE
    techniques = (result.get('mitre') or {}).get('techniques') or []
    if techniques:
        mitre_html = (
            '<table class="data"><thead><tr><th>ID</th><th>Name</th><th>Tactic</th><th>Confidence</th></tr></thead><tbody>'
            + ''.join(
                f'<tr><td><code>{_e(t.get("id"))}</code></td><td>{_e(t.get("name"))}</td>'
                f'<td>{_e(t.get("tactic"))}</td><td>{_badge(str(t.get("confidence") or "Medium"), "bad" if t.get("confidence")=="High" else "warn")}</td></tr>'
                for t in techniques
            )
            + '</tbody></table>'
        )
    else:
        mitre_html = '<p class="muted">No ATT&CK mappings generated.</p>'

    camp_ev = _bullets([
        f'{_e(e.get("signal"))} — {_e(e.get("detail"))} <span class="muted">[{_e(e.get("source"))}]</span>'
        for e in (camp.get('evidence') or [])
    ], 'No campaign evidence.', raw=True)
    actor_ev = _bullets([
        f'{_e(e.get("signal"))} — {_e(e.get("detail"))} <span class="muted">[{_e(e.get("source"))}]</span>'
        for e in (actor.get('evidence') or [])
    ], 'No actor evidence.', raw=True)

    actions_html = _bullets(narrative.get('recommended_actions') or ['Continue manual review.'])
    notes_html = ''
    if narrative.get('system_notes'):
        notes_html = _section('System Notes', _bullets(narrative.get('system_notes') or []))

    cti_note = (
        '<p class="note">CTI enrichment is <b>query-only</b> (ThreatFox, URLHaus, Feodo, SSLBL, MalwareBazaar). '
        'RepoTriage does not submit IOCs or samples to those feeds. '
        'VT contacted domains are queried on ThreatFox + URLHaus host API; Feodo/SSLBL require IPs.</p>'
    )
    exec_summary = f'''
<p>Overall risk <b class="{_risk_class(risk)}">{_e(risk)}</b> with primary family/signature
<b>{_e(family)}</b>. {int(stats.get("malicious") or 0)} malicious file(s) of {int(stats.get("total_listed") or 0)} listed;
{_e(dash.get("ioc_count", 0))} IOC(s); {_e(dash.get("mitre_count", 0))} MITRE mapping(s).</p>
<p>Campaign: <b>{_e(camp.get("candidate"))}</b> ({_e(camp.get("confidence_band"))}).
Threat actor: <b>{_e(actor.get("primary_assessment"))}</b> ({_e(actor.get("confidence_band"))}).</p>
{cti_note}
'''

    body = f'''
<header class="hero">
  <div class="brand">RepoTriage</div>
  <h1>Analyst Report</h1>
  <p class="subtitle">{_e(root_name)} · {_e(family)} · risk {_e(risk)}</p>
</header>
<div class="cards">{cards_html}</div>
{_section('Case Metadata', meta)}
{_section('Executive Summary', exec_summary)}
{_section('Attack Narrative', narrative_html)}
{_section('Likely Objective', objectives_html)}
{_section('Malicious Files', mal_table)}
{_section('Relations Snapshot', rel_cards)}
{_section('Infrastructure', infra_html)}
{_section('MITRE ATT&CK', mitre_html)}
{_section('Campaign Correlation', f'<p><b>{_e(camp.get("candidate"))}</b> — {_e(camp.get("confidence_band"))} ({_e(camp.get("confidence_score"))}%)</p>{camp_ev}')}
{_section('Threat Actor Assessment', f'<p><b>{_e(actor.get("primary_assessment"))}</b> — {_e(actor.get("confidence_band"))} ({_e(actor.get("confidence_score"))}%)</p><p class="muted">{_e(actor.get("analyst_note") or "")}</p>{actor_ev}')}
{_section('Recommended Analyst Actions', actions_html)}
{notes_html}
<footer class="footer">Generated by RepoTriage · {_e(generated)} · Standalone HTML export</footer>
'''

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RepoTriage Analyst Report — {_e(root_name)}</title>
<style>
:root {{
  --bg:#0b0f14; --panel:#121821; --panel2:#0f141c; --border:#243041;
  --text:#e8eef7; --muted:#9aa4b2; --accent:#42e8b4; --bad:#ff6b6b; --warn:#ffd166;
  --link:#7dd3fc;
}}
* {{ box-sizing:border-box; }}
body {{
  margin:0; padding:32px 18px 64px; background:radial-gradient(1200px 600px at 10% -10%, #14241f 0%, var(--bg) 45%), var(--bg);
  color:var(--text); font:15px/1.55 "Segoe UI", "Helvetica Neue", Arial, sans-serif;
}}
.wrap {{ max-width:1080px; margin:0 auto; }}
.hero {{
  background:linear-gradient(135deg,#0f1a17 0%,#121821 55%,#1a1420 100%);
  border:1px solid var(--border); border-radius:16px; padding:28px 28px 22px; margin-bottom:22px;
}}
.brand {{ font-size:12px; letter-spacing:.16em; text-transform:uppercase; color:var(--accent); font-weight:700; }}
h1 {{ margin:8px 0 6px; font-size:28px; line-height:1.2; color:#f4f7fb; }}
.subtitle {{ margin:0; color:var(--muted); font-size:14px; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin:18px 0 8px; }}
.card {{ background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:14px 14px 12px; }}
.card .k {{ font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; }}
.card .v {{ margin-top:6px; font-size:20px; font-weight:700; word-break:break-word; }}
.card .v.bad, .bad {{ color:var(--bad); }}
.card .v.warn, .warn {{ color:var(--warn); }}
.card .v.ok, .ok {{ color:var(--accent); }}
.section {{ background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:20px 22px; margin:16px 0; }}
.section h2 {{ margin:0 0 12px; font-size:18px; color:var(--accent); }}
.section h3 {{ margin:16px 0 8px; font-size:14px; color:#f4f7fb; }}
.count {{ display:inline-block; margin-left:6px; padding:1px 8px; border-radius:999px; font-size:11px; border:1px solid var(--border); color:var(--muted); }}
.kv {{ width:100%; border-collapse:collapse; }}
.kv th {{ text-align:left; width:180px; padding:8px 10px 8px 0; color:var(--muted); font-weight:600; font-size:12px; vertical-align:top; }}
.kv td {{ padding:8px 0; color:var(--text); word-break:break-word; }}
.data {{ width:100%; border-collapse:collapse; font-size:13px; }}
.data th, .data td {{ border-bottom:1px solid var(--border); padding:9px 8px; text-align:left; vertical-align:top; }}
.data th {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.04em; }}
code {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12px; color:#d7e3f4; word-break:break-all; }}
.badge {{ display:inline-block; border:1px solid var(--border); border-radius:999px; padding:2px 8px; margin:2px 4px 2px 0; font-size:11px; font-weight:700; white-space:nowrap; }}
.badge.bad {{ color:var(--bad); border-color:#804040; background:rgba(255,98,98,.08); }}
.badge.warn {{ color:var(--warn); border-color:#806d2d; background:rgba(255,209,102,.12); }}
.badge.ok {{ color:var(--accent); border-color:#1f8f72; background:rgba(66,232,180,.08); }}
ul {{ margin:8px 0 0 18px; padding:0; }}
li {{ margin:6px 0; }}
a {{ color:var(--link); text-decoration:none; }}
a:hover {{ text-decoration:underline; }}
.muted {{ color:var(--muted); }}
.note {{ background:var(--panel2); border:1px solid var(--border); border-radius:10px; padding:12px 14px; color:var(--muted); font-size:13px; }}
.footer {{ margin-top:28px; color:#6b7380; font-size:12px; text-align:center; }}
@media print {{
  body {{ background:#fff; color:#111; padding:12px; }}
  .hero, .section, .card {{ background:#fff; border-color:#ddd; }}
  .brand, .section h2 {{ color:#0a7a5c; }}
  .card .v.bad, .bad, .badge.bad {{ color:#b00020; }}
  a {{ color:#0645ad; }}
}}
</style>
</head>
<body><div class="wrap">{body}</div></body>
</html>'''
