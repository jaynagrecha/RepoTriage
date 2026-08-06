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
    if r == 'critical':
        return 'critical'
    if r == 'high':
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
    return f'<a class="link" href="{_e(href)}" target="_blank" rel="noopener">{_e(label)}</a>'


def _kv_table(rows: list[tuple[str, str]]) -> str:
    body = ''.join(f'<tr><th>{_e(k)}</th><td>{v}</td></tr>' for k, v in rows)
    return f'<div class="table-scroll"><table class="kv">{body}</table></div>'


class _SectionCounter:
    def __init__(self) -> None:
        self.n = 0

    def section(self, title: str, body: str, *, lead: str = '') -> str:
        self.n += 1
        num = f'{self.n:02d}'
        lead_html = f'<p class="section-lead">{_e(lead)}</p>' if lead else ''
        return (
            f'<section class="section" id="sec-{num}">'
            f'<div class="section-head"><span class="section-num">{num}</span>'
            f'<h2>{_e(title)}</h2></div>{lead_html}{body}</section>'
        )


def _bullets(items: list[Any], empty: str = 'None observed.', *, raw: bool = False, numbered: bool = False) -> str:
    clean = [x for x in items if x not in (None, '')]
    if not clean:
        return f'<p class="empty">{_e(empty)}</p>'
    tag = 'ol' if numbered else 'ul'
    cls = 'list numbered' if numbered else 'list'
    lis = []
    for x in clean:
        lis.append(f'<li>{x}</li>' if raw else f'<li>{_e(x)}</li>')
    return f'<{tag} class="{cls}">' + ''.join(lis) + f'</{tag}>'


def _css() -> str:
    return '''
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&family=IBM+Plex+Mono:wght@400;500;600&display=swap');
:root {
  --bg: #070b10;
  --bg-elev: #0c1219;
  --panel: rgba(18, 26, 36, 0.92);
  --panel-solid: #121a24;
  --panel2: #0e151e;
  --border: rgba(66, 232, 180, 0.12);
  --border-strong: rgba(125, 211, 252, 0.18);
  --text: #eef3f8;
  --muted: #8b97a8;
  --accent: #3ee6b0;
  --accent-dim: rgba(62, 230, 176, 0.14);
  --bad: #ff6b7a;
  --bad-dim: rgba(255, 107, 122, 0.12);
  --warn: #f0c45a;
  --warn-dim: rgba(240, 196, 90, 0.12);
  --critical: #ff3d5a;
  --link: #7dd3fc;
  --shadow: 0 18px 50px rgba(0, 0, 0, 0.45);
  --radius: 18px;
  --mono: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --sans: "DM Sans", "Segoe UI", Helvetica Neue, Arial, sans-serif;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  min-height: 100vh;
  color: var(--text);
  font: 15.5px/1.6 var(--sans);
  background:
    radial-gradient(900px 480px at 8% -8%, rgba(62, 230, 176, 0.16), transparent 55%),
    radial-gradient(700px 420px at 92% 0%, rgba(125, 211, 252, 0.10), transparent 50%),
    radial-gradient(600px 400px at 70% 100%, rgba(255, 107, 122, 0.06), transparent 45%),
    linear-gradient(180deg, #0a1017 0%, var(--bg) 40%, #06090d 100%);
  padding: 28px 16px 72px;
  -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 1100px; margin: 0 auto; position: relative; }
.topbar {
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  margin-bottom: 18px; padding: 10px 4px; color: var(--muted); font-size: 12px; letter-spacing: .04em;
}
.topbar .mark {
  display: inline-flex; align-items: center; gap: 8px; font-weight: 700; color: var(--accent);
  text-transform: uppercase; letter-spacing: .18em; font-size: 11px;
}
.topbar .mark::before {
  content: ""; width: 8px; height: 8px; border-radius: 50%;
  background: var(--accent); box-shadow: 0 0 0 4px var(--accent-dim);
}
.hero {
  position: relative; overflow: hidden;
  background:
    linear-gradient(135deg, rgba(15, 28, 24, 0.95) 0%, rgba(18, 26, 36, 0.96) 48%, rgba(22, 16, 28, 0.92) 100%);
  border: 1px solid var(--border-strong);
  border-radius: calc(var(--radius) + 4px);
  padding: 30px 30px 26px;
  box-shadow: var(--shadow);
  margin-bottom: 20px;
}
.hero::before {
  content: ""; position: absolute; inset: 0 auto 0 0; width: 4px;
  background: linear-gradient(180deg, var(--accent), #7dd3fc 55%, var(--bad));
}
.hero::after {
  content: ""; position: absolute; right: -80px; top: -80px; width: 240px; height: 240px;
  border-radius: 50%; background: radial-gradient(circle, rgba(62,230,176,.18), transparent 68%);
  pointer-events: none;
}
.brand { font-size: 11px; letter-spacing: .2em; text-transform: uppercase; color: var(--accent); font-weight: 700; }
.hero-row { display: flex; flex-wrap: wrap; align-items: flex-start; justify-content: space-between; gap: 16px; margin-top: 10px; }
h1 {
  margin: 0; font-size: clamp(28px, 4vw, 36px); line-height: 1.15; font-weight: 700;
  letter-spacing: -0.03em; color: #f7fbff;
}
.subtitle { margin: 10px 0 0; color: var(--muted); font-size: 14px; max-width: 52ch; }
.risk-pill {
  display: inline-flex; flex-direction: column; align-items: flex-end; gap: 6px;
  padding: 12px 16px; border-radius: 14px; border: 1px solid var(--border);
  background: rgba(7, 11, 16, 0.55); min-width: 140px;
}
.risk-pill .label { font-size: 10px; letter-spacing: .14em; text-transform: uppercase; color: var(--muted); }
.risk-pill .value { font-size: 22px; font-weight: 700; letter-spacing: -0.02em; }
.risk-pill.critical { border-color: rgba(255,61,90,.45); background: rgba(255,61,90,.08); }
.risk-pill.critical .value { color: var(--critical); }
.risk-pill.bad { border-color: rgba(255,107,122,.4); background: var(--bad-dim); }
.risk-pill.bad .value { color: var(--bad); }
.risk-pill.warn { border-color: rgba(240,196,90,.35); background: var(--warn-dim); }
.risk-pill.warn .value { color: var(--warn); }
.risk-pill.ok { border-color: rgba(62,230,176,.35); background: var(--accent-dim); }
.risk-pill.ok .value { color: var(--accent); }
.cards {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(148px, 1fr));
  gap: 12px; margin: 0 0 8px;
}
.card {
  position: relative; overflow: hidden;
  background: var(--panel); border: 1px solid var(--border); border-radius: 14px;
  padding: 16px 16px 14px; backdrop-filter: blur(8px);
  transition: border-color .2s ease, transform .2s ease;
}
.card:hover { border-color: rgba(62, 230, 176, 0.28); transform: translateY(-1px); }
.card .k {
  font-size: 10.5px; color: var(--muted); text-transform: uppercase;
  letter-spacing: .08em; font-weight: 600;
}
.card .v {
  margin-top: 8px; font-size: 21px; font-weight: 700; letter-spacing: -0.02em;
  word-break: break-word; line-height: 1.2;
}
.card .v.critical, .critical { color: var(--critical); }
.card .v.bad, .bad { color: var(--bad); }
.card .v.warn, .warn { color: var(--warn); }
.card .v.ok, .ok { color: var(--accent); }
.section {
  background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 22px 24px 20px; margin: 16px 0; box-shadow: 0 10px 30px rgba(0,0,0,.18);
}
.section-head { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }
.section-num {
  display: inline-flex; align-items: center; justify-content: center;
  width: 34px; height: 34px; border-radius: 10px; flex: 0 0 auto;
  font: 600 12px/1 var(--mono); color: var(--accent);
  background: var(--accent-dim); border: 1px solid rgba(62,230,176,.25);
}
.section h2 {
  margin: 0; font-size: 17px; font-weight: 700; letter-spacing: -0.02em; color: #f3f7fb;
}
.section h3 {
  margin: 20px 0 10px; font-size: 13px; font-weight: 700; color: var(--text);
  display: flex; align-items: center; gap: 8px;
}
.section-lead { margin: -4px 0 14px; color: var(--muted); font-size: 13.5px; }
.count {
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 22px; height: 20px; padding: 0 7px; border-radius: 999px;
  font-size: 11px; font-weight: 700; font-family: var(--mono);
  border: 1px solid var(--border); color: var(--muted); background: var(--panel2);
}
.table-scroll { width: 100%; overflow-x: auto; border-radius: 12px; }
.kv { width: 100%; border-collapse: collapse; }
.kv tr + tr th, .kv tr + tr td { border-top: 1px solid rgba(36, 48, 65, 0.85); }
.kv th {
  text-align: left; width: 190px; padding: 11px 14px 11px 0;
  color: var(--muted); font-weight: 600; font-size: 12px; vertical-align: top;
}
.kv td { padding: 11px 0; color: var(--text); word-break: break-word; }
.data {
  width: 100%; border-collapse: separate; border-spacing: 0;
  font-size: 13px; border: 1px solid var(--border); border-radius: 12px; overflow: hidden;
  background: var(--panel2);
}
.data th, .data td {
  padding: 11px 12px; text-align: left; vertical-align: top;
  border-bottom: 1px solid rgba(36, 48, 65, 0.9);
}
.data th {
  color: var(--muted); font-size: 10.5px; text-transform: uppercase;
  letter-spacing: .06em; font-weight: 700; background: rgba(7, 11, 16, 0.55);
}
.data tbody tr:nth-child(even) td { background: rgba(255,255,255,0.015); }
.data tbody tr:hover td { background: rgba(62, 230, 176, 0.04); }
.data tr:last-child td { border-bottom: 0; }
code, .mono {
  font-family: var(--mono); font-size: 12px; font-weight: 500;
  color: #d5e4f5; word-break: break-all;
}
.badge {
  display: inline-flex; align-items: center; gap: 4px;
  border: 1px solid var(--border); border-radius: 999px;
  padding: 3px 9px; margin: 2px 4px 2px 0; font-size: 11px; font-weight: 700;
  white-space: nowrap; letter-spacing: .01em; background: rgba(255,255,255,.02);
}
.badge.bad { color: var(--bad); border-color: rgba(255,107,122,.35); background: var(--bad-dim); }
.badge.warn { color: var(--warn); border-color: rgba(240,196,90,.35); background: var(--warn-dim); }
.badge.ok { color: var(--accent); border-color: rgba(62,230,176,.35); background: var(--accent-dim); }
.badge.critical { color: var(--critical); border-color: rgba(255,61,90,.4); background: rgba(255,61,90,.1); }
.list { margin: 4px 0 0; padding: 0; list-style: none; }
.list li {
  position: relative; margin: 0; padding: 10px 12px 10px 34px;
  border: 1px solid transparent; border-radius: 10px;
}
.list li + li { margin-top: 4px; }
.list li::before {
  content: ""; position: absolute; left: 14px; top: 17px;
  width: 7px; height: 7px; border-radius: 50%; background: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-dim);
}
.list.numbered { counter-reset: steps; }
.list.numbered li { padding-left: 44px; background: var(--panel2); border-color: var(--border); }
.list.numbered li::before {
  counter-increment: steps; content: counter(steps);
  width: 22px; height: 22px; top: 10px; left: 12px;
  display: inline-flex; align-items: center; justify-content: center;
  font: 700 11px/1 var(--mono); color: var(--accent); background: var(--accent-dim);
  border-radius: 7px; box-shadow: none;
}
.link { color: var(--link); text-decoration: none; border-bottom: 1px solid transparent; }
.link:hover { border-bottom-color: rgba(125, 211, 252, 0.5); }
.muted { color: var(--muted); }
.empty {
  margin: 0; padding: 16px; border-radius: 12px; color: var(--muted);
  background: var(--panel2); border: 1px dashed rgba(139, 151, 168, 0.25); font-size: 13.5px;
}
.note {
  background: linear-gradient(135deg, rgba(62,230,176,.06), rgba(125,211,252,.05));
  border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px;
  color: var(--muted); font-size: 13px; margin-top: 12px;
}
.note b { color: var(--text); }
.toc {
  display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 8px;
}
.toc a {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 7px 11px; border-radius: 999px; font-size: 12px; font-weight: 600;
  color: var(--muted); text-decoration: none; border: 1px solid var(--border);
  background: rgba(18, 26, 36, 0.7);
}
.toc a:hover { color: var(--text); border-color: rgba(62,230,176,.3); }
.footer {
  margin-top: 28px; padding-top: 18px; border-top: 1px solid var(--border);
  color: #667084; font-size: 12px; text-align: center; letter-spacing: .02em;
}
@media (max-width: 720px) {
  body { padding: 16px 10px 48px; }
  .hero, .section { padding: 18px 16px; border-radius: 14px; }
  .kv th { width: 120px; font-size: 11px; }
  .risk-pill { align-items: flex-start; width: 100%; }
}
@media print {
  @page { margin: 14mm; }
  body {
    background: #fff !important; color: #121418; padding: 0;
    font-size: 11pt;
  }
  .topbar, .toc, .hero::after { display: none !important; }
  .hero, .section, .card, .data, .list.numbered li, .note, .empty {
    background: #fff !important; border-color: #d7dde5 !important;
    box-shadow: none !important; backdrop-filter: none !important;
  }
  .hero::before { background: #0f8f6c; }
  .brand, .section-num, .card .v.ok, .ok { color: #0f8f6c !important; }
  .card .v.bad, .bad, .badge.bad { color: #c0152f !important; }
  .card .v.critical, .critical, .badge.critical, .risk-pill.critical .value { color: #a50020 !important; }
  h1, .section h2, .section h3 { color: #121418 !important; }
  .muted, .section-lead, .footer, .card .k { color: #5b6573 !important; }
  a, .link { color: #0b57d0 !important; }
  .section { break-inside: avoid; }
}
'''


def render_analyst_report_html(result: dict[str, Any], *, generated_at: str | None = None) -> str:
    """Return a complete standalone HTML document for the analyst report download."""
    from .cti_fusion import (
        build_campaign_analysis,
        build_cti_dashboard,
        build_threat_actor_assessment,
    )

    sec = _SectionCounter()

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
    risk_cls = _risk_class(risk)
    family = dash.get('primary_family') or vt.get('popular_threat_label') or 'Unknown'
    source_url = source.get('display_url') or source.get('url') or '—'
    root_name = root.get('filename') or source.get('filename') or '—'
    sha = root.get('sha256') or '—'

    vt_contacted_n = len((result.get('infrastructure') or {}).get('vt_contacted') or [])
    cards = [
        ('Overall Risk', risk, risk_cls),
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
        ('Owner / Repo', f'<span class="mono">{_e(f"{source.get("owner") or "—"}/{source.get("repo") or "—"}")}</span>'),
        ('Root file', f'{_e(root_name)} {_dual(str(root_name))}'),
        ('SHA256', f'<code>{_e(sha)}</code>'),
        ('VT verdict', f'{_badge(str(vt.get("verdict") or "unknown"), "bad" if str(vt.get("verdict", "")).lower() == "malicious" else "")} <span class="muted">{_e(vt.get("detections_summary") or "")}</span>'),
        ('Popular threat label', _e(vt.get('popular_threat_label') or '—')),
        ('Family labels', ' '.join(_badge(x, 'bad') for x in (vt.get('family_labels') or [])[:12]) or '—'),
        ('Campaign', _e(f"{camp.get('candidate')} · {camp.get('confidence_band')} ({camp.get('confidence_score')}%)")),
        ('Threat actor', _e(f"{actor.get('primary_assessment')} · {actor.get('confidence_band')} ({actor.get('confidence_score')}%)")),
    ])

    narrative_html = _bullets(narrative.get('narrative_bullets') or [], 'No attack narrative generated.')
    objectives_html = _bullets(narrative.get('likely_objectives') or ['Unknown based on current static evidence'])

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
            f'<td>{_link(f.get("vt_link"), "Open VT")}</td></tr>'
        )
    mal_table = (
        '<div class="table-scroll"><table class="data"><thead><tr><th>File</th><th>Type</th><th>SHA256</th><th>VT</th><th>Link</th></tr></thead>'
        f'<tbody>{"".join(mal_rows)}</tbody></table></div>'
        if mal_rows else '<p class="empty">None observed from current enrichment results.</p>'
    )

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
            f'<div class="table-scroll"><table class="data"><thead><tr><th>Indicator</th><th>Type</th><th>Confidence</th><th>Source</th><th>Detail</th></tr></thead>'
            f'<tbody>{"".join(items)}</tbody></table></div>'
        )
    infra_html = ''.join(infra_blocks) or '<p class="empty">No enriched infrastructure highlights observed.</p>'

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
            rel_cards += _bullets([
                f'<code>{_e(d.get("filename"))}</code> — {_e(d.get("label"))}'
                for d in duals[:20] if isinstance(d, dict)
            ], raw=True)
    else:
        rel_cards = '<p class="empty">No relations graph available for this job.</p>'

    techniques = (result.get('mitre') or {}).get('techniques') or []
    if techniques:
        mitre_html = (
            '<div class="table-scroll"><table class="data"><thead><tr><th>ID</th><th>Name</th><th>Tactic</th><th>Confidence</th></tr></thead><tbody>'
            + ''.join(
                f'<tr><td><code>{_e(t.get("id"))}</code></td><td>{_e(t.get("name"))}</td>'
                f'<td>{_e(t.get("tactic"))}</td><td>{_badge(str(t.get("confidence") or "Medium"), "bad" if t.get("confidence") == "High" else "warn")}</td></tr>'
                for t in techniques
            )
            + '</tbody></table></div>'
        )
    else:
        mitre_html = '<p class="empty">No ATT&CK mappings generated.</p>'

    camp_ev = _bullets([
        f'{_e(e.get("signal"))} — {_e(e.get("detail"))} <span class="muted">[{_e(e.get("source"))}]</span>'
        for e in (camp.get('evidence') or [])
    ], 'No campaign evidence.', raw=True)
    actor_ev = _bullets([
        f'{_e(e.get("signal"))} — {_e(e.get("detail"))} <span class="muted">[{_e(e.get("source"))}]</span>'
        for e in (actor.get('evidence') or [])
    ], 'No actor evidence.', raw=True)

    actions_html = _bullets(
        narrative.get('recommended_actions') or ['Continue manual review.'],
        numbered=True,
    )

    cti_note = (
        '<p class="note">CTI enrichment is <b>query-only</b> (ThreatFox, URLHaus, Feodo, SSLBL, MalwareBazaar). '
        'RepoTriage does not submit IOCs or samples to those feeds. '
        'VT contacted domains are queried on ThreatFox + URLHaus host API; Feodo/SSLBL require IPs.</p>'
    )
    exec_summary = f'''
<p>Overall risk <b class="{risk_cls}">{_e(risk)}</b> with primary family/signature
<b>{_e(family)}</b>. {int(stats.get("malicious") or 0)} malicious file(s) of {int(stats.get("total_listed") or 0)} listed;
{_e(dash.get("ioc_count", 0))} IOC(s); {_e(dash.get("mitre_count", 0))} MITRE mapping(s).</p>
<p>Campaign: <b>{_e(camp.get("candidate"))}</b> ({_e(camp.get("confidence_band"))}).
Threat actor: <b>{_e(actor.get("primary_assessment"))}</b> ({_e(actor.get("confidence_band"))}).</p>
{cti_note}
'''

    # Build sections first so TOC anchors match numbering
    sections = [
        sec.section('Case Metadata', meta, lead='Source, hashes, and VirusTotal classification for this job.'),
        sec.section('Executive Summary', exec_summary),
        sec.section('Attack Narrative', narrative_html),
        sec.section('Likely Objective', objectives_html),
        sec.section('Malicious Files', mal_table),
        sec.section('Relations Snapshot', rel_cards, lead='VT/local parent-child and dual-extension signals.'),
        sec.section('Infrastructure', infra_html),
        sec.section('MITRE ATT&CK', mitre_html),
        sec.section(
            'Campaign Correlation',
            f'<p><b>{_e(camp.get("candidate"))}</b> — {_e(camp.get("confidence_band"))} ({_e(camp.get("confidence_score"))}%)</p>{camp_ev}',
        ),
        sec.section(
            'Threat Actor Assessment',
            f'<p><b>{_e(actor.get("primary_assessment"))}</b> — {_e(actor.get("confidence_band"))} ({_e(actor.get("confidence_score"))}%)</p>'
            f'<p class="muted">{_e(actor.get("analyst_note") or "")}</p>{actor_ev}',
        ),
        sec.section('Recommended Analyst Actions', actions_html),
    ]
    if narrative.get('system_notes'):
        sections.append(sec.section('System Notes', _bullets(narrative.get('system_notes') or [])))

    toc = '<nav class="toc">' + ''.join(
        f'<a href="#sec-{i:02d}">{i:02d}</a>'
        for i in range(1, sec.n + 1)
    ) + '</nav>'

    body = f'''
<div class="topbar">
  <div class="mark">RepoTriage</div>
  <div>Analyst report · {_e(generated)}</div>
</div>
<header class="hero">
  <div class="brand">Payload intelligence</div>
  <div class="hero-row">
    <div>
      <h1>Analyst Report</h1>
      <p class="subtitle">{_e(root_name)} · {_e(family)}</p>
    </div>
    <div class="risk-pill {risk_cls}">
      <span class="label">Overall risk</span>
      <span class="value">{_e(risk)}</span>
    </div>
  </div>
</header>
{toc}
<div class="cards">{cards_html}</div>
{''.join(sections)}
<footer class="footer">Generated by RepoTriage · {_e(generated)} · Standalone HTML export</footer>
'''

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>RepoTriage Analyst Report — {_e(root_name)}</title>
<style>{_css()}</style>
</head>
<body><div class="wrap">{body}</div></body>
</html>'''
