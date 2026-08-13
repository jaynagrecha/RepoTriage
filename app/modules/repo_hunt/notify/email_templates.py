"""HTML + plain-text templates for RepoTriage alert emails."""

from __future__ import annotations

import html
from typing import Any

from ...filename_signals import detect_dual_extension


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ''), quote=True)


def _short_hash(value: Any, n: int = 16) -> str:
    s = str(value or '').strip()
    if len(s) <= n * 2:
        return s
    return f'{s[:n]}…{s[-n:]}'


def _verdict_style(verdict: str | None) -> tuple[str, str]:
    v = (verdict or 'unknown').strip().lower()
    if 'malicious' in v:
        return ('#ff6b6b', 'MALICIOUS')
    if 'suspicious' in v:
        return ('#ffd166', 'SUSPICIOUS')
    if v in {'clean', 'harmless'}:
        return ('#42e8b4', 'CLEAN')
    return ('#9aa4b2', (verdict or 'UNKNOWN').upper())


def _dual_badge_html(name: str | None) -> str:
    hit = detect_dual_extension(name)
    if not hit:
        return ''
    label = hit.get('label') or 'dual-extension'
    return (
        f'<span style="display:inline-block;margin-left:8px;padding:2px 8px;'
        f'border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.02em;'
        f'color:#ffd166;background:rgba(255,209,102,.12);border:1px solid #806d2d">'
        f'{_e(label)}</span>'
    )


def _btn(href: str, label: str, *, primary: bool = False) -> str:
    if not href:
        return ''
    bg = '#1f8f72' if primary else '#1c2430'
    border = '#42e8b4' if primary else '#2a3444'
    color = '#04140f' if primary else '#e8eef7'
    return (
        f'<a href="{_e(href)}" style="display:inline-block;margin:0 8px 8px 0;padding:10px 14px;'
        f'border-radius:8px;text-decoration:none;font-size:13px;font-weight:700;'
        f'color:{color};background:{bg};border:1px solid {border}">{_e(label)}</a>'
    )


def _meta_row(label: str, value: str, *, mono: bool = False) -> str:
    if not value:
        return ''
    font = "font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;" if mono else ''
    return (
        f'<tr><td style="padding:6px 0;color:#9aa4b2;font-size:12px;width:120px;'
        f'vertical-align:top">{_e(label)}</td>'
        f'<td style="padding:6px 0;color:#e8eef7;font-size:13px;word-break:break-all;{font}">'
        f'{value}</td></tr>'
    )


def _shell(title: str, subtitle: str, body_html: str, *, footer: str = '') -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)}</title></head>
<body style="margin:0;padding:0;background:#0b0f14;color:#e8eef7;
font-family:Segoe UI,Helvetica Neue,Arial,sans-serif">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0b0f14;padding:24px 12px">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:680px;background:#121821;
border:1px solid #243041;border-radius:14px;overflow:hidden">
<tr><td style="padding:22px 24px;background:linear-gradient(135deg,#0f1a17 0%,#121821 55%,#1a1420 100%);
border-bottom:1px solid #243041">
<div style="font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:#42e8b4;font-weight:700">RepoTriage</div>
<div style="margin-top:8px;font-size:22px;font-weight:700;color:#f4f7fb;line-height:1.25">{_e(title)}</div>
<div style="margin-top:6px;font-size:13px;color:#9aa4b2;line-height:1.45">{_e(subtitle)}</div>
</td></tr>
<tr><td style="padding:22px 24px">{body_html}</td></tr>
<tr><td style="padding:14px 24px;border-top:1px solid #243041;color:#6b7380;font-size:11px;line-height:1.5">
{_e(footer or 'Automated alert from RepoTriage. Plain-text alternative is included for non-HTML clients.')}
</td></tr>
</table>
</td></tr>
</table>
</body></html>"""


def _hit_card_html(hit: dict[str, Any], *, index: int, default_url: str = '', default_triage: str = '') -> str:
    name = hit.get('filename') or hit.get('path') or f'hit-{index}'
    url = hit.get('url') or default_url or ''
    sha = hit.get('sha256') or ''
    keywords = ', '.join(hit.get('matched_keywords') or []) or '—'
    verdict = hit.get('vt_verdict') or 'unknown'
    mal = hit.get('vt_malicious')
    label = hit.get('popular_threat_label') or '—'
    families = ', '.join(hit.get('family_labels') or []) or '—'
    vt_link = hit.get('vt_link') or (f'https://www.virustotal.com/gui/file/{sha}' if sha else '')
    triage = hit.get('triage_url') or default_triage or ''
    vcolor, vtext = _verdict_style(str(verdict))
    mal_txt = f'{mal}' if mal is not None else '—'

    rows = [
        _meta_row('Source URL', f'<a href="{_e(url)}" style="color:#7dd3fc;text-decoration:none">{_e(url)}</a>' if url else '—'),
        _meta_row('SHA256', _e(sha) if sha else '—', mono=True),
        _meta_row('Matched', _e(keywords)),
        _meta_row('VT label', _e(label)),
        _meta_row('Families', _e(families)),
    ]
    return f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 16px 0;
background:#0f141c;border:1px solid #243041;border-radius:12px">
<tr><td style="padding:16px 16px 8px 16px">
<div style="display:flex;align-items:center;flex-wrap:wrap;gap:8px">
<span style="display:inline-block;min-width:28px;height:28px;line-height:28px;text-align:center;
border-radius:8px;background:#1c2430;color:#9aa4b2;font-size:12px;font-weight:700">{index}</span>
<span style="font-size:16px;font-weight:700;color:#f4f7fb;word-break:break-all">{_e(name)}</span>
{_dual_badge_html(str(name))}
</div>
<div style="margin-top:10px">
<span style="display:inline-block;padding:4px 10px;border-radius:999px;font-size:11px;font-weight:800;
letter-spacing:.04em;color:{vcolor};background:rgba(255,255,255,.04);border:1px solid {vcolor}33">{vtext}</span>
<span style="display:inline-block;margin-left:8px;padding:4px 10px;border-radius:999px;font-size:11px;
font-weight:700;color:#e8eef7;background:#1c2430;border:1px solid #2a3444">VT malicious={_e(mal_txt)}</span>
</div>
</td></tr>
<tr><td style="padding:0 16px 8px 16px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0">{''.join(rows)}</table>
</td></tr>
<tr><td style="padding:4px 16px 16px 16px">
{_btn(vt_link, 'Open VirusTotal', primary=True)}
{_btn(triage, 'Open in RepoTriage')}
{_btn(url, 'Source file') if url else ''}
</td></tr>
</table>"""


def render_wu_alert_html(
    *,
    title: str,
    subtitle: str,
    mode: str,
    job_id: str | None,
    source_url: str,
    triage_url: str,
    rule_id: str,
    hits: list[dict[str, Any]],
) -> str:
    meta = (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="margin-bottom:18px">'
        + _meta_row('Mode', _e(mode))
        + _meta_row('Job', _e(job_id or '—'), mono=True)
        + _meta_row('LiveHunt rule', _e(f'DETECT_GTI_MaliciousFilesWithWUKeywords (id {rule_id})'))
        + _meta_row(
            'Source',
            f'<a href="{_e(source_url)}" style="color:#7dd3fc;text-decoration:none">{_e(source_url)}</a>'
            if source_url else '—',
        )
        + '</table>'
        + (
            f'<div style="margin:0 0 18px 0">{_btn(triage_url, "Open triage job", primary=True)}</div>'
            if triage_url else ''
        )
        + f'<div style="margin:0 0 10px 0;font-size:13px;color:#9aa4b2;font-weight:700;'
        f'letter-spacing:.06em;text-transform:uppercase">Hits · {len(hits)}</div>'
    )
    cards = ''.join(
        _hit_card_html(h, index=i, default_url=source_url, default_triage=triage_url)
        for i, h in enumerate(hits, 1)
    )
    return _shell(title, subtitle, meta + cards, footer='WU/MTCN LiveHunt mirror · sent only on hits')


def render_wu_alert_text(
    *,
    header: str,
    mode: str,
    job_id: str | None,
    source_url: str,
    triage_url: str,
    rule_id: str,
    hits: list[dict[str, Any]],
) -> str:
    lines = [
        header,
        f'LiveHunt rule: DETECT_GTI_MaliciousFilesWithWUKeywords (id {rule_id})',
        f'Mode: {mode}',
        f'Job: {job_id or "-"}',
        f'Source: {source_url or "-"}',
        f'Triage: {triage_url or "-"}',
        '',
    ]
    for i, hit in enumerate(hits, 1):
        name = hit.get('filename') or hit.get('path') or '-'
        dual = detect_dual_extension(str(name) if name else None)
        lines.extend([
            f'{i}. {name}' + (f'  [{dual["label"]}]' if dual else ''),
            f'   url: {hit.get("url") or source_url or "-"}',
            f'   sha256: {hit.get("sha256") or "-"}',
            f'   matched: {",".join(hit.get("matched_keywords") or []) or "-"}',
            f'   vt: verdict={hit.get("vt_verdict") or "-"} malicious={hit.get("vt_malicious") if hit.get("vt_malicious") is not None else "-"} '
            f'label={hit.get("popular_threat_label") or "-"}',
            f'   families: {",".join(hit.get("family_labels") or []) or "-"}',
            f'   vt link: {hit.get("vt_link") or "-"}',
            f'   triage: {hit.get("triage_url") or triage_url or "-"}',
            '',
        ])
    return '\n'.join(lines)


def render_hunt_findings_html(
    *,
    findings_count: int,
    summary: str,
    run_meta: dict[str, Any],
    cards_html: str,
    truncated_note: str = '',
) -> str:
    subtitle = f'{findings_count} hit(s) · {summary}'
    meta = (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:18px">'
        + _meta_row('Sources scanned', _e(run_meta.get('sources')))
        + _meta_row('Candidates', _e(run_meta.get('candidates')))
        + _meta_row('Local matches', _e(run_meta.get('local_matches')))
        + _meta_row('WU/MTCN name matches', _e(run_meta.get('wu_name_matches', 0)))
        + '</table>'
        + '<div style="margin:0 0 14px 0;padding:12px 14px;border-radius:10px;background:#0f141c;'
        'border:1px solid #243041;color:#9aa4b2;font-size:12px;line-height:1.5">'
        '<b style="color:#e8eef7">Rules covered</b><br>'
        '• potential_jsoutprox_js (JsOutProx LiveHunt mirror)<br>'
        '• DETECT_GTI_MaliciousFilesWithWUKeywords (WU/MTCN filename + VT malicious&gt;0)<br>'
        '• FINANCIAL_REPO_VT_MALICIOUS (keyword-matched repo recent files + VT malicious&gt;0)'
        '</div>'
        + f'<div style="margin:0 0 10px 0;font-size:13px;color:#9aa4b2;font-weight:700;'
        f'letter-spacing:.06em;text-transform:uppercase">Findings · {findings_count}</div>'
        + cards_html
        + (f'<div style="color:#9aa4b2;font-size:12px;margin-top:8px">{_e(truncated_note)}</div>' if truncated_note else '')
    )
    return _shell('Repository hunt alert', subtitle, meta, footer='Automated RepoTriage hunt worker alert')


def finding_card_html(
    *,
    index: int,
    rule: str,
    repo: str,
    path: str,
    source: str,
    url: str,
    filename: str,
    sha256: str,
    filesize: Any,
    matched: str,
    vt_status: Any,
    vt_verdict: Any,
    vt_malicious: Any,
    triage_url: str,
    livehunt: Any = '',
) -> str:
    vcolor, vtext = _verdict_style(str(vt_verdict) if vt_verdict else None)
    vt_link = f'https://www.virustotal.com/gui/file/{sha256}' if sha256 else ''
    rows = [
        _meta_row('Rule', _e(rule)),
        _meta_row('Repo', _e(repo or '—')),
        _meta_row('Path', _e(path or '—'), mono=True),
        _meta_row('Source', _e(source or '—')),
        _meta_row('URL', f'<a href="{_e(url)}" style="color:#7dd3fc;text-decoration:none">{_e(url)}</a>' if url else '—'),
        _meta_row('SHA256', _e(sha256 or '—'), mono=True),
        _meta_row('Size', _e(f'{filesize} bytes') if filesize is not None else '—'),
        _meta_row('Matched', _e(matched or '—')),
        _meta_row('VT status', _e(f'{vt_status or "—"} · livehunt={livehunt or "—"}')),
    ]
    return f"""
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 16px 0;
background:#0f141c;border:1px solid #243041;border-radius:12px">
<tr><td style="padding:16px 16px 8px 16px">
<span style="display:inline-block;min-width:28px;height:28px;line-height:28px;text-align:center;
border-radius:8px;background:#1c2430;color:#9aa4b2;font-size:12px;font-weight:700">{index}</span>
<span style="font-size:16px;font-weight:700;color:#f4f7fb;word-break:break-all;margin-left:8px">{_e(filename or path or '—')}</span>
{_dual_badge_html(filename or path)}
<div style="margin-top:10px">
<span style="display:inline-block;padding:4px 10px;border-radius:999px;font-size:11px;font-weight:800;
letter-spacing:.04em;color:{vcolor};background:rgba(255,255,255,.04);border:1px solid {vcolor}33">{vtext}</span>
<span style="display:inline-block;margin-left:8px;padding:4px 10px;border-radius:999px;font-size:11px;
font-weight:700;color:#e8eef7;background:#1c2430;border:1px solid #2a3444">VT malicious={_e(vt_malicious if vt_malicious is not None else '—')}</span>
</div>
</td></tr>
<tr><td style="padding:0 16px 8px 16px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0">{''.join(rows)}</table>
</td></tr>
<tr><td style="padding:4px 16px 16px 16px">
{_btn(vt_link, 'Open VirusTotal', primary=True) if sha256 else ''}
{_btn(triage_url, 'Open in RepoTriage')}
{_btn(url, 'Source file') if url else ''}
</td></tr>
</table>"""
