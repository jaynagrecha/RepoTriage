from __future__ import annotations

import smtplib
import ssl
from collections import Counter
from email.message import EmailMessage
from typing import Any

from ..config import RepoHuntConfig
from ..types import Finding
from .email_templates import (
    finding_card_html,
    render_hunt_findings_html,
    render_wu_alert_html,
    render_wu_alert_text,
)


def _rule_summary(findings: list[Finding]) -> str:
    counts = Counter((f.detection.rule or 'unknown') for f in findings)
    parts = [f'{rule}×{n}' for rule, n in counts.most_common()]
    return ', '.join(parts) if parts else 'findings'


def _attach_multipart(msg: EmailMessage, text_body: str, html_body: str) -> EmailMessage:
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype='html')
    return msg


def build_findings_email(findings: list[Finding], cfg: RepoHuntConfig, *, run_meta: dict[str, Any]) -> EmailMessage:
    msg = EmailMessage()
    summary = _rule_summary(findings)
    msg['Subject'] = f'[RepoTriage Hunt] {len(findings)} hit(s): {summary}'
    msg['From'] = cfg.smtp_from
    msg['To'] = cfg.smtp_to

    lines = [
        'RepoTriage automated repository hunt',
        f'Findings: {len(findings)} ({summary})',
        f"Sources scanned: {run_meta.get('sources')}",
        f"Candidates checked: {run_meta.get('candidates')}",
        f"Local matches: {run_meta.get('local_matches')}",
        f"WU/MTCN name matches: {run_meta.get('wu_name_matches', 0)}",
        f"Financial repo files scanned: {run_meta.get('financial_repo_files', 0)}",
        '',
        'Rules covered:',
        '  - potential_jsoutprox_js (JsOutProx LiveHunt mirror)',
        '  - DETECT_GTI_MaliciousFilesWithWUKeywords (WU/MTCN filename + VT malicious>0)',
        '  - FINANCIAL_REPO_VT_MALICIOUS (keyword-matched repo recent files + VT malicious>0)',
        '',
    ]
    cards: list[str] = []
    shown = findings[: cfg.max_findings_email]
    for i, f in enumerate(shown, 1):
        c = f.candidate
        vt = f.detection.vt_confirm or {}
        url = c.html_url or c.url or ''
        lines.extend([
            f'{i}. [{f.detection.rule}] {c.repo or "-"} :: {c.path or f.filename or c.url}',
            f'   source: {c.source}',
            f'   url: {url}',
            f'   filename: {f.filename}',
            f'   sha256: {f.sha256}',
            f'   size: {f.detection.filesize} bytes',
            f'   matched: {",".join(f.detection.matched_strings) or "-"}',
            f'   vt: status={vt.get("status")} verdict={vt.get("verdict")} '
            f'malicious={vt.get("malicious")} livehunt={vt.get("livehunt_rule_id")}',
            f'   triage: {f.triage_url or "(set REPOTRIAGE_PUBLIC_URL)"}',
            '',
        ])
        cards.append(
            finding_card_html(
                index=i,
                rule=f.detection.rule or 'unknown',
                repo=c.repo or '',
                path=c.path or f.filename or '',
                source=c.source or '',
                url=url,
                filename=f.filename or c.path or '',
                sha256=f.sha256 or '',
                filesize=f.detection.filesize,
                matched=','.join(f.detection.matched_strings) or '-',
                vt_status=vt.get('status'),
                vt_verdict=vt.get('verdict'),
                vt_malicious=vt.get('malicious'),
                triage_url=f.triage_url or '',
                livehunt=vt.get('livehunt_rule_id'),
            )
        )
    truncated = ''
    if len(findings) > cfg.max_findings_email:
        truncated = f'…and {len(findings) - cfg.max_findings_email} more (truncated).'
        lines.append(truncated)

    html_body = render_hunt_findings_html(
        findings_count=len(findings),
        summary=summary,
        run_meta=run_meta,
        cards_html=''.join(cards),
        truncated_note=truncated,
    )
    return _attach_multipart(msg, '\n'.join(lines), html_body)


def build_analysis_wu_alert_email(
    *,
    cfg: RepoHuntConfig,
    job_id: str | None,
    source_url: str,
    hits: list[dict[str, Any]],
    triage_url: str = '',
    scan_mode: str = 'analyze',
) -> EmailMessage:
    """WU/MTCN alert — used by manual Analyze and the 5-minute scheduled scan."""
    msg = EmailMessage()
    mode = (scan_mode or 'analyze').strip().lower()
    rule_id = cfg.vt_livehunt_wu_rule_id or '20744291635'
    if mode in {'scheduled', 'hunt', 'loop', 'worker'}:
        msg['Subject'] = (
            f'[RepoTriage WU/Financial] {len(hits)} hit(s) '
            f'(keyword repo watch · VT malicious · scheduled scan)'
        )
        title = 'WU/Financial repo watch hit'
        subtitle = (
            'Scheduled WU/financial keyword-repo watch (every REPO_HUNT_INTERVAL_SECONDS) — '
            'emails when a recent file in a matching repo is VT malicious.'
        )
        header = (
            'RepoTriage scheduled WU/financial repo watch '
            '(last 10 commits → top 5 newest files → VT) — '
            'email sent only when a malicious file is found.'
        )
    else:
        msg['Subject'] = (
            f'[RepoTriage Analyze] WU/MTCN LiveHunt hit(s): {len(hits)} '
            f'(DETECT_GTI_MaliciousFilesWithWUKeywords)'
        )
        title = 'WU/MTCN analysis alert'
        subtitle = 'Western Union / MTCN malicious filename rule matched during Analyze'
        header = 'RepoTriage analysis alert — Western Union / MTCN malicious filename rule'
    msg['From'] = cfg.smtp_from
    msg['To'] = cfg.smtp_to

    text_body = render_wu_alert_text(
        header=header,
        mode=mode,
        job_id=job_id,
        source_url=source_url,
        triage_url=triage_url or cfg.triage_base_url or '',
        rule_id=str(rule_id),
        hits=hits,
    )
    html_body = render_wu_alert_html(
        title=title,
        subtitle=subtitle,
        mode=mode,
        job_id=job_id,
        source_url=source_url,
        triage_url=triage_url or cfg.triage_base_url or '',
        rule_id=str(rule_id),
        hits=hits,
    )
    return _attach_multipart(msg, text_body, html_body)


def send_email(msg: EmailMessage, cfg: RepoHuntConfig) -> dict[str, Any]:
    if not cfg.smtp_ready():
        return {'ok': False, 'error': 'SMTP not configured (SMTP_HOST / SMTP_FROM / REPO_HUNT_TO_EMAIL)'}
    try:
        if cfg.smtp_use_tls:
            context = ssl.create_default_context()
            with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=45) as smtp:
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
                if cfg.smtp_user:
                    smtp.login(cfg.smtp_user, cfg.smtp_password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=45) as smtp:
                if cfg.smtp_user:
                    smtp.login(cfg.smtp_user, cfg.smtp_password)
                smtp.send_message(msg)
        return {
            'ok': True,
            'to': cfg.smtp_to,
            'subject': msg['Subject'],
            'format': 'multipart/alternative' if msg.is_multipart() else 'text/plain',
        }
    except Exception as exc:
        return {'ok': False, 'error': f'{exc.__class__.__name__}: {exc}'}
