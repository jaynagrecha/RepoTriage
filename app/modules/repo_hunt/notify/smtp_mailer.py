from __future__ import annotations

import smtplib
import ssl
from collections import Counter
from email.message import EmailMessage
from typing import Any

from ..config import RepoHuntConfig
from ..types import Finding


def _rule_summary(findings: list[Finding]) -> str:
    counts = Counter((f.detection.rule or 'unknown') for f in findings)
    parts = [f'{rule}×{n}' for rule, n in counts.most_common()]
    return ', '.join(parts) if parts else 'findings'


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
        '',
        'Rules covered:',
        '  - potential_jsoutprox_js (JsOutProx LiveHunt mirror)',
        '  - DETECT_GTI_MaliciousFilesWithWUKeywords (WU/MTCN filename + VT malicious>0)',
        '',
    ]
    for i, f in enumerate(findings[: cfg.max_findings_email], 1):
        c = f.candidate
        vt = f.detection.vt_confirm or {}
        lines.extend([
            f'{i}. [{f.detection.rule}] {c.repo or "-"} :: {c.path or f.filename or c.url}',
            f'   source: {c.source}',
            f'   url: {c.html_url or c.url}',
            f'   filename: {f.filename}',
            f'   sha256: {f.sha256}',
            f'   size: {f.detection.filesize} bytes',
            f'   matched: {",".join(f.detection.matched_strings) or "-"}',
            f'   vt: status={vt.get("status")} verdict={vt.get("verdict")} '
            f'malicious={vt.get("malicious")} livehunt={vt.get("livehunt_rule_id")}',
            f'   triage: {f.triage_url or "(set REPOTRIAGE_PUBLIC_URL)"}',
            '',
        ])
    if len(findings) > cfg.max_findings_email:
        lines.append(f'…and {len(findings) - cfg.max_findings_email} more (truncated).')
    msg.set_content('\n'.join(lines))
    return msg


def build_analysis_wu_alert_email(
    *,
    cfg: RepoHuntConfig,
    job_id: str | None,
    source_url: str,
    hits: list[dict[str, Any]],
    triage_url: str = '',
) -> EmailMessage:
    msg = EmailMessage()
    msg['Subject'] = (
        f'[RepoTriage Analyze] WU/MTCN LiveHunt hit(s): {len(hits)} '
        f'(DETECT_GTI_MaliciousFilesWithWUKeywords)'
    )
    msg['From'] = cfg.smtp_from
    msg['To'] = cfg.smtp_to
    lines = [
        'RepoTriage analysis alert — Western Union / MTCN malicious filename rule',
        f'LiveHunt rule: DETECT_GTI_MaliciousFilesWithWUKeywords '
        f'(id {cfg.vt_livehunt_wu_rule_id or "20744291635"})',
        f'Job: {job_id or "-"}',
        f'Source: {source_url}',
        f'Triage: {triage_url or cfg.triage_base_url or "-"}',
        '',
    ]
    for i, hit in enumerate(hits, 1):
        lines.extend([
            f'{i}. {hit.get("filename") or hit.get("path") or "-"}',
            f'   sha256: {hit.get("sha256")}',
            f'   matched: {",".join(hit.get("matched_keywords") or [])}',
            f'   vt: verdict={hit.get("vt_verdict")} malicious={hit.get("vt_malicious")} '
            f'label={hit.get("popular_threat_label") or "-"}',
            f'   families: {",".join(hit.get("family_labels") or []) or "-"}',
            f'   vt link: {hit.get("vt_link") or "-"}',
            '',
        ])
    msg.set_content('\n'.join(lines))
    return msg


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
        return {'ok': True, 'to': cfg.smtp_to, 'subject': msg['Subject']}
    except Exception as exc:
        return {'ok': False, 'error': f'{exc.__class__.__name__}: {exc}'}
