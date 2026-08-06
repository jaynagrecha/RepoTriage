from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

from ..config import RepoHuntConfig
from ..types import Finding


def build_findings_email(findings: list[Finding], cfg: RepoHuntConfig, *, run_meta: dict[str, Any]) -> EmailMessage:
    msg = EmailMessage()
    msg['Subject'] = f"[RepoTriage Hunt] {len(findings)} JsOutProx-like hit(s)"
    msg['From'] = cfg.smtp_from
    msg['To'] = cfg.smtp_to

    lines = [
        'RepoTriage automated repository hunt',
        f"Findings: {len(findings)}",
        f"Sources scanned: {run_meta.get('sources')}",
        f"Candidates checked: {run_meta.get('candidates')}",
        f"Local matches: {run_meta.get('local_matches')}",
        '',
    ]
    for i, f in enumerate(findings[: cfg.max_findings_email], 1):
        c = f.candidate
        vt = f.detection.vt_confirm or {}
        lines.extend([
            f'{i}. {c.repo or "-"} :: {c.path or c.url}',
            f'   source: {c.source}',
            f'   url: {c.html_url or c.url}',
            f'   sha256: {f.sha256}',
            f'   size: {f.detection.filesize} bytes',
            f'   rule: {f.detection.rule} strings={",".join(f.detection.matched_strings)}',
            f'   vt: status={vt.get("status")} verdict={vt.get("verdict")} livehunt={vt.get("livehunt_rule_id")}',
            f'   triage: {f.triage_url or "(set REPOTRIAGE_PUBLIC_URL)"}',
            '',
        ])
    if len(findings) > cfg.max_findings_email:
        lines.append(f'…and {len(findings) - cfg.max_findings_email} more (truncated).')
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
