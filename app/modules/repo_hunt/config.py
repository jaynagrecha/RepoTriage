from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in {'1', 'true', 'yes', 'on'}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


def _csv(name: str) -> list[str]:
    raw = (os.getenv(name) or '').strip()
    if not raw:
        return []
    return [x.strip() for x in raw.split(',') if x.strip()]


@dataclass(frozen=True, slots=True)
class RepoHuntConfig:
    enabled: bool
    min_bytes: int
    max_bytes: int
    github_token: str
    github_orgs: list[str]
    github_users: list[str]
    search_query: str
    search_max_results: int
    vt_confirm: bool
    vt_api_key: str
    vt_livehunt_rule_id: str
    webhook_secret: str
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_from: str
    smtp_to: str
    smtp_use_tls: bool
    triage_base_url: str
    max_candidates: int
    max_findings_email: int

    @classmethod
    def from_env(cls) -> 'RepoHuntConfig':
        default_query = (
            '"var _0x" "eval(function(_0x" extension:js '
            'size:>512000 size:<1048576'
        )
        return cls(
            enabled=_bool('REPO_HUNT_ENABLED', False),
            min_bytes=_int('REPO_HUNT_MIN_BYTES', 500 * 1024),
            max_bytes=_int('REPO_HUNT_MAX_BYTES', 1024 * 1024),
            github_token=(os.getenv('GITHUB_TOKEN') or os.getenv('GH_TOKEN') or '').strip(),
            github_orgs=_csv('REPO_HUNT_GITHUB_ORGS'),
            github_users=_csv('REPO_HUNT_GITHUB_USERS'),
            search_query=(os.getenv('REPO_HUNT_SEARCH_QUERY') or default_query).strip(),
            search_max_results=_int('REPO_HUNT_SEARCH_MAX_RESULTS', 30),
            vt_confirm=_bool('REPO_HUNT_VT_CONFIRM', True),
            vt_api_key=(os.getenv('VT_API_KEY') or '').strip(),
            vt_livehunt_rule_id=(os.getenv('VT_LIVEHUNT_RULE_ID') or '').strip(),
            webhook_secret=(os.getenv('REPO_HUNT_WEBHOOK_SECRET') or '').strip(),
            smtp_host=(os.getenv('SMTP_HOST') or '').strip(),
            smtp_port=_int('SMTP_PORT', 587),
            smtp_user=(os.getenv('SMTP_USER') or '').strip(),
            smtp_password=(os.getenv('SMTP_PASSWORD') or '').strip(),
            smtp_from=(os.getenv('SMTP_FROM') or os.getenv('SMTP_USER') or '').strip(),
            smtp_to=(os.getenv('REPO_HUNT_TO_EMAIL') or os.getenv('SMTP_TO') or '').strip(),
            smtp_use_tls=_bool('SMTP_USE_TLS', True),
            triage_base_url=(os.getenv('REPOTRIAGE_PUBLIC_URL') or os.getenv('REPO_HUNT_TRIAGE_BASE_URL') or '').strip().rstrip('/'),
            max_candidates=_int('REPO_HUNT_MAX_CANDIDATES', 40),
            max_findings_email=_int('REPO_HUNT_MAX_FINDINGS_EMAIL', 25),
        )

    def smtp_ready(self) -> bool:
        return bool(self.smtp_host and self.smtp_to and self.smtp_from)
