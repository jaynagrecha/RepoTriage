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


_DEFAULT_WU_REPO_QUERIES = (
    'mtcn in:name',
    'westernunion in:name',
    'wupos in:name',
    'pagofacil in:name',
)

_DEFAULT_WU_CODE_QUERIES = (
    'filename:mtcn',
    'filename:westernunion',
    'filename:wupos',
    'filename:pagofacil',
)


@dataclass(frozen=True, slots=True)
class RepoHuntConfig:
    enabled: bool
    min_bytes: int
    max_bytes: int
    github_token: str
    github_orgs: list[str]
    github_users: list[str]
    search_query: str
    extra_search_queries: list[str]
    search_max_results: int
    wu_hunt_enabled: bool
    wu_repo_search_queries: list[str]
    vt_confirm: bool
    vt_api_key: str
    vt_livehunt_rule_id: str
    vt_livehunt_wu_rule_id: str
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
    analysis_alert_email: bool

    @classmethod
    def from_env(cls) -> 'RepoHuntConfig':
        default_query = (
            '"var _0x" "eval(function(_0x" extension:js '
            'size:>512000 size:<1048576'
        )
        wu_enabled = _bool('REPO_HUNT_WU_ENABLED', True)
        extra = _csv('REPO_HUNT_EXTRA_SEARCH_QUERIES')
        if wu_enabled and not extra:
            extra = list(_DEFAULT_WU_CODE_QUERIES)
        wu_repo_q = _csv('REPO_HUNT_WU_REPO_QUERIES') or list(_DEFAULT_WU_REPO_QUERIES)
        return cls(
            enabled=_bool('REPO_HUNT_ENABLED', False),
            min_bytes=_int('REPO_HUNT_MIN_BYTES', 500 * 1024),
            max_bytes=_int('REPO_HUNT_MAX_BYTES', 1024 * 1024),
            github_token=(os.getenv('GITHUB_TOKEN') or os.getenv('GH_TOKEN') or '').strip(),
            github_orgs=_csv('REPO_HUNT_GITHUB_ORGS'),
            github_users=_csv('REPO_HUNT_GITHUB_USERS'),
            search_query=(os.getenv('REPO_HUNT_SEARCH_QUERY') or default_query).strip(),
            extra_search_queries=extra,
            search_max_results=_int('REPO_HUNT_SEARCH_MAX_RESULTS', 30),
            wu_hunt_enabled=wu_enabled,
            wu_repo_search_queries=wu_repo_q,
            vt_confirm=_bool('REPO_HUNT_VT_CONFIRM', True),
            vt_api_key=(os.getenv('VT_API_KEY') or '').strip(),
            vt_livehunt_rule_id=(os.getenv('VT_LIVEHUNT_RULE_ID') or '').strip(),
            vt_livehunt_wu_rule_id=(
                os.getenv('VT_LIVEHUNT_WU_RULE_ID') or '20744291635'
            ).strip(),
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
            analysis_alert_email=_bool('ANALYSIS_ALERT_EMAIL', True),
        )

    def smtp_ready(self) -> bool:
        return bool(self.smtp_host and self.smtp_to and self.smtp_from)
