from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover — non-Unix platforms
    fcntl = None  # type: ignore[assignment]


class RateLimitExceeded(Exception):
    def __init__(self, message: str, status: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.status = status or {}


def _bool_env(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


class UsageLimiter:
    """Small file-backed public usage limiter for MVP/public beta deployments.

    This protects expensive VT/AbuseCH lookups by rate-limiting analysis job creation.
    It intentionally limits only /api/jobs creation, not result polling or exports.
    For high traffic production, replace this with Redis/Postgres.
    """

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.usage_dir = base_dir / "data"
        self.usage_dir.mkdir(parents=True, exist_ok=True)
        self.usage_file = self.usage_dir / "usage_limits.json"
        self.enabled = _bool_env("PUBLIC_MODE", False) or _bool_env("RATE_LIMIT_ENABLED", False)
        self.free_daily_limit = _int_env("FREE_DAILY_ANALYSIS_LIMIT", _int_env("FREE_DAILY_LIMIT", 10))
        self.burst_limit = _int_env("BURST_ANALYSIS_LIMIT_PER_MINUTE", _int_env("BURST_LIMIT_PER_MINUTE", 5))
        self.max_running_per_ip = _int_env("MAX_RUNNING_JOBS_PER_IP", 2)
        self.max_url_length = _int_env("MAX_INPUT_URL_LENGTH", 2048)
        self.admin_bypass_token = os.getenv("ADMIN_BYPASS_TOKEN", "").strip()
        self.static_daily_limit = _int_env("STATIC_ANALYSIS_DAILY_LIMIT", 25)
        self.static_burst_limit = _int_env("STATIC_ANALYSIS_BURST_LIMIT", 5)

    def _today(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime())

    def _now(self) -> float:
        return time.time()

    def _load(self) -> dict[str, Any]:
        if not self.usage_file.exists():
            return {"ips": {}}
        try:
            return json.loads(self.usage_file.read_text(encoding="utf-8"))
        except Exception:
            return {"ips": {}}

    def _save(self, data: dict[str, Any]) -> None:
        tmp = self.usage_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.usage_file)

    @contextmanager
    def _locked_usage(self):
        """Serialize read-modify-write on the usage file (best-effort on local disk)."""
        self.usage_dir.mkdir(parents=True, exist_ok=True)
        if not self.usage_file.exists():
            self.usage_file.write_text(json.dumps({"ips": {}}, indent=2), encoding="utf-8")
        with self.usage_file.open("r+", encoding="utf-8") as handle:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                handle.seek(0)
                raw = handle.read()
                try:
                    data = json.loads(raw) if raw.strip() else {"ips": {}}
                except Exception:
                    data = {"ips": {}}
                yield data
                handle.seek(0)
                handle.truncate()
                handle.write(json.dumps(data, indent=2, ensure_ascii=False))
                handle.flush()
            finally:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def get_status(self, ip: str, active_jobs: int = 0, is_admin: bool = False) -> dict[str, Any]:
        data = self._load()
        rec = (data.get("ips") or {}).get(ip, {})
        today = self._today()
        daily = rec.get("daily", {})
        used_today = int(daily.get(today, 0))
        remaining = None if (not self.enabled or is_admin) else max(0, self.free_daily_limit - used_today)
        recent = [t for t in rec.get("recent", []) if self._now() - float(t) <= 60]
        return {
            "enabled": self.enabled,
            "ip": ip,
            "used_today": used_today,
            "free_daily_limit": self.free_daily_limit,
            "remaining_today": remaining,
            "burst_limit_per_minute": self.burst_limit,
            "burst_used": len(recent),
            "max_running_jobs_per_ip": self.max_running_per_ip,
            "active_jobs_for_ip": active_jobs,
            "admin_bypass": bool(is_admin),
        }

    def check_and_consume(self, ip: str, file_url: str, active_jobs: int = 0, admin_token: str | None = None) -> dict[str, Any]:
        is_admin = bool(self.admin_bypass_token and admin_token and admin_token == self.admin_bypass_token)
        if len(file_url or "") > self.max_url_length:
            raise RateLimitExceeded("Submitted URL is too long.", self.get_status(ip, active_jobs, is_admin))

        if not self.enabled or is_admin:
            return self.get_status(ip, active_jobs, is_admin)

        now = self._now()
        today = self._today()

        with self._locked_usage() as data:
            ips = data.setdefault("ips", {})
            rec = ips.setdefault(ip, {"daily": {}, "recent": []})
            rec["recent"] = [float(t) for t in rec.get("recent", []) if now - float(t) <= 60]
            used_today = int(rec.setdefault("daily", {}).get(today, 0))

            if active_jobs >= self.max_running_per_ip:
                raise RateLimitExceeded(
                    f"Too many analyses are already running for this IP. Limit: {self.max_running_per_ip}.",
                    self.get_status(ip, active_jobs, is_admin),
                )

            if len(rec["recent"]) >= self.burst_limit:
                raise RateLimitExceeded(
                    f"Burst limit reached. Try again in about a minute. Limit: {self.burst_limit}/minute.",
                    self.get_status(ip, active_jobs, is_admin),
                )

            if used_today >= self.free_daily_limit:
                raise RateLimitExceeded(
                    f"Daily free analysis limit reached. Limit: {self.free_daily_limit}/day.",
                    self.get_status(ip, active_jobs, is_admin),
                )

            rec["recent"].append(now)
            rec["daily"][today] = used_today + 1
            rec["last_seen"] = now

        return self.get_status(ip, active_jobs, is_admin)

    def check_static_analysis(self, ip: str, admin_token: str | None = None) -> dict[str, Any]:
        is_admin = bool(self.admin_bypass_token and admin_token and admin_token == self.admin_bypass_token)
        if not self.enabled or is_admin:
            return {'enabled': self.enabled, 'admin_bypass': is_admin}

        now = self._now()
        today = self._today()
        with self._locked_usage() as data:
            ips = data.setdefault("ips", {})
            rec = ips.setdefault(ip, {"daily": {}, "recent": [], "static_daily": {}, "static_recent": []})
            rec["static_recent"] = [float(t) for t in rec.get("static_recent", []) if now - float(t) <= 60]
            used_today = int(rec.setdefault("static_daily", {}).get(today, 0))

            if len(rec["static_recent"]) >= self.static_burst_limit:
                raise RateLimitExceeded(
                    f"Static analysis burst limit reached. Limit: {self.static_burst_limit}/minute.",
                    self.get_status(ip, 0, is_admin),
                )
            if used_today >= self.static_daily_limit:
                raise RateLimitExceeded(
                    f"Daily static analysis limit reached. Limit: {self.static_daily_limit}/day.",
                    self.get_status(ip, 0, is_admin),
                )
            rec["static_recent"].append(now)
            rec["static_daily"][today] = used_today + 1
        return {'enabled': True, 'used_today': used_today + 1, 'daily_limit': self.static_daily_limit}
