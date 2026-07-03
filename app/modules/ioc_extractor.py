from __future__ import annotations

import ipaddress
import math
import re
from pathlib import Path
from urllib.parse import urlparse

MAX_TEXT_BYTES = 2_000_000

URL_RE = re.compile(r"(?i)\b(?:https?|hxxps?|hxxp)://[^\s'\"<>\)\]\}]+")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]{2,64}@[A-Za-z0-9.\-]{3,253}\.[A-Za-z]{2,24}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|in|ru|cn|xyz|top|site|online|shop|info|biz|cc|me|pw|tk|ml|ga|cf|dev|app|cloud|live|work|space|click|link|monster|fun|pro|lol|icu|bond|cam|cyou|vip|club|today|website|store|host|download|zip|mov)\b", re.I)
DISCORD_WEBHOOK_RE = re.compile(r"https?://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[A-Za-z0-9_\-]+/[A-Za-z0-9_\-]+", re.I)
TELEGRAM_RE = re.compile(r"(?i)\b(?:https?://)?(?:t\.me|telegram\.me|telegram\.dog)/[A-Za-z0-9_+\-/]+")
BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
XMR_RE = re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

SKIP_EXT = {'.png','.jpg','.jpeg','.gif','.bmp','.ico','.webp','.mp3','.mp4','.avi','.mkv','.wav','.pdf'}

# Conservative TLD allow-list to reduce binary-string false positives. Extend as needed.
KNOWN_TLDS = {
    'com','net','org','io','co','in','ru','cn','xyz','top','site','online','shop','info','biz','cc','me','dev','app',
    'cloud','live','work','space','click','link','fun','pro','lol','icu','vip','club','today','website','store','host',
    'download','zip','mov','gov','edu','mil','us','uk','de','fr','nl','br','au','ca','jp','kr','sg','ua','pl','it','es',
    'se','no','fi','ch','at','be','dk','cz','sk','ro','tr','ir','id','my','th','vn','ph','hk','tw','mx','ar','za','ng'
}
SINKHOLE_COMMON = {'example.com','example.org','example.net','localhost'}


def _safe_text(path: str | Path) -> str:
    p = Path(path)
    if p.suffix.lower() in SKIP_EXT and p.stat().st_size > 200_000:
        return ""
    data = p.read_bytes()[:MAX_TEXT_BYTES]
    text = data.decode('utf-8', errors='ignore')
    if not text.strip():
        text = data.decode('latin-1', errors='ignore')
    return text.replace('hxxp://', 'http://').replace('hxxps://', 'https://').replace('[.]', '.')


def _valid_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return not (obj.is_private or obj.is_loopback or obj.is_multicast or obj.is_reserved or obj.is_unspecified)
    except Exception:
        return False


def _domain_from_url(url: str) -> str | None:
    try:
        host = urlparse(url).netloc.split('@')[-1].split(':')[0].lower().strip('.')
        return host or None
    except Exception:
        return None


def _uniq(items):
    seen = set(); out=[]
    for x in items:
        if not x: continue
        x = str(x).strip().strip('.,;:!?)"]}').strip("'")
        key = x.lower()
        if key and key not in seen:
            seen.add(key); out.append(x)
    return out


def _tld(domain: str) -> str:
    return domain.lower().rstrip('.').split('.')[-1]


def _valid_domain(domain: str, source: str = 'standalone') -> tuple[bool, str, str]:
    """Return (valid, confidence, reason)."""
    d = domain.lower().rstrip('.').strip()
    if not d or d in SINKHOLE_COMMON:
        return False, 'Rejected', 'sinkhole/example domain'
    if '..' in d or '_' in d or len(d) > 253:
        return False, 'Rejected', 'invalid domain syntax'
    parts = d.split('.')
    if len(parts) < 2:
        return False, 'Rejected', 'not a fqdn'
    tld = parts[-1]
    if tld not in KNOWN_TLDS:
        return False, 'Rejected', f'unknown/untrusted TLD .{tld}'
    # Binary false positives often look like R2.ML, 5.ME, t3.u.AA.
    sld = parts[-2]
    if source != 'url' and (len(sld) < 3 or sld.isdigit()):
        return False, 'Rejected', 'standalone short/noisy label likely binary artifact'
    if any(len(p) == 0 or len(p) > 63 or p.startswith('-') or p.endswith('-') for p in parts):
        return False, 'Rejected', 'invalid label'
    # Confidence scoring
    if source == 'url':
        return True, 'High', 'extracted from URL host'
    if tld in {'com','net','org','io','co','ru','cn','xyz','top','site','online','shop'}:
        return True, 'Medium', 'standalone plausible domain'
    return True, 'Low', 'standalone domain with less-common TLD'


def _valid_email(email: str) -> tuple[bool, str]:
    e = email.strip().lower().strip('.,;:!?)"]}')
    if '@' not in e:
        return False, 'missing @'
    local, domain = e.rsplit('@', 1)
    if len(local) < 3 or len(local) > 64:
        return False, 'local-part too short/noisy'
    if any(ord(c) < 32 or ord(c) > 126 for c in e):
        return False, 'non-printable character'
    ok, _, reason = _valid_domain(domain, source='email')
    if not ok:
        return False, f'invalid email domain: {reason}'
    # Heuristic: random binary often makes very short mixed-case/short-domain emails.
    if len(domain.split('.')[0]) < 3:
        return False, 'email domain label too short/noisy'
    return True, 'valid syntax and trusted TLD'


def _add_detail(details: dict, typ: str, value: str, source_file: str, confidence: str, reason: str):
    key = value.lower()
    bucket = details.setdefault(typ, {})
    if key not in bucket:
        bucket[key] = {'indicator': value, 'type': typ, 'confidence': confidence, 'reason': reason, 'sources': []}
    if source_file not in bucket[key]['sources']:
        bucket[key]['sources'].append(source_file)
    # Promote confidence if better source later.
    rank = {'Rejected':0, 'Low':1, 'Medium':2, 'High':3}
    if rank.get(confidence, 0) > rank.get(bucket[key].get('confidence'), 0):
        bucket[key]['confidence'] = confidence
        bucket[key]['reason'] = reason


def extract_iocs_from_file(path: str | Path) -> dict:
    p = Path(path)
    base = {'urls': [], 'domains': [], 'ips': [], 'emails': [], 'discord_webhooks': [], 'telegram': [], 'wallets': [], 'ioc_details': {}}
    if not p.is_file():
        return base
    text = _safe_text(p)
    if not text:
        return base

    details = {}

    urls = _uniq(URL_RE.findall(text))
    clean_urls = []
    url_domains = []
    for u in urls:
        clean_urls.append(u)
        _add_detail(details, 'urls', u, str(p.name), 'High', 'explicit URL pattern')
        host = _domain_from_url(u)
        if host:
            ok, conf, reason = _valid_domain(host, source='url')
            if ok:
                url_domains.append(host)
                _add_detail(details, 'domains', host, str(p.name), conf, reason)

    discord = _uniq(DISCORD_WEBHOOK_RE.findall(text))
    for w in discord:
        _add_detail(details, 'discord_webhooks', w, str(p.name), 'High', 'explicit Discord webhook pattern')

    telegram = _uniq(TELEGRAM_RE.findall(text))
    for t in telegram:
        _add_detail(details, 'telegram', t, str(p.name), 'Medium', 'Telegram URL/reference pattern')

    emails = []
    for e in _uniq(EMAIL_RE.findall(text)):
        ok, reason = _valid_email(e)
        if ok:
            emails.append(e)
            _add_detail(details, 'emails', e, str(p.name), 'Medium', reason)
        else:
            _add_detail(details, 'rejected_emails', e, str(p.name), 'Rejected', reason)

    ips = _uniq([x for x in IPV4_RE.findall(text) if _valid_ip(x)])
    for ip in ips:
        _add_detail(details, 'ips', ip, str(p.name), 'Medium', 'public IPv4 address')

    standalone_domains = []
    for d in DOMAIN_RE.findall(text):
        ok, conf, reason = _valid_domain(d, source='standalone')
        if ok:
            standalone_domains.append(d.lower())
            _add_detail(details, 'domains', d.lower(), str(p.name), conf, reason)
        else:
            _add_detail(details, 'rejected_domains', d, str(p.name), 'Rejected', reason)

    wallets = _uniq(BTC_RE.findall(text) + ETH_RE.findall(text) + XMR_RE.findall(text))
    for w in wallets:
        _add_detail(details, 'wallets', w, str(p.name), 'Medium', 'cryptocurrency wallet-like pattern')

    # Convert detail dict to lists for JSON/UI friendliness.
    detail_lists = {k: list(v.values()) for k, v in details.items()}
    return {
        'urls': clean_urls,
        'domains': _uniq(url_domains + standalone_domains),
        'ips': ips,
        'emails': emails,
        'discord_webhooks': discord,
        'telegram': telegram,
        'wallets': wallets,
        'ioc_details': detail_lists,
    }


def merge_iocs(per_file: list[dict]) -> dict:
    merged = {'urls': [], 'domains': [], 'ips': [], 'emails': [], 'discord_webhooks': [], 'telegram': [], 'wallets': []}
    merged_details = {}
    for item in per_file:
        iocs = item.get('iocs') or {}
        for k in merged:
            merged[k].extend(iocs.get(k, []))
        for typ, rows in (iocs.get('ioc_details') or {}).items():
            bucket = merged_details.setdefault(typ, {})
            for row in rows:
                key = str(row.get('indicator','')).lower()
                if not key:
                    continue
                if key not in bucket:
                    bucket[key] = {**row, 'sources': list(row.get('sources') or [])}
                else:
                    for src in row.get('sources') or []:
                        if src not in bucket[key]['sources']:
                            bucket[key]['sources'].append(src)
    out = {k: _uniq(v) for k, v in merged.items()}
    out['ioc_details'] = {k: list(v.values()) for k, v in merged_details.items()}
    return out


def classify_infrastructure(iocs: dict) -> dict:
    """Conservative local infra hints — high-confidence exfil/control only.

    Probable C2 / payload delivery buckets are filled from CTI feeds after exact
    IOC lookup (ThreatFox, URLHaus, Feodo, SSLBL), not URL keyword guessing.
    """
    discord = iocs.get('discord_webhooks', [])
    telegram = iocs.get('telegram', [])
    exfil = []
    control = []
    for w in discord:
        exfil.append({
            'indicator': w,
            'type': 'Discord Webhook Exfil Channel',
            'confidence': 'High',
            'source': 'IOC extraction',
        })
    for t in telegram:
        control.append({
            'indicator': t,
            'type': 'Telegram Channel/Bot Reference',
            'confidence': 'Medium',
            'source': 'IOC extraction',
        })
    return {
        'probable_c2': [],
        'control_channels': control,
        'exfil_channels': exfil,
        'config_sources': [],
        'payload_delivery': [],
        'malware_downloads': [],
        'known_bad_infrastructure': [],
    }
