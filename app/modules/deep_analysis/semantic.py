from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CAPABILITY_DEFS: dict[str, str] = {
    'cli_interface': 'Command-line interface (argparse/getopt/sys.argv)',
    'library_module': 'Importable module with callable functions',
    'network_http': 'HTTP client or URL fetch primitives',
    'subprocess_exec': 'Spawns subprocesses or shell commands',
    'dynamic_exec': 'Dynamic code execution (eval/exec/Invoke-Expression)',
    'file_write': 'Writes data to files on disk',
    'file_read': 'Reads files from disk',
    'shellcode_literals': 'Hex-encoded shellcode byte literals (\\x…)',
    'shellcode_transform': 'Encrypt/decrypt/encode shellcode buffers',
    'crypto_xor': 'XOR-based encoding or decoding',
    'crypto_base64': 'Base64 encode/decode',
    'crypto_generic': 'Other encoding or encryption routines',
    'metasploit_framework': 'Metasploit Framework module markers',
    'privesc_enumeration': 'Privilege-escalation enumeration logic',
    'download_remote': 'Downloads remote payloads or stages',
    'persistence': 'Persistence via registry/cron/startup',
    'credential_access': 'Credential or secret harvesting patterns',
    'webhook_exfil': 'Webhook or bot exfiltration channels',
    'sms_abuse_api': 'SMS/OTP registration or reset API calls',
    'phone_fields': 'Phone number input fields',
    'threading_parallel': 'Parallel HTTP or worker threads',
    'pe_injection': 'PE process injection imports',
    'pe_packing': 'Packer or protector indicators',
    'anti_analysis': 'Anti-debug or anti-VM checks',
}


@dataclass
class CapabilityHit:
    id: str
    confidence: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class PurposeRule:
    rule_id: str
    behavior_class: str
    behavior_title: str
    threat_category: str
    requires: frozenset[str]
    any_of: frozenset[str]
    forbids: frozenset[str]
    summary_template: str
    primary_effect: str
    recommended_action: str


PURPOSE_RULES: list[PurposeRule] = [
    PurposeRule(
        rule_id='shellcode_encoder_utility',
        behavior_class='shellcode_tool',
        behavior_title='Shellcode encode/decode utility',
        threat_category='dual_use_security_tool',
        requires=frozenset({'shellcode_transform', 'crypto_xor'}),
        any_of=frozenset({'cli_interface', 'library_module'}),
        forbids=frozenset({'network_http', 'subprocess_exec', 'download_remote', 'dynamic_exec'}),
        summary_template=(
            'This is a {language} {entry_label} that XOR-encodes or decodes hex shellcode buffers. '
            'It transforms user-supplied shellcode locally and prints results — no network, subprocess, '
            'or payload execution primitives were found in source. Dual-use offensive-security utility.'
        ),
        primary_effect='Transform shellcode bytes with XOR locally (encode/decode) — offline utility, not a dropper.',
        recommended_action=(
            'Treat as dual-use shellcode tooling. Safe to study in an isolated lab; investigate delivery '
            'context if found outside authorized security work.'
        ),
    ),
    PurposeRule(
        rule_id='linux_privesc_enumerator',
        behavior_class='linux_privesc_enum',
        behavior_title='Linux privilege-escalation enumerator',
        threat_category='dual_use_security_tool',
        requires=frozenset({'privesc_enumeration'}),
        any_of=frozenset({'library_module', 'cli_interface'}),
        forbids=frozenset({'sms_abuse_api'}),
        summary_template=(
            'This behaves like a Linux privilege-escalation enumeration script. It searches for '
            'misconfigurations, SUID/sudo paths, cron/capability issues, and embeds pentest reference material. '
            'Dual-use: legitimate in scoped pentests; hostile if run without authorization.'
        ),
        primary_effect='Enumerate the local Linux host for privilege-escalation paths.',
        recommended_action=(
            'Treat as offensive-security enumeration. Authorized pentest use only — investigate if unmanaged on production.'
        ),
    ),
    PurposeRule(
        rule_id='metasploit_module',
        behavior_class='metasploit_module',
        behavior_title='Metasploit Framework module',
        threat_category='dual_use_security_tool',
        requires=frozenset({'metasploit_framework'}),
        any_of=frozenset({'library_module', 'cli_interface'}),
        forbids=frozenset(),
        summary_template=(
            'This is Metasploit Framework module source, intended to run inside msfconsole — not a standalone implant. '
            '{role_line}Dual-use exploit-framework component from Rapid7 upstream patterns.'
        ),
        primary_effect='Extend Metasploit Framework with module capability — runs inside msfconsole.',
        recommended_action=(
            'Treat as exploit-framework module source. Lab or authorized engagement only; correlate delivery path on production.'
        ),
    ),
    PurposeRule(
        rule_id='sms_otp_abuse',
        behavior_class='sms_otp_abuse',
        behavior_title='SMS / OTP abuse tool',
        threat_category='abuse_tool',
        requires=frozenset({'sms_abuse_api', 'phone_fields'}),
        any_of=frozenset({'network_http'}),
        forbids=frozenset(),
        summary_template=(
            'This automates HTTP requests to third-party registration or password-reset APIs using phone-number fields — '
            'consistent with SMS/OTP abuse tooling rather than traditional C2 malware.'
        ),
        primary_effect='Trigger SMS/OTP messages via third-party service APIs.',
        recommended_action='Do not run against phone numbers you do not own. Block if deployed for harassment.',
    ),
    PurposeRule(
        rule_id='script_dropper',
        behavior_class='script_dropper',
        behavior_title='Script-based dropper / downloader',
        threat_category='malware',
        requires=frozenset({'download_remote'}),
        any_of=frozenset({'dynamic_exec', 'subprocess_exec'}),
        forbids=frozenset(),
        summary_template=(
            'This script downloads remote content and contains execution primitives — staged dropper/downloader behavior.'
        ),
        primary_effect='Download external content and execute or invoke follow-on payload.',
        recommended_action='Do not execute on production. Quarantine and investigate delivery path.',
    ),
    PurposeRule(
        rule_id='credential_exfil',
        behavior_class='credential_stealer',
        behavior_title='Credential / data theft',
        threat_category='malware',
        requires=frozenset({'webhook_exfil'}),
        any_of=frozenset({'credential_access', 'network_http'}),
        forbids=frozenset(),
        summary_template='Behavior suggests data exfiltration via messaging/webhook channels.',
        primary_effect='Exfiltrate data via webhook or bot endpoints.',
        recommended_action='Do not execute. Quarantine and investigate exposure.',
    ),
]


def _cap_ids(hits: list[CapabilityHit]) -> set[str]:
    return {h.id for h in hits}


def _score_rule(rule: PurposeRule, caps: set[str]) -> tuple[int, list[str]]:
    reasons: list[str] = []
    if not rule.requires.issubset(caps):
        missing = rule.requires - caps
        return 0, [f'missing required: {", ".join(sorted(missing))}']
    score = len(rule.requires) * 10
    reasons.append(f'matched required: {", ".join(sorted(rule.requires))}')
    if rule.any_of:
        matched_any = rule.any_of & caps
        if not matched_any:
            return 0, ['no optional capability matched']
        score += len(matched_any) * 4
        reasons.append(f'matched optional: {", ".join(sorted(matched_any))}')
    forbidden = rule.forbids & caps
    if forbidden:
        return 0, [f'forbidden capability present: {", ".join(sorted(forbidden))}']
    return score, reasons


def _entry_label(entry_point: str) -> str:
    return {
        'cli': 'command-line tool',
        'library': 'library module',
        'script': 'script',
        'binary': 'compiled binary',
    }.get(entry_point, 'program')


def _extract_cli_description(text: str) -> str | None:
    m = re.search(r'ArgumentParser\s*\(\s*description\s*=\s*["\']([^"\']+)["\']', text, re.I)
    if m:
        return m.group(1).strip()[:200]
    m = re.search(r'add_argument\s*\([^)]*help\s*=\s*["\']([^"\']+)["\']', text, re.I)
    if m:
        return m.group(1).strip()[:200]
    return None


def _compose_generic_summary(
    *,
    language: str,
    entry_point: str,
    caps: list[CapabilityHit],
    functions: list[dict[str, Any]],
    data_flow: str | None,
    cli_description: str | None = None,
) -> tuple[str, str, list[str]]:
    cap_labels = [CAPABILITY_DEFS.get(c.id, c.id) for c in caps[:8]]
    fn_names = [f['name'] for f in functions[:6] if f.get('name')]
    bullets: list[str] = []
    if cap_labels:
        bullets.append(f'Detected capabilities: {"; ".join(cap_labels)}.')
    if fn_names:
        bullets.append(f'Key functions: {", ".join(fn_names)}.')
    if data_flow:
        bullets.append(f'Data flow: {data_flow}')

    absent: list[str] = []
    present = _cap_ids(caps)
    for cap_id, label in (
        ('network_http', 'network HTTP client'),
        ('subprocess_exec', 'subprocess/shell execution'),
        ('download_remote', 'remote download/staging'),
        ('dynamic_exec', 'dynamic eval/exec'),
    ):
        if cap_id not in present:
            absent.append(label)
    if absent:
        bullets.append(f'Not observed in source: {", ".join(absent)}.')

    purpose_hint = ''
    if cli_description:
        purpose_hint = f' Stated purpose: "{cli_description}".'

    primary_cap = cap_labels[0].split('(')[0].strip().lower() if cap_labels else 'utility script'
    summary = (
        f'This {language} {_entry_label(entry_point)} was analyzed from source (AST + capability scan). '
        f'Primary behavior: {primary_cap}.{purpose_hint} '
        + (f'Processing path: {data_flow}.' if data_flow else '')
        + (f' No {"; ".join(absent)} detected.' if absent else '')
    ).strip()

    title_parts = [language.title(), _entry_label(entry_point)]
    if cli_description:
        title_parts.append(cli_description[:60])
    elif cap_labels:
        title_parts.append(cap_labels[0].split('(')[0].strip())
    return ' — '.join(title_parts[:3]), summary, bullets


class _PythonCapabilityVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.imports: set[str] = set()
        self.calls: list[str] = []
        self.functions: list[dict[str, Any]] = []
        self.has_main_guard = False
        self.argparse = False
        self.current_class: str | None = None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.add(alias.name.split('.')[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.imports.add(node.module.split('.')[0])

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        prev = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = prev

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        doc = ast.get_docstring(node) or ''
        self.functions.append({
            'name': node.name,
            'class': self.current_class,
            'args': [a.arg for a in node.args.args[:8]],
            'doc': doc[:200],
        })
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)  # type: ignore[arg-type]

    def visit_Call(self, node: ast.Call) -> None:
        name = self._call_name(node.func)
        if name:
            self.calls.append(name)
            if name.endswith('ArgumentParser') or name == 'ArgumentParser':
                self.argparse = True
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        test = ast.unparse(node.test) if hasattr(ast, 'unparse') else ''
        if '__name__' in test and '__main__' in test:
            self.has_main_guard = True
        self.generic_visit(node)

    @staticmethod
    def _call_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = _PythonCapabilityVisitor._call_name(node.value)
            return f'{base}.{node.attr}' if base else node.attr
        return None


def _analyze_python_ast(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        'parsed': False,
        'imports': [],
        'functions': [],
        'calls': [],
        'entry_point': 'script',
        'argparse': False,
        'parse_error': None,
    }
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        out['parse_error'] = str(exc)[:120]
        return out

    visitor = _PythonCapabilityVisitor()
    visitor.visit(tree)
    out['parsed'] = True
    out['imports'] = sorted(visitor.imports)
    out['functions'] = visitor.functions[:40]
    out['calls'] = visitor.calls[:80]
    out['argparse'] = visitor.argparse
    if visitor.argparse or 'argparse' in visitor.imports:
        out['entry_point'] = 'cli'
    elif visitor.functions and not visitor.has_main_guard:
        out['entry_point'] = 'library'
    elif visitor.has_main_guard:
        out['entry_point'] = 'cli' if visitor.argparse else 'script'
    return out


def _text_capability_scan(text: str, *, filename: str = '') -> list[CapabilityHit]:
    hits: dict[str, CapabilityHit] = {}
    lower = text.lower()
    name_lower = filename.lower()

    def add(cap_id: str, evidence: str, confidence: str = 'high') -> None:
        if cap_id not in hits:
            hits[cap_id] = CapabilityHit(cap_id, confidence, [])
        if evidence not in hits[cap_id].evidence:
            hits[cap_id].evidence.append(evidence[:160])

    if re.search(r'argparse|ArgumentParser|getopt|sys\.argv', text):
        add('cli_interface', 'CLI parser or argv usage')
    if re.search(r'^\s*def\s+\w+\(', text, re.M) and 'if __name__' not in text:
        add('library_module', 'Defines functions without exclusive main guard')

    if re.search(r'requests\.(get|post|put|patch|delete)|urllib\.|http\.client|aiohttp|httpx', text, re.I):
        add('network_http', 'HTTP client library usage')
    if re.search(r'subprocess\.|os\.system|os\.popen|Popen\s*\(', text):
        add('subprocess_exec', 'Subprocess or shell spawn')
    if re.search(r'\beval\s*\(|\bexec\s*\(|invoke-expression|\biex\b', text, re.I):
        add('dynamic_exec', 'Dynamic evaluation primitive')
    if re.search(r'open\s*\([^)]*[\'"][wa]', text):
        add('file_write', 'File write via open()')
    if re.search(r'open\s*\([^)]*[\'"]r', text):
        add('file_read', 'File read via open()')

    if re.search(r'\\x[0-9a-fA-F]{2}', text) or re.search(r'shellcode', lower):
        add('shellcode_literals', 'Hex shellcode literals or shellcode identifiers')
    if re.search(r'encrypt.*shellcode|decrypt.*shellcode|shellcode.*encrypt|shellcode.*decrypt', lower):
        add('shellcode_transform', 'Shellcode encrypt/decrypt routines')
    elif re.search(r'EncryptShellcode|DecryptShellcode|encode.*shellcode|decode.*shellcode', text):
        add('shellcode_transform', 'Named shellcode transform functions')

    if re.search(r'\^|\bxor\b', lower) or ' ^ ' in text:
        add('crypto_xor', 'XOR operations')
    if re.search(r'base64|b64encode|b64decode|frombase64', lower):
        add('crypto_base64', 'Base64 encode/decode')
    if re.search(r'encrypt|decrypt|cipher|aes|rc4', lower) and 'crypto_xor' not in hits:
        add('crypto_generic', 'Encryption or encoding routines')

    if re.search(r'metasploit|meterpreter|Msf::|MetasploitModule|rapid7/metasploit-framework', text, re.I):
        add('metasploit_framework', 'Metasploit Framework markers')
    if re.search(r'linpeas|privilege.?escalation|gtfobins|/etc/shadow|suid|sudoers', text, re.I):
        add('privesc_enumeration', 'Privilege-escalation enumeration patterns')

    if re.search(r'downloadstring|downloadfile|invoke-webrequest|curl\s|wget\s|bitsadmin', text, re.I):
        add('download_remote', 'Remote download primitive')
    if re.search(r'CurrentVersion\\Run|schtasks|crontab|/etc/cron', text, re.I):
        add('persistence', 'Persistence mechanism reference')
    if re.search(r'mimikatz|lsass|sekurlsa|\.env|id_rsa|password|credential', text, re.I):
        add('credential_access', 'Credential or secret access pattern')
    if re.search(r'discord(?:app)?\.com/api/webhooks|api\.telegram\.org', text, re.I):
        add('webhook_exfil', 'Webhook/bot exfil endpoint')

    if re.search(r'auth/sms|/sms/send|profiles/register|sign_up|password.?reset', lower):
        add('sms_abuse_api', 'SMS/OTP API-style URL or path')
    if re.search(r'phone_number|phoneNumber|msisdn', text):
        add('phone_fields', 'Phone number variable fields')
    if re.search(r'threading|ThreadPool|multiprocessing|asyncio\.gather', text):
        add('threading_parallel', 'Parallel worker/thread usage')

    if 'bf_xor' in name_lower or ('xor' in name_lower and 'bf' in name_lower):
        add('metasploit_framework', 'Filename consistent with Metasploit auxiliary module', 'medium')

    return list(hits.values())


def _infer_data_flow(functions: list[dict[str, Any]], caps: set[str], text: str) -> str | None:
    names = ' '.join(f['name'].lower() for f in functions)
    if 'shellcode_transform' in caps and 'crypto_xor' in caps:
        if 'encrypt' in names and 'decrypt' in names:
            return 'User shellcode + key → XOR encrypt/decrypt → hex \\x output (stdout)'
        return 'Shellcode bytes → XOR transform → encoded output'
    if 'download_remote' in caps and ('dynamic_exec' in caps or 'subprocess_exec' in caps):
        return 'Remote URL → download → execute/invoke'
    if 'network_http' in caps and 'phone_fields' in caps:
        return 'Phone number input → HTTP API requests → external services'
    if re.search(r'Encrypting\s*&\s*Decrypting\s*Shellcode', text, re.I):
        return 'CLI args (shellcode, key) → XOR transform → printed encoded/decoded shellcode'
    return None


def _infer_language(filename: str, text: str, static: dict[str, Any] | None) -> str:
    typed = ((static or {}).get('typed_analysis') or {})
    if typed.get('language'):
        return str(typed['language'])
    ext = Path(filename or '').suffix.lower()
    mapping = {
        '.py': 'python', '.rb': 'ruby', '.ps1': 'powershell', '.js': 'javascript',
        '.sh': 'shell', '.bash': 'shell', '.pl': 'perl', '.lua': 'lua',
    }
    if ext in mapping:
        return mapping[ext]
    if text.startswith('#!'):
        shebang = text.splitlines()[0].lower()
        if 'python' in shebang:
            return 'python'
        if 'bash' in shebang or 'sh' in shebang:
            return 'shell'
    return 'script'


def _pe_capabilities(pe: dict[str, Any]) -> list[CapabilityHit]:
    hits: list[CapabilityHit] = []
    for imp in pe.get('high_risk_imports') or []:
        cat = imp.get('category') or ''
        if cat == 'process_injection':
            hits.append(CapabilityHit('pe_injection', 'high', [imp.get('import', '')]))
        elif cat == 'anti_analysis':
            hits.append(CapabilityHit('anti_analysis', 'high', [imp.get('import', '')]))
    if pe.get('packer_hints'):
        hits.append(CapabilityHit('pe_packing', 'medium', list(pe.get('packer_hints') or [])[:3]))
    for url in (pe.get('embedded_urls') or [])[:5]:
        hits.append(CapabilityHit('network_http', 'medium', [f'embedded URL: {url}']))
    return hits


def analyze_semantic(
    path: Path | None,
    *,
    filename: str | None = None,
    sample_text: str | None = None,
    static: dict[str, Any] | None = None,
    family_hints: dict[str, Any] | None = None,
    script_deep: dict[str, Any] | None = None,
    pe_deep: dict[str, Any] | None = None,
) -> dict[str, Any]:
    text = sample_text or ''
    if not text and path is not None:
        text = path.read_bytes()[:2_000_000].decode('utf-8', errors='ignore')

    fname = filename or (path.name if path else 'file')
    language = _infer_language(fname, text, static)
    ast_info: dict[str, Any] = {}
    if language == 'python' and text.strip():
        ast_info = _analyze_python_ast(text)

    capabilities = _text_capability_scan(text, filename=fname)
    cap_map = {c.id: c for c in capabilities}

    if ast_info.get('parsed'):
        if ast_info.get('argparse'):
            if 'cli_interface' not in cap_map:
                capabilities.append(CapabilityHit('cli_interface', 'high', ['argparse AST']))
        for mod in ast_info.get('imports') or []:
            if mod in {'requests', 'urllib', 'httpx', 'aiohttp', 'http'}:
                if 'network_http' not in cap_map:
                    capabilities.append(CapabilityHit('network_http', 'high', [f'import {mod}']))
            if mod == 'subprocess':
                if 'subprocess_exec' not in cap_map:
                    capabilities.append(CapabilityHit('subprocess_exec', 'high', ['import subprocess']))
        cap_map = {c.id: c for c in capabilities}

    if family_hints:
        for match in family_hints.get('family_matches') or []:
            fam = match.get('family')
            if fam == 'metasploit' and 'metasploit_framework' not in cap_map:
                capabilities.append(CapabilityHit(
                    'metasploit_framework', 'high',
                    [f"family parser: {match.get('hits', 0)} hit(s)"],
                ))

    for hit in _pe_capabilities(pe_deep or {}):
        if hit.id not in cap_map:
            capabilities.append(hit)
            cap_map[hit.id] = hit

    caps = _cap_ids(capabilities)
    entry_point = ast_info.get('entry_point') or ('binary' if (pe_deep or {}).get('high_risk_imports') else 'script')

    best_rule: PurposeRule | None = None
    best_score = 0
    best_reasons: list[str] = []
    for rule in PURPOSE_RULES:
        score, reasons = _score_rule(rule, caps)
        if score > best_score:
            best_score = score
            best_rule = rule
            best_reasons = reasons

    functions = ast_info.get('functions') or []
    data_flow = _infer_data_flow(functions, caps, text)
    role_line = ''
    if best_rule and best_rule.rule_id == 'metasploit_module':
        if re.search(r'bf[_-]?xor|brute.?force.*xor', fname + text[:1500], re.I):
            role_line = 'Inferred role: brute-force XOR / decode auxiliary. '

    inference_method = 'capability_rules'
    if best_rule and best_score >= 18:
        behavior_class = best_rule.behavior_class
        behavior_title = best_rule.behavior_title
        threat_category = best_rule.threat_category
        summary = best_rule.summary_template.format(
            language=language,
            entry_label=_entry_label(str(entry_point)),
            role_line=role_line,
        )
        what_it_does = best_reasons + [best_rule.primary_effect]
        if data_flow:
            what_it_does.append(f'Data flow: {data_flow}')
        recommended = best_rule.recommended_action
        confidence = 'high' if best_score >= 28 else 'medium'
        confidence_score = min(100, best_score * 3)
        purpose_rule_id = best_rule.rule_id
    else:
        inference_method = 'capability_compose'
        behavior_title, summary, bullets = _compose_generic_summary(
            language=language,
            entry_point=str(entry_point),
            caps=capabilities,
            functions=functions,
            data_flow=data_flow,
            cli_description=_extract_cli_description(text),
        )
        behavior_class = 'semantic_analysis'
        threat_category = 'unknown'
        if caps & {'subprocess_exec', 'dynamic_exec', 'download_remote', 'pe_injection'}:
            threat_category = 'malware'
        elif caps & {'metasploit_framework', 'privesc_enumeration', 'shellcode_transform', 'crypto_xor'}:
            threat_category = 'dual_use_security_tool'
        what_it_does = bullets
        recommended = (
            'Review structured capabilities below. Run in an isolated VM if dynamic validation is required.'
        )
        purpose_rule_id = None
        confidence_score = min(100, len(capabilities) * 8 + (20 if ast_info.get('parsed') else 0))
        confidence = 'high' if confidence_score >= 56 else ('medium' if confidence_score >= 32 else 'low')

    return {
        'engine': 'repotriage_semantic_v1',
        'language': language,
        'entry_point': entry_point,
        'ast_parsed': bool(ast_info.get('parsed')),
        'capabilities': [
            {
                'id': c.id,
                'label': CAPABILITY_DEFS.get(c.id, c.id),
                'confidence': c.confidence,
                'evidence': c.evidence[:4],
            }
            for c in capabilities
        ],
        'functions': functions[:12],
        'data_flow': data_flow,
        'purpose_rule_id': purpose_rule_id,
        'behavior_class': behavior_class,
        'behavior_title': behavior_title,
        'summary': summary,
        'what_it_does': what_it_does,
        'threat_category': threat_category,
        'confidence': confidence,
        'confidence_score': confidence_score,
        'recommended_action': recommended,
        'inference_method': inference_method,
        'rule_score': best_score,
    }
