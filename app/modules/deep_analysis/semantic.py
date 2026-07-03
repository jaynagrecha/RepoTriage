from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .semantic_structure import extract_structure, merge_ast_and_structure
from .semantic_rules import PurposeRule, PURPOSE_RULES
from .semantic_capabilities_ext import EXTENDED_CAPABILITY_DEFS, scan_extended_capabilities


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
    'network_socket': 'Raw socket / reverse-shell style networking',
    'registry_access': 'Windows registry read/write',
    'service_manipulation': 'Service or scheduled task control',
    'file_enumeration': 'Directory or filesystem enumeration',
    'process_manipulation': 'Process creation or termination',
    'keylogging': 'Keystroke capture patterns',
    'ransomware_pattern': 'Mass file encryption / ransom note patterns',
    'scanner_recon': 'Network or host scanning',
    'database_access': 'Database client or query execution',
    'email_smtp': 'Email sending via SMTP',
    'cloud_api': 'Cloud provider API usage',
    'packer_obfuscation': 'Heavy obfuscation or packing markers',
}

CAPABILITY_DEFS.update(EXTENDED_CAPABILITY_DEFS)


@dataclass
class CapabilityHit:
    id: str
    confidence: str
    evidence: list[str] = field(default_factory=list)


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
    if re.search(r'^\s*def\s+\w+\(', text, re.M):
        add('library_module', 'Defines callable functions')
    if re.search(r'class\s+MetasploitModule|module\.exports|Msf::', text):
        add('library_module', 'Module class or export surface')

    if re.search(r'requests\.(get|post|put|patch|delete)|urllib\.|http\.client|aiohttp|httpx|axios|fetch\s*\(|http\.get|http\.request', text, re.I):
        add('network_http', 'HTTP client library usage')
    if re.search(r'subprocess\.|os\.system|os\.popen|Popen\s*\(|Start-Process|Invoke-Expression|\biex\b', text, re.I):
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

    if re.search(r'downloadstring|downloadfile|invoke-webrequest|wget\s|bitsadmin|iwr\b', text, re.I):
        add('download_remote', 'Remote download primitive')
    else:
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('::'):
                continue
            if re.search(r'\bcurl\s+', line, re.I):
                add('download_remote', 'Remote download via curl')
                break
    if re.search(r'CurrentVersion\\Run|schtasks|crontab|/etc/cron', text, re.I):
        add('persistence', 'Persistence mechanism reference')
    if re.search(r'mimikatz|lsass|sekurlsa|id_rsa|\.htpasswd|google_authenticator|/etc/shadow', text, re.I):
        add('credential_access', 'Credential or secret access pattern')
    if re.search(r'discord(?:app)?\.com/api/webhooks|api\.telegram\.org', text, re.I):
        add('webhook_exfil', 'Webhook/bot exfil endpoint')

    if re.search(r'auth/sms|/sms/send|profiles/register|sign_up|password.?reset', lower):
        add('sms_abuse_api', 'SMS/OTP API-style URL or path')
    if re.search(r'phone_number|phoneNumber|msisdn', text):
        add('phone_fields', 'Phone number variable fields')
    if re.search(r'threading|ThreadPool|multiprocessing|asyncio\.gather', text):
        add('threading_parallel', 'Parallel worker/thread usage')

    if re.search(r'/dev/tcp/|socket\.socket|\.connect\s*\(|\.bind\s*\(|/dev/udp/|bash\s+-i\s+>&|TCPClient|Net\.Sockets', text, re.I):
        add('network_socket', 'Socket or bash reverse-shell networking')
    if re.search(r'reg\s+(add|delete)|HKEY_|Registry\.|Set-ItemProperty.*Registry', text, re.I):
        add('registry_access', 'Windows registry access')
    if re.search(r'os\.walk|glob\.glob|Get-ChildItem\s+.*-Recurse|find\s+/|scandir', text, re.I):
        add('file_enumeration', 'Directory or filesystem enumeration')
    if re.search(r'CreateProcess|TerminateProcess|kill\s*\(|taskkill|Stop-Process', text, re.I):
        add('process_manipulation', 'Process creation or termination')
    if re.search(r'GetAsyncKeyState|keylog|pynput\.keyboard|SetWindowsHookEx', text, re.I):
        add('keylogging', 'Keystroke capture pattern')
    if re.search(r'ransom|decrypt\s+instruction|bitcoin|\.locked|\.encrypted|README.*recover', lower):
        add('ransomware_pattern', 'Ransom note or mass-encryption marker')
    if re.search(r'nmap|masscan|ping\s+-c|Test-NetConnection|port\s*scan', text, re.I):
        add('scanner_recon', 'Network or port scanning')
    if re.search(r'sqlite3|pymysql|psycopg2|mysql\.connector|Invoke-Sqlcmd', text, re.I):
        add('database_access', 'Database client usage')
    if re.search(r'smtplib|Send-MailMessage|System\.Net\.Mail', text, re.I):
        add('email_smtp', 'Email/SMTP sending')
    if re.search(r'boto3|azure\.|google\.cloud|BlobServiceClient', text, re.I):
        add('cloud_api', 'Cloud provider API usage')
    if len(re.findall(r'_0x[a-f0-9]{3,}|chr\s*\(|fromCharCode|-EncodedCommand|\\\\x[0-9a-f]{2}', text, re.I)) >= 4:
        add('packer_obfuscation', 'Heavy obfuscation markers')

    if 'bf_xor' in name_lower or ('xor' in name_lower and 'bf' in name_lower):
        add('metasploit_framework', 'Filename consistent with Metasploit auxiliary module', 'medium')

    for cap_id, evidence_list in scan_extended_capabilities(text, filename=filename).items():
        for ev in evidence_list:
            add(cap_id, ev)

    if not hits and len(text.strip()) > 100 and not re.search(r'^\s*(?:def |function |class |import |#include)', text, re.M):
        if re.search(r'^\s*[\{\[]|^\s*\w+\s*:', text, re.M):
            add('config_file_only', 'Mostly configuration/data structure with minimal executable logic', 'medium')

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
    if 'network_socket' in caps and ('subprocess_exec' in caps or 'dynamic_exec' in caps):
        return 'Remote host:port → shell/command channel (reverse shell pattern)'
    if 'network_http' in caps and 'download_remote' not in caps and 'subprocess_exec' not in caps:
        return 'HTTP request/response to external endpoints (client only in source)'
    if 'file_enumeration' in caps and 'crypto_generic' in caps and 'file_write' in caps:
        return 'Directory walk → read files → encrypt/write (ransomware-like chain)'
    if 'registry_access' in caps and 'persistence' in caps:
        return 'Registry modification for persistence'
    if 'scanner_recon' in caps:
        return 'Host/network discovery and port scanning'
    return None


def _infer_language(filename: str, text: str, static: dict[str, Any] | None) -> str:
    typed = ((static or {}).get('typed_analysis') or {})
    if typed.get('language'):
        return str(typed['language'])
    ext = Path(filename or '').suffix.lower()
    mapping = {
        '.py': 'python', '.rb': 'ruby', '.ps1': 'powershell', '.psm1': 'powershell',
        '.js': 'javascript', '.mjs': 'javascript', '.ts': 'javascript',
        '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell',
        '.pl': 'perl', '.lua': 'lua', '.php': 'php',
        '.bat': 'batch', '.cmd': 'batch', '.vbs': 'vbscript', '.vbe': 'vbscript',
        '.hta': 'html', '.wsf': 'xml',
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


def _analyze_binary_semantic(pe_deep: dict[str, Any], text: str, filename: str) -> dict[str, Any]:
    caps = _pe_capabilities(pe_deep)
    cap_ids = _cap_ids(caps)
    imports = (pe_deep.get('high_risk_imports') or []) + (pe_deep.get('informational_imports') or [])
    import_names = [i.get('import', '') for i in imports[:8]]
    title = 'PE binary — import and string analysis'
    summary = (
        f'Compiled PE binary `{filename}` analyzed via import taxonomy and embedded strings. '
        f'Detected {len(caps)} capability signal(s) from PE structure.'
    )
    bullets: list[str] = []
    if import_names:
        bullets.append(f'Notable imports: {", ".join(import_names)}.')
    if pe_deep.get('packer_hints'):
        bullets.append(f'Packer/protector hints: {"; ".join(pe_deep["packer_hints"][:3])}.')
    if cap_ids & {'pe_injection'}:
        title = 'PE loader / injection-capable binary'
        summary = (
            'PE imports indicate cross-process manipulation or injection. Review as potential loader unless '
            'this is a known legitimate DLL in your environment.'
        )
    elif cap_ids & {'pe_packing'} and not cap_ids & {'pe_injection'}:
        title = 'Packed or protected PE binary'
        summary = 'High-entropy or low-import PE — may hide a second-stage payload. Static unpack recommended.'
    threat = 'malware' if cap_ids & {'pe_injection', 'anti_analysis'} else 'unknown'
    if cap_ids & {'pe_packing'} and threat == 'unknown':
        threat = 'unknown'
    return {
        'behavior_class': 'pe_binary_analysis',
        'behavior_title': title,
        'summary': summary,
        'what_it_does': bullets or ['Binary analyzed from PE imports and embedded strings — no script source.'],
        'threat_category': threat,
        'confidence': 'medium' if caps else 'low',
        'confidence_score': min(100, len(caps) * 15 + len(imports)),
        'recommended_action': 'Do not execute on production unless scope is confirmed. Use static PE analysis below.',
        'capabilities': [
            {'id': c.id, 'label': CAPABILITY_DEFS.get(c.id, c.id), 'confidence': c.confidence, 'evidence': c.evidence[:4]}
            for c in caps
        ],
        'entry_point': 'binary',
        'language': 'pe/binary',
        'data_flow': None,
        'purpose_rule_id': 'pe_implant_loader' if cap_ids >= {'pe_injection'} else None,
        'inference_method': 'pe_capability',
        'rule_score': len(caps) * 10,
        'ast_parsed': False,
        'functions': [],
        'engine': 'repotriage_semantic_v2',
    }


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
    if text.strip():
        structure = extract_structure(language, text)
        ast_info = merge_ast_and_structure(ast_info, structure)
        for imp in ast_info.get('imports') or []:
            if any(x in imp.lower() for x in ('http', 'request', 'urllib', 'axios', 'fetch')):
                pass  # handled in text scan

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
    is_pe = bool((pe_deep or {}).get('high_risk_imports') or (pe_deep or {}).get('packer_hints'))
    entry_point = ast_info.get('entry_point') or ('binary' if is_pe else 'script')

    # Minimal / binary-only input — derive behavior from PE surface
    if len(text.strip()) < 40 and is_pe:
        binary_sem = _analyze_binary_semantic(pe_deep or {}, text, fname)
        for rule in PURPOSE_RULES:
            score, _ = _score_rule(rule, caps)
            if score >= 18 and rule.rule_id == 'pe_implant_loader' and ('pe_injection' in cap_ids):
                binary_sem['purpose_rule_id'] = rule.rule_id
                binary_sem['behavior_class'] = rule.behavior_class
                binary_sem['behavior_title'] = rule.behavior_title
                binary_sem['summary'] = rule.summary_template.format(language='pe', entry_label='binary', role_line='')
                binary_sem['confidence'] = 'high'
                binary_sem['confidence_score'] = max(binary_sem['confidence_score'], 72)
                break
        return binary_sem

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
    if best_rule and best_score >= 14:
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
        confidence_score = min(100, len(capabilities) * 10 + (25 if ast_info.get('parsed') else 10))
        confidence = 'high' if confidence_score >= 50 else ('medium' if confidence_score >= 24 else 'low')

    return {
        'engine': 'repotriage_semantic_v2',
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
