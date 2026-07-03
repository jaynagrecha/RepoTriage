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
        'config': 'configuration file',
    }.get(entry_point, 'program')


CONFIG_EXTENSIONS = frozenset({
    '.iml', '.xml', '.xsl', '.xslt', '.json', '.yaml', '.yml', '.toml',
    '.ini', '.properties', '.cfg', '.conf', '.plist', '.csproj', '.sln',
    '.props', '.targets', '.gradle', '.pom', '.nuspec', '.resx',
})


def _detect_config_kind(filename: str, text: str, static: dict[str, Any] | None) -> str | None:
    ext = Path(filename or '').suffix.lower()
    typed = ((static or {}).get('typed_analysis') or {})
    fmt = str(typed.get('format') or '').lower()
    stripped = text.lstrip()

    if ext == '.iml' or (ext in {'.xml', '.xsl', '.xslt'} and re.search(r'<module\b', text, re.I)):
        return 'idea_module'
    if ext == '.pom' or (ext == '.xml' and 'maven.apache.org/POM' in text):
        return 'maven_pom'
    if ext in {'.csproj', '.sln', '.props', '.targets', '.gradle', '.nuspec'}:
        return 'build_metadata'
    if ext in CONFIG_EXTENSIONS or fmt in {'xml', 'json', 'yaml'}:
        if stripped.startswith('<?xml') or fmt == 'xml':
            return 'xml'
        if ext in {'.json', '.yaml', '.yml', '.toml', '.ini', '.properties', '.cfg', '.conf'}:
            return 'structured'
        if ext in {'.xml', '.xsl', '.xslt', '.plist'}:
            return 'xml'
    if stripped.startswith('<?xml') and not re.search(r'^\s*(?:def |function |class |import |#include)', text, re.M):
        if re.search(r'<module\b', text, re.I):
            return 'idea_module'
        return 'xml'
    return None


def _parse_config_facts(text: str, filename: str, kind: str) -> dict[str, Any]:
    facts: dict[str, Any] = {
        'document_kind': kind,
        'module_type': None,
        'source_folders': [],
        'exclude_folders': [],
        'dependencies': [],
        'language_level': None,
        'is_maven': False,
        'is_burp_extender': False,
        'root_element': None,
    }
    if kind == 'idea_module':
        m = re.search(r'<module\b[^>]*\btype="([^"]+)"', text, re.I)
        facts['module_type'] = m.group(1) if m else 'JAVA_MODULE'
        facts['is_maven'] = bool(re.search(r'MavenProjectsManager|Maven:', text, re.I))
        facts['source_folders'] = re.findall(
            r'<sourceFolder[^>]+url="[^"]+\$MODULE_DIR\$/([^"]+)"', text, re.I,
        )
        facts['exclude_folders'] = re.findall(
            r'<excludeFolder[^>]+url="[^"]+\$MODULE_DIR\$/([^"]+)"', text, re.I,
        )
        facts['dependencies'] = re.findall(
            r'<orderEntry[^>]+name="Maven:\s*([^"]+)"', text, re.I,
        )
        ll = re.search(r'LANGUAGE_LEVEL="([^"]+)"', text)
        facts['language_level'] = ll.group(1) if ll else None
        lower = text.lower()
        facts['is_burp_extender'] = 'burp-extender' in lower or 'burp.extender' in lower
    elif kind in {'xml', 'maven_pom', 'build_metadata'}:
        root = re.search(r'<\s*([A-Za-z_][\w.-]*)', text)
        facts['root_element'] = root.group(1) if root else None
        if kind == 'maven_pom' or 'maven.apache.org/POM' in text:
            facts['is_maven'] = True
            facts['dependencies'] = re.findall(r'<artifactId>([^<]+)</artifactId>', text)[:8]
    return facts


def _config_capability_scan(text: str, filename: str, kind: str) -> list[CapabilityHit]:
    hits: list[CapabilityHit] = []
    facts = _parse_config_facts(text, filename, kind)

    def add(cap_id: str, evidence: str, confidence: str = 'high') -> None:
        hits.append(CapabilityHit(cap_id, confidence, [evidence[:160]]))

    add('config_file_only', f'{kind.replace("_", " ")} document — no executable script logic', 'high')
    if kind == 'idea_module':
        add('idea_module_descriptor', 'IntelliJ `.iml` module root element', 'high')
        if facts['is_maven']:
            add('maven_module_metadata', 'Maven module markers in IDEA module file', 'high')
    elif kind in {'xml', 'maven_pom', 'build_metadata'}:
        add('xml_config_document', f'XML document ({facts.get("root_element") or "root element"})', 'high')
        if facts.get('is_maven'):
            add('maven_module_metadata', 'Maven POM/project metadata', 'high')
    return hits


def _build_config_summary(
    *,
    filename: str,
    kind: str,
    facts: dict[str, Any],
    rule: PurposeRule | None,
) -> tuple[str, str, list[str], str, str, int]:
    bullets: list[str] = []
    ext = Path(filename).suffix.lower() or 'file'

    if kind == 'idea_module':
        title = 'IntelliJ IDEA module descriptor'
        if facts.get('is_maven'):
            title += ' (Maven/Java)'
        if facts.get('is_burp_extender'):
            title += ' — Burp Suite extender project'

        bullets.append(f'Document type: IntelliJ `.iml` module configuration ({ext}).')
        if facts.get('module_type'):
            bullets.append(f'Module type: {facts["module_type"]}.')
        if facts.get('language_level'):
            bullets.append(f'Language level: {facts["language_level"]}.')
        if facts.get('source_folders'):
            bullets.append(f'Source roots: {", ".join(facts["source_folders"][:6])}.')
        if facts.get('exclude_folders'):
            bullets.append(f'Excluded paths: {", ".join(facts["exclude_folders"][:4])}.')
        if facts.get('dependencies'):
            bullets.append(f'Library dependencies: {", ".join(facts["dependencies"][:5])}.')
        bullets.append('Not executable code — consumed by IntelliJ/IDEA and build tools only.')

        summary = (
            f'`{filename}` is an IntelliJ IDEA module descriptor, not a runnable script. '
            f'It defines Java/Maven project layout'
        )
        if facts.get('dependencies'):
            summary += f' and declares dependencies such as `{facts["dependencies"][0]}`'
        if facts.get('is_burp_extender'):
            summary += ' — consistent with a Burp Suite extender (Java) project'
        summary += '.'
        behavior_class = rule.behavior_class if rule else 'config_metadata'
        threat = rule.threat_category if rule else 'unknown'
        score = 42 if rule else 30
    elif kind == 'maven_pom':
        title = 'Maven POM project descriptor'
        bullets.append('Document type: Maven `pom.xml` project metadata.')
        if facts.get('dependencies'):
            bullets.append(f'Artifacts referenced: {", ".join(facts["dependencies"][:6])}.')
        bullets.append('Build/project configuration — not standalone executable logic.')
        summary = f'`{filename}` is Maven project metadata (POM), not executable malware source.'
        behavior_class = 'config_metadata'
        threat = 'unknown'
        score = 36
    elif kind == 'structured':
        title = f'Structured configuration ({ext.lstrip(".") or "data"})'
        bullets.append(f'Document type: structured config/data file ({ext or "unknown extension"}).')
        bullets.append('No functions, imports, or script execution primitives detected.')
        summary = f'`{filename}` is a structured configuration or data file with no executable script logic.'
        behavior_class = 'config_metadata'
        threat = 'unknown'
        score = 24
    else:
        title = 'XML / build configuration document'
        root = facts.get('root_element') or 'unknown'
        bullets.append(f'Document type: XML configuration (root element `<{root}>`).')
        bullets.append('No script functions or execution primitives detected in this file.')
        summary = f'`{filename}` is XML project or tool configuration — not a standalone executable script.'
        behavior_class = rule.behavior_class if rule else 'config_metadata'
        threat = rule.threat_category if rule else 'unknown'
        score = 30 if rule else 22

    if rule:
        behavior_class = rule.behavior_class
        threat = rule.threat_category
        score = max(score, 48)

    return title, summary, bullets, behavior_class, threat, score


def _analyze_config_semantic(
    text: str,
    filename: str,
    static: dict[str, Any] | None,
    kind: str,
) -> dict[str, Any]:
    capabilities = _config_capability_scan(text, filename, kind)
    caps = _cap_ids(capabilities)
    facts = _parse_config_facts(text, filename, kind)

    best_rule: PurposeRule | None = None
    best_score = 0
    best_reasons: list[str] = []
    for rule in PURPOSE_RULES:
        score, reasons = _score_rule(rule, caps)
        if score > best_score:
            best_score = score
            best_rule = rule
            best_reasons = reasons

    title, summary, bullets, behavior_class, threat_category, confidence_score = _build_config_summary(
        filename=filename,
        kind=kind,
        facts=facts,
        rule=best_rule if best_score >= 14 else None,
    )

    if best_rule and best_score >= 14:
        summary = best_rule.summary_template.format(
            language='xml',
            entry_label='configuration file',
            role_line='',
        )
        if kind == 'idea_module' and facts.get('is_burp_extender'):
            summary += ' Project context: Burp Suite extender (Java API dependency present).'
        what_it_does = best_reasons + bullets[:6]
        purpose_rule_id = best_rule.rule_id
        inference_method = 'capability_rules'
        confidence = 'high' if best_score >= 28 else 'medium'
    else:
        what_it_does = bullets
        purpose_rule_id = None
        inference_method = 'config_metadata'
        confidence = 'medium' if kind == 'idea_module' else 'low'

    return {
        'engine': 'repotriage_semantic_v2',
        'language': 'xml' if kind != 'structured' else 'config',
        'entry_point': 'config',
        'ast_parsed': False,
        'capabilities': [
            {
                'id': c.id,
                'label': CAPABILITY_DEFS.get(c.id, c.id),
                'confidence': c.confidence,
                'evidence': c.evidence[:4],
            }
            for c in capabilities
        ],
        'functions': [],
        'data_flow': None,
        'purpose_rule_id': purpose_rule_id,
        'behavior_class': behavior_class,
        'behavior_title': title,
        'summary': summary,
        'what_it_does': what_it_does,
        'threat_category': threat_category,
        'confidence': confidence,
        'confidence_score': confidence_score,
        'recommended_action': (
            best_rule.recommended_action if best_rule and best_score >= 14
            else 'Configuration/metadata only — review project source files separately for executable logic.'
        ),
        'inference_method': inference_method,
        'rule_score': best_score,
        'config_facts': facts,
    }


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

    present = _cap_ids(caps)
    if cap_labels:
        absent: list[str] = []
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

    entry = _entry_label(entry_point)
    if language == 'script' and entry == 'script':
        kind_label = 'script'
    elif language in {'script', 'config', 'xml'}:
        kind_label = entry
    else:
        kind_label = f'{language} {entry}'

    if cap_labels:
        primary_cap = cap_labels[0].split('(')[0].strip().lower()
    elif fn_names:
        primary_cap = f'helper functions ({", ".join(fn_names[:3])})'
    else:
        primary_cap = 'offline utility logic'

    summary_parts = [
        f'This {kind_label} was analyzed from source (AST + capability scan).',
        f'Primary behavior: {primary_cap}.{purpose_hint}',
    ]
    if data_flow:
        summary_parts.append(f'Processing path: {data_flow}.')
    elif not cap_labels and fn_names:
        summary_parts.append('No network, shell, download, or dynamic-eval primitives observed.')
    elif not cap_labels:
        summary_parts.append('No strong malicious capability patterns detected in source.')
    summary = ' '.join(part.strip() for part in summary_parts if part).strip()

    title_parts = [language.title() if language != 'script' else 'Script', entry if entry != 'script' else '']
    title_parts = [p for p in title_parts if p]
    if cli_description:
        title_parts.append(cli_description[:60])
    elif cap_labels:
        title_parts.append(cap_labels[0].split('(')[0].strip())
    elif fn_names:
        title_parts.append(fn_names[0])
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
    if re.search(r'\bencrypt\b|\bdecrypt\b|\bcipher\b|\baes\b|\brc4\b', lower) and 'crypto_xor' not in hits:
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
    fmt = str(typed.get('format') or '').lower()
    ext = Path(filename or '').suffix.lower()
    if ext == '.iml' or (fmt == 'xml' and re.search(r'<module\b', text, re.I)):
        return 'xml'
    mapping = {
        '.py': 'python', '.rb': 'ruby', '.ps1': 'powershell', '.psm1': 'powershell',
        '.js': 'javascript', '.mjs': 'javascript', '.ts': 'javascript',
        '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell',
        '.pl': 'perl', '.lua': 'lua', '.php': 'php',
        '.bat': 'batch', '.cmd': 'batch', '.vbs': 'vbscript', '.vbe': 'vbscript',
        '.hta': 'html', '.wsf': 'xml', '.xml': 'xml', '.xsl': 'xml', '.xslt': 'xml',
        '.json': 'config', '.yaml': 'config', '.yml': 'config', '.toml': 'config',
        '.ini': 'config', '.properties': 'config',
    }
    if ext in mapping:
        return mapping[ext]
    if fmt in {'xml', 'json', 'yaml'}:
        return fmt if fmt != 'yaml' else 'config'
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


def _analyze_python_marshal_stub(text: str, filename: str) -> dict[str, Any] | None:
    if Path(filename or '').suffix.lower() != '.py':
        return None
    if len(text) < 24:
        return None
    head = text[:16000]
    has_marshal = bool(re.search(r'marshal\.loads|py_compile|types\.CodeType|imp\.load_module', head, re.I))
    has_exec = bool(re.search(r'\bexec\s*\(', head))
    binaryish = '\x00' in text[:8192] or bool(re.search(r'[\x00-\x08\x0e-\x1f]', text[:4096]))
    if not has_exec or not (has_marshal or binaryish):
        return None

    capabilities = [
        CapabilityHit('python_marshal_payload', 'high', ['marshal / embedded bytecode loader stub']),
        CapabilityHit('dynamic_exec', 'high', ['exec() launches embedded payload']),
    ]
    if binaryish or len(re.findall(r'\\x[0-9a-fA-F]{2}', head)) >= 8:
        capabilities.append(CapabilityHit('packer_obfuscation', 'medium', ['Binary or heavy hex-escaped payload content']))
    caps = _cap_ids(capabilities)

    best_rule: PurposeRule | None = None
    best_score = 0
    best_reasons: list[str] = []
    for rule in PURPOSE_RULES:
        score, reasons = _score_rule(rule, caps)
        if score > best_score:
            best_score = score
            best_rule = rule
            best_reasons = reasons

    title = 'Obfuscated Python marshal/exec stub'
    summary = (
        f'`{filename}` is not normal Python source — it embeds marshal bytecode (or binary payload data) '
        'and uses exec() to run it. Treat as a dropper/stager; readable logic is hidden inside the embedded blob.'
    )
    bullets = [
        'Stub pattern: embedded marshal/binary payload executed via exec().',
        'Readable Python source is minimal — primary behavior is inside the embedded bytecode.',
        'Static review should focus on decoded/unpacked output, not this wrapper file alone.',
    ]
    if binaryish:
        bullets.append('File contains binary/non-text bytes — typical of packed or compiled-in-place payloads.')

    behavior_class = 'obfuscated_dropper'
    threat_category = 'malware'
    purpose_rule_id = None
    inference_method = 'marshal_stub'
    confidence = 'high'
    confidence_score = 72

    if best_rule and best_score >= 14:
        behavior_class = best_rule.behavior_class
        title = best_rule.behavior_title
        summary = best_rule.summary_template.format(language='python', entry_label='script', role_line='')
        threat_category = best_rule.threat_category
        purpose_rule_id = best_rule.rule_id
        inference_method = 'capability_rules'
        what_it_does = best_reasons + bullets[:4]
    else:
        what_it_does = bullets

    return {
        'engine': 'repotriage_semantic_v2',
        'language': 'python',
        'entry_point': 'script',
        'ast_parsed': False,
        'capabilities': [
            {'id': c.id, 'label': CAPABILITY_DEFS.get(c.id, c.id), 'confidence': c.confidence, 'evidence': c.evidence[:4]}
            for c in capabilities
        ],
        'functions': [],
        'data_flow': 'Embedded marshal bytecode → exec() → in-process payload execution',
        'purpose_rule_id': purpose_rule_id,
        'behavior_class': behavior_class,
        'behavior_title': title,
        'summary': summary,
        'what_it_does': what_it_does,
        'threat_category': threat_category,
        'confidence': confidence,
        'confidence_score': confidence_score,
        'recommended_action': 'Do not execute. Quarantine and analyze unpacked/decoded payload in an isolated VM.',
        'inference_method': inference_method,
        'rule_score': best_score,
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
    marshal_stub = _analyze_python_marshal_stub(text, fname)
    if marshal_stub:
        return marshal_stub
    config_kind = _detect_config_kind(fname, text, static)
    if config_kind:
        return _analyze_config_semantic(text, fname, static, config_kind)

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
