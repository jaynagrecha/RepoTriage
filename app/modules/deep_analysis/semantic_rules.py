from __future__ import annotations

from dataclasses import dataclass


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


_M = 'Do not execute on production. Quarantine and investigate delivery path.'
_D = 'Dual-use security tooling — authorized lab or pentest scope only.'
_A = 'Do not deploy for harassment or unauthorized targeting.'
_R = 'Review capabilities and deployment context before execution.'


def _mk(
    rule_id: str,
    behavior_class: str,
    title: str,
    category: str,
    requires: set[str],
    any_of: set[str] | None = None,
    forbids: set[str] | None = None,
    summary: str | None = None,
    effect: str | None = None,
    action: str | None = None,
) -> PurposeRule:
    return PurposeRule(
        rule_id=rule_id,
        behavior_class=behavior_class,
        behavior_title=title,
        threat_category=category,
        requires=frozenset(requires),
        any_of=frozenset(any_of or ()),
        forbids=frozenset(forbids or ()),
        summary_template=summary or f'{title} identified from source capability composition.',
        primary_effect=effect or title,
        recommended_action=action or _R,
    )


def build_purpose_rules() -> list[PurposeRule]:
    r: list[PurposeRule] = []

    # 1–12: Core rules
    r += [
        _mk('shellcode_encoder_utility', 'shellcode_tool', 'Shellcode encode/decode utility', 'dual_use_security_tool',
            {'shellcode_transform', 'crypto_xor'}, {'cli_interface', 'library_module'},
            {'network_http', 'subprocess_exec', 'download_remote', 'dynamic_exec'},
            'Offline XOR shellcode utility — no network/exec in source.', action=_D),
        _mk('linux_privesc_enumerator', 'linux_privesc_enum', 'Linux privilege-escalation enumerator', 'dual_use_security_tool',
            {'privesc_enumeration'}, {'library_module', 'cli_interface', 'file_enumeration', 'credential_access'},
            {'sms_abuse_api'},
            'This behaves like a Linux privilege-escalation enumeration script with pentest reference patterns.',
            action=_D),
        _mk('metasploit_module', 'metasploit_module', 'Metasploit Framework module', 'dual_use_security_tool',
            {'metasploit_framework'}, {'library_module', 'cli_interface'},
            summary='This is Metasploit Framework module source for msfconsole — {role_line}not a standalone implant.', action=_D),
        _mk('sms_otp_abuse', 'sms_otp_abuse', 'SMS / OTP abuse tool', 'abuse_tool',
            {'sms_abuse_api', 'phone_fields'}, {'network_http'},
            summary='Automates SMS/OTP API abuse using phone-number fields against third-party services.', action=_A),
        _mk('script_dropper', 'script_dropper', 'Script-based dropper / downloader', 'malware',
            {'download_remote'}, {'dynamic_exec', 'subprocess_exec'}, action=_M),
        _mk('credential_exfil_webhook', 'credential_stealer', 'Credential theft via webhook', 'malware',
            {'webhook_exfil'}, {'credential_access', 'network_http'}, action=_M),
        _mk('reverse_shell', 'remote_access', 'Reverse shell / remote command channel', 'malware',
            {'network_socket'}, {'subprocess_exec', 'dynamic_exec'}, action=_M),
        _mk('obfuscated_dropper', 'script_dropper', 'Obfuscated downloader / dropper', 'malware',
            {'download_remote'}, {'dynamic_exec', 'subprocess_exec', 'crypto_base64', 'packer_obfuscation'},
            {'privesc_enumeration'}, action=_M),
        _mk('ransomware_like', 'ransomware_pattern', 'Ransomware-like encryption pattern', 'malware',
            {'crypto_generic', 'file_write', 'file_enumeration'}, {'file_read', 'ransomware_pattern'}, action=_M),
        _mk('network_client_utility', 'generic_network_tool', 'HTTP/network client utility', 'unknown',
            {'network_http'}, {'cli_interface', 'library_module'},
            {'subprocess_exec', 'dynamic_exec', 'download_remote', 'webhook_exfil', 'persistence'}),
        _mk('pe_implant_loader', 'process_injection', 'PE injection-capable binary', 'malware',
            {'pe_injection'}, {'pe_packing', 'network_http', 'anti_analysis'}, action=_M),
        _mk('pe_packed_binary', 'packed_loader', 'Packed / protected PE binary', 'malware',
            {'pe_packing'}, {'pe_injection', 'anti_analysis'}, action=_M),
    ]

    # 13–27: RAT / C2
    for rid, cap, title, any_c in [
        ('cobalt_strike_beacon', 'cobalt_strike', 'Cobalt Strike beacon implant', {'network_http', 'network_socket', 'pe_injection'}),
        ('sliver_implant', 'sliver_c2', 'Sliver C2 implant', {'network_http', 'network_socket'}),
        ('havoc_implant', 'havoc_c2', 'Havoc C2 demon agent', {'network_socket', 'process_hollow'}),
        ('asyncrat_implant', 'asyncrat_marker', 'AsyncRAT trojan', {'network_socket', 'keylogging', 'screen_capture'}),
        ('njrat_implant', 'njrat_marker', 'NjRAT trojan', {'network_socket', 'keylogging'}),
        ('quasar_rat', 'quasar_marker', 'Quasar RAT', {'network_socket', 'screen_capture'}),
        ('remcos_rat', 'remcos_marker', 'Remcos RAT', {'network_socket', 'keylogging'}),
        ('empire_agent_rule', 'empire_agent', 'PowerShell Empire agent', {'network_http', 'dynamic_exec'}),
        ('covenant_grunt', 'covenant_grpc', 'Covenant C2 grunt', {'network_http'}),
        ('irc_botnet_client', 'botnet_irc', 'IRC botnet client', {'network_socket'}),
        ('donut_loader_rule', 'donut_loader', 'Donut shellcode loader', {'shellcode_literals', 'reflective_dll'}),
        ('reflective_dll_rule', 'reflective_dll', 'Reflective DLL loader', {'pe_injection', 'dynamic_exec'}),
        ('tor_hidden_c2', 'tor_network', 'Tor-hidden C2 channel', {'network_http', 'network_socket'}),
        ('meterpreter_payload', 'metasploit_framework', 'Meterpreter payload reference', {'network_socket', 'shellcode_literals'}),
        ('bind_shell_listener', 'network_socket', 'Bind shell listener', {'subprocess_exec'}),
    ]:
        r.append(_mk(rid, 'c2_implant', title, 'malware', {cap}, any_c, action=_M))

    # 28–39: Stealers
    for rid, cap, title, any_c in [
        ('redline_stealer_rule', 'redline_stealer', 'RedLine stealer', {'browser_stealer', 'webhook_exfil'}),
        ('browser_stealer_rule', 'browser_stealer', 'Browser credential stealer', {'file_read', 'webhook_exfil'}),
        ('cookie_stealer_rule', 'cookie_stealer', 'Cookie/session stealer', {'browser_stealer', 'network_http'}),
        ('discord_stealer_rule', 'discord_stealer', 'Discord token stealer', {'webhook_exfil', 'file_read'}),
        ('wallet_stealer_rule', 'wallet_stealer', 'Cryptocurrency wallet stealer', {'file_read', 'webhook_exfil'}),
        ('keylogger_rule', 'keylogging', 'Keylogger', {'webhook_exfil', 'persistence'}),
        ('clipboard_clipper', 'clipboard_monitor', 'Clipboard hijacker', {'crypto_miner', 'wallet_stealer'}),
        ('screen_spy_rule', 'screen_capture', 'Screen capture spyware', {'network_http', 'webhook_exfil'}),
        ('webcam_spy_rule', 'webcam_capture', 'Webcam spyware', {'network_http'}),
        ('audio_spy_rule', 'audio_capture', 'Audio spyware', {'network_http'}),
        ('mimikatz_rule', 'mimikatz_tool', 'Mimikatz credential dumper', {'credential_access', 'process_manipulation'}),
        ('impacket_secretsdump', 'impacket_tool', 'Impacket secretsdump tool', {'ldap_enumeration', 'psexec_lateral'}),
    ]:
        r.append(_mk(rid, 'credential_stealer', title, 'malware', {cap}, any_c, action=_M))

    # 40–51: Lateral / AD
    for rid, cls, title, cat, req, any_c in [
        ('psexec_lateral_rule', 'lateral_movement', 'PsExec SMB lateral movement', 'malware', {'psexec_lateral'}, {'credential_access'}),
        ('wmi_lateral_rule', 'lateral_movement', 'WMI remote execution', 'malware', {'wmi_lateral'}, {'subprocess_exec'}),
        ('dcom_lateral_rule', 'lateral_movement', 'DCOM lateral movement', 'malware', {'dcom_lateral'}, {'subprocess_exec'}),
        ('bloodhound_rule', 'ad_enumeration', 'BloodHound AD enumeration', 'dual_use_security_tool', {'bloodhound_ad'}, {'ldap_enumeration'}),
        ('ldap_recon_rule', 'ad_enumeration', 'LDAP/AD reconnaissance', 'dual_use_security_tool', {'ldap_enumeration'}, {'network_http'}),
        ('kerberos_attack_rule', 'ad_attack', 'Kerberos attack tool', 'malware', {'kerberos_attack'}, {'ldap_enumeration'}),
        ('pass_the_hash_rule', 'lateral_movement', 'Pass-the-hash tool', 'malware', {'impacket_tool', 'psexec_lateral'}, {'credential_access'}),
        ('named_pipe_rule', 'privilege_escalation', 'Named pipe impersonation', 'malware', {'named_pipe'}, {'token_impersonate'}),
        ('token_theft_rule', 'privilege_escalation', 'Token theft / impersonation', 'malware', {'token_impersonate'}, {'process_manipulation'}),
        ('dll_hijack_rule', 'persistence_tool', 'DLL hijacking', 'malware', {'dll_hijack'}, {'file_write', 'persistence'}),
        ('wmi_persist_rule', 'persistence_tool', 'WMI persistence', 'malware', {'persistence_wmi'}, {'persistence'}),
        ('schtask_persist_rule', 'persistence_tool', 'Scheduled task persistence', 'malware', {'persistence_schtask'}, {'subprocess_exec'}),
    ]:
        r.append(_mk(rid, cls, title, cat, set(req), set(any_c), action=_D if cat == 'dual_use_security_tool' else _M))

    # 52–66: LOLBins / evasion
    for rid, cap, title, any_c in [
        ('certutil_lolbin', 'lolbin_certutil', 'Certutil download/decode LOLBin', {'download_remote', 'crypto_base64'}),
        ('msbuild_lolbin', 'lolbin_msbuild', 'MSBuild inline execution', {'dynamic_exec', 'download_remote'}),
        ('regsvr32_lolbin', 'lolbin_regsvr32', 'Regsvr32 squiblydoo', {'download_remote', 'dynamic_exec'}),
        ('rundll32_lolbin', 'lolbin_rundll32', 'Rundll32 suspicious exec', {'dynamic_exec'}),
        ('mshta_lolbin', 'lolbin_mshta', 'MSHTA remote launcher', {'download_remote', 'dynamic_exec'}),
        ('hta_dropper_rule', 'hta_execution', 'HTA dropper', {'download_remote', 'dynamic_exec'}),
        ('office_macro_rule', 'macro_office', 'Office macro dropper', {'download_remote', 'dynamic_exec'}),
        ('encoded_powershell', 'packer_obfuscation', 'Encoded PowerShell dropper', {'dynamic_exec', 'download_remote'}),
        ('amsi_bypass_rule', 'amsi_bypass', 'AMSI bypass loader', {'dynamic_exec', 'download_remote'}),
        ('uac_bypass_rule', 'uac_bypass', 'UAC bypass utility', {'subprocess_exec', 'registry_access'}),
        ('defense_disable_rule', 'defense_disable', 'Security product disabler', {'registry_access', 'subprocess_exec'}),
        ('log_clear_rule', 'log_clearing', 'Event log clearing', {'subprocess_exec'}),
        ('process_hollow_rule', 'process_hollow', 'Process hollowing', {'pe_injection', 'process_manipulation'}),
        ('api_unhook_rule', 'api_unhook', 'API unhooking', {'pe_injection'}),
        ('timestomp_rule', 'timestomp', 'Timestomp utility', {'file_write'}),
    ]:
        r.append(_mk(rid, 'script_dropper' if 'lolbin' in rid or 'dropper' in rid or 'encoded' in rid else 'evasion_tool',
                     title, 'malware', {cap}, any_c, action=_M))

    # 67–76: Web
    for rid, cls, title, cat, req, any_c in [
        ('php_webshell_rule', 'webshell', 'PHP web shell', 'malware', {'webshell_php'}, {'dynamic_exec'}),
        ('asp_webshell_rule', 'webshell', 'ASP/JSP web shell', 'malware', {'webshell_asp'}, {'dynamic_exec'}),
        ('sqlmap_rule', 'web_attack_tool', 'SQLMap SQLi automation', 'dual_use_security_tool', {'sqlmap_tool'}, {'sql_injection'}),
        ('sqli_probe_rule', 'web_attack_tool', 'SQL injection probe', 'malware', {'sql_injection'}, {'network_http'}),
        ('xss_probe_rule', 'web_attack_tool', 'XSS probe', 'malware', {'xss_probe'}, {'network_http'}),
        ('phishing_kit_rule', 'phishing_tool', 'Credential phishing kit', 'malware', {'phishing_html'}, {'email_smtp'}),
        ('beef_hook_rule', 'web_attack_tool', 'BeEF browser hook', 'malware', {'beef_hook'}, {'network_http'}),
        ('nuclei_rule', 'scanner_tool', 'Nuclei vulnerability scanner', 'dual_use_security_tool', {'nuclei_scanner'}, {'network_http'}),
        ('ffuf_rule', 'scanner_tool', 'Web fuzzer (ffuf/gobuster)', 'dual_use_security_tool', {'ffuf_fuzzer'}, {'network_http'}),
        ('responder_rule', 'network_attack_tool', 'Responder LLMNR poisoner', 'dual_use_security_tool', {'responder_poison'}, {'network_socket'}),
    ]:
        r.append(_mk(rid, cls, title, cat, set(req), set(any_c), action=_D if 'dual' in cat else _M))

    # 77–86: Miners / abuse
    for rid, cls, title, cat, req, any_c in [
        ('miner_rule', 'miner_malware', 'Cryptocurrency miner', 'malware', {'crypto_miner'}, {'stratum_mining', 'network_socket'}),
        ('stratum_rule', 'miner_malware', 'Stratum pool miner', 'malware', {'stratum_mining'}, {'network_socket'}),
        ('password_spray_rule', 'abuse_tool', 'Password spraying tool', 'abuse_tool', {'password_spray'}, {'network_http'}),
        ('ssh_brute_rule', 'abuse_tool', 'SSH brute-force tool', 'abuse_tool', {'ssh_brute'}, {'network_socket'}),
        ('hydra_rule', 'abuse_tool', 'Hydra brute-forcer', 'abuse_tool', {'hydra_brute'}, {'network_http', 'network_socket'}),
        ('ddos_rule', 'abuse_tool', 'HTTP/UDP flood tool', 'abuse_tool', {'flood_stress'}, {'network_socket'}),
        ('spam_rule', 'abuse_tool', 'Bulk spam campaign tool', 'abuse_tool', {'spam_campaign'}, {'email_smtp'}),
        ('click_fraud_rule', 'abuse_tool', 'Click fraud bot', 'abuse_tool', {'click_fraud'}, {'network_http'}),
        ('dns_exfil_rule', 'exfil_tool', 'DNS exfiltration tunnel', 'malware', {'dns_exfil'}, {'network_socket'}),
        ('icmp_tunnel_rule', 'exfil_tool', 'ICMP tunnel utility', 'malware', {'icmp_tunnel'}, {'network_socket'}),
    ]:
        r.append(_mk(rid, cls, title, cat, set(req), set(any_c), action=_A if cat == 'abuse_tool' else _M))

    # 87–94: Cloud / container
    for rid, title, req, any_c in [
        ('kube_abuse_rule', 'Kubernetes API abuse', {'kube_exfil'}, {'network_http', 'credential_access'}),
        ('container_escape_rule', 'Container escape exploit', {'container_escape'}, {'privesc_enumeration', 'subprocess_exec'}),
        ('aws_abuse_rule', 'AWS metadata/credential abuse', {'aws_exfil'}, {'network_http', 'cloud_api'}),
        ('azure_abuse_rule', 'Azure credential abuse', {'azure_exfil'}, {'network_http', 'cloud_api'}),
        ('gcp_abuse_rule', 'GCP metadata abuse', {'gcp_exfil'}, {'network_http', 'cloud_api'}),
        ('cloud_exfil_rule', 'Cloud storage exfil client', {'cloud_api'}, {'network_http', 'file_read'}),
        ('proxy_tunnel_rule', 'SOCKS/proxy tunnel', {'proxy_socks'}, {'network_socket'}),
        ('bettercap_rule', 'Bettercap MITM suite', {'bettercap_attack'}, {'network_socket', 'credential_access'}),
    ]:
        r.append(_mk(rid, 'cloud_abuse', title, 'malware', set(req), set(any_c), action=_M))

    # 95–99: Ransomware extras
    r += [
        _mk('ransomware_vss_rule', 'ransomware_pattern', 'Ransomware VSS deletion', 'malware',
            {'ransomware_vss'}, {'crypto_generic', 'file_write'}, action=_M),
        _mk('ransom_note_rule', 'ransomware_pattern', 'Ransom note dropper', 'malware',
            {'ransomware_pattern'}, {'file_write', 'crypto_generic'}, action=_M),
        _mk('mass_encrypt_rule', 'ransomware_pattern', 'Mass file encryptor', 'malware',
            {'crypto_generic', 'file_enumeration', 'file_write'}, {'file_read'}, action=_M),
        _mk('wiper_rule', 'wiper_malware', 'File wiper', 'malware',
            {'file_write', 'file_enumeration'}, {'process_manipulation'}, {'network_http'}, action=_M),
        _mk('double_extortion_rule', 'ransomware_pattern', 'Ransomware with exfiltration', 'malware',
            {'ransomware_pattern', 'crypto_generic'}, {'webhook_exfil', 'network_http'}, action=_M),
    ]

    # 100–110: Recon / benign
    r += [
        _mk('nmap_rule', 'scanner_tool', 'Network/port scanner', 'dual_use_security_tool',
            {'scanner_recon'}, {'network_socket', 'cli_interface'}, action=_D),
        _mk('hashcat_rule', 'dual_use_crypto', 'Hash cracking utility', 'dual_use_security_tool',
            {'hashcat_helper'}, {'cli_interface', 'file_read'}, action=_D),
        _mk('sandbox_evasion_rule', 'evasion_tool', 'Sandbox evasion checks', 'malware',
            {'sandbox_evasion'}, {'vm_detection', 'anti_analysis'}, action=_M),
        _mk('vm_detect_rule', 'evasion_tool', 'VM detection', 'malware', {'vm_detection'}, action=_M),
        _mk('startup_persist_rule', 'persistence_tool', 'Startup persistence', 'malware',
            {'persistence_startup'}, {'persistence', 'file_write'}, action=_M),
        _mk('registry_persist_rule', 'persistence_tool', 'Registry persistence', 'malware',
            {'registry_access', 'persistence'}, {'file_write'}, action=_M),
        _mk('cli_http_benign', 'generic_network_tool', 'Benign CLI HTTP client', 'unknown',
            {'network_http', 'cli_interface'}, forbids={'download_remote', 'dynamic_exec', 'subprocess_exec', 'webhook_exfil'}),
        _mk('install_script_rule', 'installer_script', 'Installer script', 'unknown',
            {'install_script'}, {'cli_interface', 'file_write'}),
        _mk('unit_test_rule', 'test_harness', 'Unit test harness', 'unknown', {'unit_test_code'}, {'library_module'}),
        _mk('build_script_rule', 'build_automation', 'Build/CI script', 'unknown', {'build_script'}, {'subprocess_exec'}),
        _mk('data_etl_rule', 'data_tool', 'ETL data pipeline', 'unknown', {'data_etl'}, {'file_read', 'database_access'}),
        _mk('idea_module_config', 'config_metadata', 'IntelliJ IDEA module descriptor', 'unknown',
            {'idea_module_descriptor', 'config_file_only'},
            forbids={'network_http', 'subprocess_exec', 'dynamic_exec', 'download_remote'},
            summary='IntelliJ IDEA `.iml` module metadata — defines source roots and library dependencies, not executable code.',
            effect='IDE module configuration (Java/Maven project layout and dependencies).',
            action='Safe to review statically. Not executable outside the IDE/build tool.'),
        _mk('xml_config_document', 'config_metadata', 'XML configuration document', 'unknown',
            {'xml_config_document', 'config_file_only'},
            forbids={'network_http', 'subprocess_exec', 'dynamic_exec', 'download_remote'},
            summary='XML configuration or project metadata — no executable script logic detected.',
            effect='Structured XML configuration consumed by tools or build systems.'),
        _mk('structured_config_file', 'config_metadata', 'Structured configuration file', 'unknown',
            {'config_file_only'},
            forbids={'network_http', 'subprocess_exec', 'dynamic_exec', 'download_remote'},
            summary='Configuration or data file with minimal executable logic.',
            effect='Settings, metadata, or data — not a runnable script.'),
    ]

    seen: set[str] = set()
    out: list[PurposeRule] = []
    for rule in r:
        if rule.rule_id in seen:
            continue
        seen.add(rule.rule_id)
        out.append(rule)
    return out


PURPOSE_RULES: list[PurposeRule] = build_purpose_rules()
