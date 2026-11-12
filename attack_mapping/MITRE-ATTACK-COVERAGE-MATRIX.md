
# MITRE ATT&CK Coverage Matrix
## Cyberion ThreatShield

## 1. Scope

This matrix documents ATT&CK technique mappings identified in the project's Sigma YAML rules and Log Analyzer detection logic.

Coverage is separated into:
- Sigma YAML tagged coverage
- Log Analyzer tested coverage

A technique is counted once, regardless of how many rules map to it.

## 2. Sigma YAML Coverage

| Technique ID | Technique Name | Tactic | Related Rule |
|---|---|---|---|
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement | WIN-5145 |
| T1572 | Protocol Tunneling | Command and Control | WIN-5156 |
| T1070.001 | Clear Windows Event Logs | Defense Evasion | WIN-SEC-1102 |
| T1059.001 | PowerShell | Execution | WIN-SYSMON-1 Embedded PowerShell; WIN-SYSMON-1 Encoded PowerShell |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion | WIN-SYSMON-1 Embedded PowerShell |
| T1027.010 | Command Obfuscation | Defense Evasion | WIN-SYSMON-1 Encoded PowerShell |
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access | WIN-SYSMON-10; WIN-SYSMON-11; WIN-SYSMON-8; CORR-002; CORR-003 |
| T1003 | OS Credential Dumping | Credential Access | WIN-SYSMON-10 PowerShell; WIN-SYSMON-10 Suspicious LSASS; CORR-001 |
| T1218.005 | System Binary Proxy Execution: Mshta | Defense Evasion | WIN-SYSMON-3 |
| T1547.004 | Boot or Logon Autostart Execution: Winlogon Helper DLL | Persistence | WIN-SYSMON-13 |

## 3. Log Analyzer Tested Coverage

| Technique ID | Technique Name | Tactic | Detection Rule | Test Evidence |
|---|---|---|---|---|
| T1546.003 | Event Triggered Execution: WMI Event Subscription | Persistence | CT-004 | test_wmi_subscription_detection.py - PASS |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Execution, Persistence | CT-005 | test_scheduled_task_detection.py - PASS |
| T1543.003 | Create or Modify System Process: Windows Service | Persistence | CT-006 | test_windows_service_detection.py - PASS |

Note: These are dedicated synthetic test results. They demonstrate the tested detection logic, not guaranteed real-world detection effectiveness.

## 4. Coverage Summary

- Total Sigma YAML files: 17
- Individual Sigma rules: 14
- Correlation Sigma rules: 3
- Unique ATT&CK techniques tagged in Sigma YAML: 10
- Additional Log Analyzer techniques with dedicated passing tests: 3
- Total distinct documented techniques: 13
- Target: 20+ unique techniques
- Remaining to target: 7

## 5. Rule Requiring ATT&CK Tag Review

- WIN-SYSMON-7-PowerShell-Credential-DLL-Load.yml

This rule detects selected DLL loads by PowerShell. DLL loading alone does not establish a specific ATT&CK technique, so it remains without an explicit technique tag.

## 6. Hunt and Response Coverage

- HUNT-01: LSASS Remote Thread and Process Access
- HUNT-02: LSASS Access Correlated with Dump File Creation
- PB-01: LSASS Credential Dumping Response
- PB-02: Suspicious PowerShell Execution Response
- PB-03: Malicious Process and Network Activity Response

Hunt and playbook references are operational coverage, not additional verified detection technique IDs.

## 7. Limitations

- YAML mappings are based on explicit ATT&CK tags.
- Log Analyzer mappings are counted separately and require dedicated test evidence.
- Synthetic tests do not establish production effectiveness.
- Repeated technique tags across rules do not increase unique technique count.
- ATT&CK mappings do not guarantee detection in every environment.
- Correlation results indicate suspicious activity and do not independently prove credential extraction.
- The 20+ unique technique target has not yet been achieved.

## 8. Validation

Technique IDs and names should be checked against the official MITRE ATT&CK Enterprise knowledge base before final submission.

Official reference: https://attack.mitre.org/
