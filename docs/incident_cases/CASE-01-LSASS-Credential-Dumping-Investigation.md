# CASE-01: LSASS Credential Dumping Activity Investigation

**Project:** Cyberion ThreatShield  
**Case ID:** CASE-01  
**Case Type:** Dataset-Based Investigation Case Study  
**Investigation Status:** Completed — Offline Dataset Analysis  
**Severity:** High (Analytical Priority; Not a Confirmed Incident)  
**MITRE ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory  
**Data Source:** EVTX-ATTACK-SAMPLES  
**Dataset:** datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv  
**Investigation Date:** 2026-11-11

## 1. Executive Summary

This investigation examines suspicious process activity involving access to the Windows Local Security Authority Subsystem Service (LSASS), followed by the creation of .dmp files.

Three experimental detection rules were evaluated using the EVTX-ATTACK-SAMPLES dataset. Offline analysis identified LSASS access candidates, dump-file creation events, and process-level correlations within a configured 60-second window.

The correlation analysis identified 16 matching event pairs representing six unique process-level correlations.

The findings are consistent with credential-dumping activity in selected attack-simulation scenarios. They do not establish six independently confirmed attacks or prove that every dump file contains LSASS memory.

**Final assessment:** Suspicious activity patterns were identified. Further investigation and live endpoint validation are required before making a real-world incident determination.

## 2. Investigation Objective

Determine whether processes accessing LSASS also created .dmp files within 60 seconds, using process GUID and host context to correlate events.

Objectives:
- Identify suspicious LSASS process-access activity.
- Identify dump-file creation events.
- Correlate both event types using process GUID and computer name.
- Review observed process and file-path combinations.
- Recommend appropriate investigation and response actions.

## 3. Detection Evidence

### 3.1 LSASS Process Access

Supporting rule: WIN-SYSMON-10-Suspicious-LSASS-Access.yml

- Event source: Windows Sysmon
- Event ID: 10 — Process Access
- Total dataset records: 4,633
- Event ID 10 records: 140
- Events targeting LSASS: 26
- Candidate matches: 12
- Unique source process paths: 8
- Dataset scenarios with matches: 6

The rule evaluated LSASS access events where the source process path contained known tool-name indicators such as Mimikatz, ProcDump, PPLdump, Dumpert, or AndrewSpecial.

### 3.2 Dump-File Creation

Supporting rule: WIN-SYSMON-11-LSASS-Dump-File-Creation.yml

- Event source: Windows Sysmon
- Event ID: 11 — File Create
- Event ID 11 records: 185
- Matching .dmp events: 8
- Unique EVTX scenarios: 4

Observed processes included:
- services.exe
- procdump.exe
- taskmgr.exe
- Outflank-Dumpert.exe
- rundll32.exe
- AndrewSpecial.exe
- rdrleakdiag.exe

A .dmp extension alone does not establish that a file contains LSASS memory.

### 3.3 Correlation Evidence

Correlation rule: WIN-SYSMON-CORR-002-LSASS-Access-Dump-Creation.yml

Correlation configuration:
- Event A: Sysmon Event ID 10 — LSASS access
- Event B: Sysmon Event ID 11 — .dmp file creation
- Grouping fields: Process GUID and Computer
- Dataset scenario context: EVTX filename
- Correlation type: Temporal, unordered
- Time window: 60 seconds

Offline analysis results:

| Measurement | Result |
|---|---:|
| LSASS access events selected | 26 |
| .dmp creation events selected | 8 |
| Matching event pairs | 16 |
| Unique process-level correlations | 6 |

The 16 matching pairs represent repeated event combinations and must not be interpreted as 16 independent incidents.

## 4. Process-Level Findings

| Process | Observed dump file |
|---|---|
| services.exe | C:\Users\IEUser\Desktop\lsass.dmp |
| procdump.exe | C:\Users\IEUser\Desktop\lsass.exe_190317_120941.dmp |
| taskmgr.exe | C:\Users\IEUser\AppData\Local\Temp\lsass (2).DMP |
| Outflank-Dumpert.exe | C:\Windows\Temp\dumpert.dmp |
| rundll32.exe | C:\Windows\Temp\dumpert.dmp |
| AndrewSpecial.exe | C:\Users\administrator\Desktop\Andrew.dmp |

These are dataset observations. They do not independently prove malicious intent, successful credential extraction, or the contents of each dump file.

## 5. Investigation and Analysis

The investigation combined three evidence sources:
1. Known credential-dumping tool-name indicators associated with LSASS access.
2. File-creation events involving .dmp extensions.
3. Temporal correlation between LSASS access and dump creation.

The correlation test used Python and pandas to select events, normalize process GUID values, join records using EVTX scenario, computer and process GUID, calculate timestamp differences, and retain matching pairs within 60 seconds.

Six unique process-level combinations were identified.

The services.exe and taskmgr.exe observations require additional context because legitimate system diagnostics and authorized troubleshooting can also produce suspicious-looking activity.

## 6. Severity Assessment

**Analytical priority: High**

Rationale:
- LSASS is a sensitive Windows process involved in authentication.
- Process access followed by dump-file creation can be consistent with credential-dumping behavior.
- The observed patterns warrant investigation in an actual endpoint environment.

This is an investigation-priority assessment, not a confirmed incident severity assigned by a live SOC.

## 7. Recommended Response Actions

The following actions are recommendations only. No live endpoint response was performed during this dataset investigation.

### Immediate Investigation
1. Retrieve original Sysmon Event ID 10 and Event ID 11 records.
2. Validate process GUID, host, timestamps, user account, and parent process.
3. Inspect command lines, executable paths, hashes, and digital signatures.
4. Determine whether observed dump files contain LSASS memory.
5. Check for related authentication anomalies and suspicious outbound activity.

### Containment — If Confirmed in a Live Environment
1. Follow the organization's incident-response approval process.
2. Isolate the affected endpoint if malicious activity is confirmed and containment is authorized.
3. Preserve relevant logs and forensic evidence.
4. Consider credential-reset procedures according to organizational security policy.
5. Escalate findings to the incident-response team.

**Action status:** Recommended; not executed.

## 8. False Positive Considerations

Potential legitimate explanations include:
- Authorized forensic investigations.
- Approved penetration testing.
- Legitimate Sysinternals ProcDump usage.
- Task Manager diagnostic dump generation.
- Authorized endpoint-security or troubleshooting activity.

Analysts should verify user authorization, process context, command line, file path, signature, and surrounding telemetry before classifying an event as malicious.

## 9. Limitations

- The dataset is attack-simulation oriented.
- No separate benign enterprise baseline was available.
- Filename-based detection may miss renamed or unknown tools.
- A .dmp extension does not prove LSASS memory content.
- Dataset scenario labels are not independent ground truth.
- Repeated event pairs can inflate raw correlation counts.
- No production SIEM correlation backend was executed.
- No live Windows endpoint testing was performed.
- No real containment or remediation action was executed.
- Detection rules remain experimental.

## 10. Evidence and Validation Status

| Evidence / Validation | Status |
|---|---|
| LSASS access rule YAML parsing | PASS |
| LSASS access rule pySigma loading | PASS |
| LSASS access dataset-equivalent test | PASS |
| Dump-file rule YAML parsing | PASS |
| Dump-file rule pySigma loading | PASS |
| Dump-file dataset analysis | PASS |
| Correlation dataset analysis | PASS |
| Production SIEM execution | NOT TESTED |
| Live endpoint validation | NOT TESTED |
| Benign enterprise baseline | NOT AVAILABLE |

## 11. Final Conclusion

The offline investigation identified suspicious LSASS access and dump-file creation patterns in the EVTX-ATTACK-SAMPLES dataset.

The correlation analysis identified 16 matching event pairs representing six unique process-level correlations within the configured 60-second window.

These results demonstrate the feasibility of correlating LSASS access with dump-file creation using process and host context. They do not establish six confirmed real-world attacks or successful credential theft.

**Case disposition:** Dataset-Based Investigation Completed — Further Live Validation Required.

**Related ATT&CK technique:** T1003.001 — OS Credential Dumping: LSASS Memory.

**Related threat-hunting reports:** HUNT-01 and HUNT-02.
