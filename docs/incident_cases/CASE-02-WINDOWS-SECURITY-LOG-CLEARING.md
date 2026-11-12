\# CASE-02: Windows Security Audit Log Clearing Investigation



\*\*Project:\*\* Cyberion ThreatShield  

\*\*Case ID:\*\* CASE-02  

\*\*Case Type:\*\* Dataset-Based Investigation Case Study  

\*\*Investigation Status:\*\* Completed — Offline Dataset Analysis  

\*\*Severity:\*\* Medium (Analytical Priority; Not a Confirmed Incident)  

\*\*MITRE ATT\&CK:\*\* T1070.001 — Clear Windows Event Logs (Provisional Mapping)  

\*\*Data Source:\*\* EVTX-ATTACK-SAMPLES  

\*\*Dataset:\*\* `datasets/raw/EVTX-ATTACK-SAMPLES/evtx\_data.csv`  

\*\*Investigation Date:\*\* 2026-11-11  



\---



\## 1. Executive Summary



This investigation examines Windows Security Event ID 1102, which records that the Windows Security audit log was cleared.



The experimental detection rule was evaluated against the EVTX-ATTACK-SAMPLES dataset. The offline analysis identified 21 Event ID 1102 records across 21 source EVTX files. All 21 records matched the equivalent Python selection condition.



Clearing the Security audit log may be associated with defense-evasion activity, but the event alone does not establish malicious intent. Authorized maintenance, system administration, troubleshooting, and incident-response activities may also explain the event.



\*\*Final assessment:\*\* The dataset analysis successfully identified all observed Event ID 1102 records. Additional contextual investigation is required before classifying any individual occurrence as malicious.



\## 2. Investigation Objective



Investigate Windows Security audit-log clearing activity and identify the contextual evidence required to determine whether the action was authorized or suspicious.



Objectives:



\- Identify Event ID 1102 records.

\- Review available account and host context.

\- Examine dataset scenario distribution.

\- Identify relevant surrounding telemetry for follow-up.

\- Recommend appropriate investigation and response actions.



\## 3. Detection Evidence



\*\*Detection rule:\*\* `WIN-SEC-1102-Security-Log-Cleared-Test-Report.md`



\- Event source: Windows Security

\- Event ID: 1102

\- Detection condition: Event ID equals 1102

\- Total dataset records inspected: 4,633

\- Event ID 1102 records: 21

\- Unique source files: 21

\- Matching records: 21

\- Match coverage of observed Event ID 1102 records: 100%



The detection condition identifies the audit-log clearing event. Account and host information are retained as investigation context and are not mandatory matching conditions.



\## 4. Dataset Findings



The 21 matching records were distributed across 21 source EVTX files.



\### Dataset Scenario-Label Distribution



| Dataset scenario label | Records |

|---|---:|

| Credential Access | 5 |

| Lateral Movement | 5 |

| Discovery | 3 |

| Privilege Escalation | 3 |

| Defense Evasion | 2 |

| Persistence | 2 |

| Command and Control | 1 |

| \*\*Total\*\* | \*\*21\*\* |



These are dataset scenario labels, not independently verified ATT\&CK technique classifications or confirmed malicious outcomes.



\## 5. Available Event Context



The inspected dataset records contain the following fields:



\- `SystemTime`

\- `Computer`

\- `ProviderName`

\- `SubjectUserName`

\- `SubjectDomainName`

\- `SubjectLogonId`

\- `SubjectUserSid`

\- `EVTX\_FileName`

\- `EVTX\_Tactic`



The account fields use XML namespace-prefixed column names in the source CSV. The test script handled those names to extract populated values.



\*\*Evidence limitation:\*\* This report contains aggregate dataset findings. It does not establish the identity of a particular real-world user or host responsible for malicious log clearing.



\## 6. Investigation and Analysis



Event ID 1102 provides an important audit-log clearing signal. However, determining intent requires additional context.



A live SOC investigation should correlate:



1\. The event timestamp and hostname.

2\. The initiating username, domain, SID, and Logon ID.

3\. Nearby Security and System events.

4\. Account modifications and privilege changes.

5\. Remote logons and suspicious administrative activity.

6\. Approved maintenance or incident-response records.



The dataset analysis verified the equivalent Event ID selection condition. It did not perform a complete investigation of every event's surrounding telemetry.



\## 7. Severity Assessment



\*\*Analytical priority: Medium\*\*



Rationale:



\- Clearing the Windows Security audit log can reduce the availability of historical audit evidence.

\- The event may be relevant to defense-evasion investigations.

\- The event alone does not establish malicious intent or attacker attribution.



This is an investigation-priority assessment, not a confirmed incident severity assigned by a live SOC.



\## 8. Recommended Response Actions



The following actions are recommendations only. No live endpoint response was performed during this dataset investigation.



\### Immediate Investigation



1\. Record the hostname and event timestamp.

2\. Identify the initiating user, domain, SID, and Logon ID.

3\. Review nearby Security and System events.

4\. Check for suspicious account changes, privilege escalation, and remote access.

5\. Confirm whether approved maintenance or incident-response activity explains the event.

6\. Preserve available logs and evidence.



\### Containment — If Malicious Activity Is Confirmed



1\. Follow the organization's incident-response approval process.

2\. Investigate the affected account and endpoint.

3\. Isolate the endpoint if justified and authorized.

4\. Preserve available forensic evidence.

5\. Escalate to the incident-response team.

6\. Restore appropriate logging and monitoring under organizational policy.



\*\*Action status:\*\* Recommended; not executed.



\## 9. False Positive Considerations



Potential legitimate explanations include:



\- Authorized security-log maintenance.

\- Approved system administration.

\- Troubleshooting or system recovery.

\- Authorized incident response and forensic work.



Analysts should verify the initiating account, authorization, host role, maintenance records, and surrounding events before classifying the activity as malicious.



\## 10. Limitations



\- Event ID 1102 identifies a log-clearing event, not its reason.

\- The dataset does not establish whether the activity was malicious or authorized.

\- The dataset is scenario-oriented.

\- No representative benign enterprise baseline was available.

\- The ATT\&CK mapping remains provisional pending technique-level verification.

\- Dataset-based testing does not establish production SIEM compatibility.

\- The false-positive rate has not been quantified.

\- No live endpoint testing was performed.

\- No containment or remediation action was executed.



\## 11. Evidence and Validation Status



| Evidence / Validation | Status |

|---|---|

| YAML syntax validation | PASS |

| pySigma parsing | PASS |

| Event ID selection verification | PASS |

| Dataset equivalent-condition test | PASS |

| Observed Event ID 1102 matches | 21 |

| Production SIEM execution | NOT TESTED |

| Live endpoint validation | NOT TESTED |

| Benign enterprise baseline | NOT AVAILABLE |

| False-positive rate measurement | NOT AVAILABLE |



\## 12. Final Conclusion



The offline dataset analysis identified all 21 observed Windows Security Event ID 1102 records across 21 source EVTX files.



The detection rule successfully passed YAML validation, pySigma parsing, and dataset-equivalent-condition testing.



These findings demonstrate that the experimental rule can identify the observed log-clearing events in the selected dataset. They do not establish 21 confirmed security incidents or prove malicious intent.



\*\*Case disposition:\*\* Dataset-Based Investigation Completed — Further Contextual and Live Validation Required.



\*\*Related ATT\&CK technique:\*\* T1070.001 — Clear Windows Event Logs (Provisional Mapping).



