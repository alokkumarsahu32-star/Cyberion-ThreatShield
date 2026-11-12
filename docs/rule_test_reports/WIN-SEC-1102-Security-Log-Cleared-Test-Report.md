# Rule Test Report: Windows Security Audit Log Cleared

## 1. Rule Information

- Rule ID: 3a7d9c21-6f84-4b52-a190-8e2c5d7f6130
- Rule Name: windows_security_audit_log_cleared
- Title: Windows Security Audit Log Cleared
- Status: Experimental
- Severity: Medium
- Event ID: 1102
- Log Source: Windows Security
- Provisional ATT&CK Mapping: T1070.001 - Clear Windows Event Logs

## 2. Objective

Detect Windows Security Event ID 1102, which records that the Windows Security audit log was cleared.

The alert provides an investigation starting point. Analysts should examine the initiating account, host, logon session and surrounding events to determine whether the action was authorized.

## 3. Dataset

- Dataset: EVTX-ATTACK-SAMPLES
- Source: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- Analysis file: evtx_data.csv
- Total records inspected: 4,633
- Event ID 1102 records: 21
- Unique source files containing Event ID 1102: 21

## 4. Detection Logic

Sigma selection:

- EventID: 1102

Condition:

- selection

The rule uses Event ID as its detection condition. Account and host information are retained as investigation context rather than mandatory matching conditions.

## 5. Validation

- YAML syntax validation: Passed
- PySigma parsing: Passed
- Event ID selection verification: Passed
- Dataset equivalent-condition test: Passed
- Total matching records: 21
- Match coverage of observed Event ID 1102 records: 100%

Testing was performed using Python against the selected CSV dataset. This was not a production SIEM execution.

## 6. Dataset Findings

The 21 records were distributed across 21 source files.

EVTX_Tactic scenario-label distribution:

- Credential Access: 5
- Lateral Movement: 5
- Discovery: 3
- Privilege Escalation: 3
- Defense Evasion: 2
- Persistence: 2
- Command and Control: 1

These labels describe the dataset's scenario grouping. They do not independently establish the ATT&CK technique or maliciousness of each Event ID 1102 record.

## 7. Event Context

The inspected events contain:

- SystemTime
- Computer
- ProviderName
- SubjectUserName
- SubjectDomainName
- SubjectLogonId
- SubjectUserSid
- EVTX_FileName
- EVTX_Tactic

The account fields are stored under XML namespace-prefixed column names in the source CSV. The test script explicitly handled these names to extract the populated values.

## 8. False Positive Considerations

Potential legitimate causes include:

- Authorized security log maintenance.
- Approved system administration.
- Troubleshooting or system recovery.
- Authorized incident response and forensic work.

A separate benign baseline dataset was not available. Therefore, the false-positive rate has not been measured.

## 9. Investigation Recommendations

When this rule fires, analysts should:

1. Record the hostname and event timestamp.
2. Identify the initiating user, domain, SID and Logon ID.
3. Review nearby Security and System events.
4. Check for suspicious log clearing, account changes, privilege escalation or remote access activity.
5. Confirm whether an approved maintenance or incident response action explains the event.
6. Preserve available logs and evidence before further remediation.

## 10. Limitations

- Event ID 1102 identifies a log-clearing event, not the reason for it.
- The rule does not determine whether the action was malicious or authorized.
- The dataset is scenario-oriented and does not provide a representative benign baseline.
- The ATT&CK mapping remains provisional pending technique-level verification.
- Dataset-based testing does not establish production SIEM compatibility.
- The false-positive rate has not been quantified.

## 11. Conclusion

All 21 observed Event ID 1102 records matched the rule's equivalent Python condition.

YAML validation and PySigma parsing passed. The rule is retained as an experimental detection candidate for Windows Security audit-log clearing.

The 21 matches are detection observations, not 21 confirmed security incidents. Further contextual investigation and benign-baseline testing are required before production deployment.
