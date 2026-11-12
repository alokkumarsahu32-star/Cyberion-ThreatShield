# Rule Tuning Review 01: LSASS Access and Dump File Creation

## 1. Rule Information

- Rule ID: 2e6a9c41-7b35-4d80-a1f2-5c8e3b9d6047
- Rule: WIN-SYSMON-CORR-002-LSASS-Access-Dump-Creation
- MITRE ATT&CK: T1003.001 - OS Credential Dumping: LSASS Memory
- Current status: Experimental

## 2. Existing Detection Logic

The correlation identifies:
- Sysmon Event ID 10 where TargetImage is lsass.exe.
- Sysmon Event ID 11 where TargetFilename ends with .dmp.
- Matching process GUID and Computer.
- Both events occurring within 60 seconds, without requiring a specific order.

## 3. False-Positive Scenario

Task Manager (taskmgr.exe) can legitimately create diagnostic process dumps during authorized troubleshooting.

The dataset contains a process-level correlation involving taskmgr.exe and:
C:\Users\IEUser\AppData\Local\Temp\lsass (2).DMP

This is a candidate false-positive scenario, not a confirmed benign event. The dataset does not establish whether the activity was authorized.

## 4. Proposed Logic Change

Do not immediately exclude taskmgr.exe.

For a production environment, consider adding contextual enrichment:
- Verify the process signer and executable hash.
- Check whether the activity was initiated by an approved administrator.
- Check for an approved troubleshooting or forensic ticket.
- Review parent process and command-line context.
- Allowlist only verified and approved workflows.

No exclusion has been added to the current Sigma rule.

## 5. Expected Trade-off

Potential benefit:
- Better separation of authorized diagnostic activity from suspicious LSASS dumping.

Potential risk:
- Broad exclusions for taskmgr.exe or other legitimate utilities could allow attackers to abuse those same tools without generating an alert.

## 6. Tuning Decision

Decision: Retain the current detection logic.

Reason:
The available dataset does not provide sufficient evidence to define a safe process-wide exclusion. Contextual enrichment is preferred over a broad allowlist.

## 7. Validation Status

- Dataset correlation test: Completed.
- False-positive scenario identified: Yes, candidate only.
- Logic change implemented: No.
- Post-tuning retest: Not applicable because no logic change was implemented.
- Production validation: Not performed.

## 8. Conclusion

This review documents a realistic potential false-positive scenario and a proposed tuning approach. The rule remains experimental until validated against an environment-specific benign baseline.
