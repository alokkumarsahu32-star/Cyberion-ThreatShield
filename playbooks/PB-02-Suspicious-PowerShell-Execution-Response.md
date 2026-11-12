# PB-02 - Suspicious PowerShell Execution Response

## 1. Purpose
Provide a response procedure for suspicious or potentially malicious PowerShell execution.

## 2. Trigger conditions
- Encoded PowerShell commands are detected.
- Execution policy bypass arguments are observed.
- PowerShell loads suspicious credential-related DLLs.
- Unexpected PowerShell network connections are detected.

## 3. Initial triage
1. Record hostname, timestamp, username and process GUID.
2. Collect PowerShell command line and parent process details.
3. Review Sysmon Event IDs 1, 3 and 7.
4. Review PowerShell operational logs, if available.
5. Determine whether the activity is authorized administration.

## 4. Containment
1. Escalate confirmed suspicious activity.
2. Isolate the endpoint when authorized and necessary.
3. Restrict suspicious scripts and associated accounts according to policy.
4. Preserve scripts, logs and related evidence before removal.

## 5. Investigation
1. Decode encoded commands safely in an isolated analysis environment.
2. Examine script content and execution arguments.
3. Review process ancestry and subsequent child processes.
4. Identify network destinations and related DNS activity.
5. Search other endpoints for matching command patterns and hashes.

## 6. Eradication and recovery
1. Remove confirmed malicious scripts and persistence.
2. Revoke compromised credentials where necessary.
3. Restore approved PowerShell security settings.
4. Verify endpoint security controls and logging.

## 7. Validation
- Confirm suspicious scripts and processes are no longer active.
- Confirm unauthorized network activity has stopped.
- Verify PowerShell logging and endpoint monitoring.
- Monitor for repeated suspicious command execution.

## 8. Evidence to retain
- PowerShell command lines and scripts
- Sysmon and PowerShell event logs
- Process ancestry
- Network indicators
- File hashes and incident timeline

## 9. Closure criteria
Close after investigation, containment, eradication and recovery are documented and approved.

## 10. References
MITRE ATT&CK:
- T1059.001 - Command and Scripting Interpreter: PowerShell

Note: Response actions must follow authorized organizational procedures.
