# PB-01 - LSASS Credential Dumping Incident Response

## 1. Purpose
Provide a response procedure for suspected LSASS memory access and credential-dumping activity.

## 2. Trigger conditions
- Sysmon Event ID 10 shows suspicious access to lsass.exe.
- Sysmon Event ID 11 shows suspicious dump-file creation.
- Detection correlation identifies LSASS access and dump creation by the same process GUID within 60 seconds.
- Suspicious tools such as ProcDump or Dumpert are observed.

## 3. Initial triage
1. Record hostname, timestamp, username and process GUID.
2. Identify the source process, executable path and command line.
3. Review related Event IDs 1, 10 and 11.
4. Check whether the activity is associated with approved administrative or security software.
5. Preserve relevant logs and evidence.

## 4. Containment
1. Escalate confirmed suspicious activity to the incident response lead.
2. Isolate the affected endpoint using approved EDR procedures when malicious activity is confirmed or containment is authorized.
3. Do not delete suspicious files before evidence preservation.
4. Restrict compromised accounts if credential exposure is suspected.

## 5. Investigation
1. Collect executable hashes and digital signatures.
2. Examine dump-file metadata and preserve the original evidence.
3. Review process ancestry and command-line arguments.
4. Search other endpoints for matching process names, hashes and behavior.
5. Determine whether credentials may have been exposed.

## 6. Eradication and recovery
1. Remove confirmed malicious tools and persistence mechanisms.
2. Reset potentially exposed credentials according to organizational policy.
3. Restore endpoint security controls.
4. Reconnect the endpoint only after validation and authorization.

## 7. Validation
- Confirm suspicious processes are no longer active.
- Confirm unauthorized dump files and tools are addressed.
- Verify endpoint monitoring is operational.
- Monitor for repeated LSASS access activity.

## 8. Evidence to retain
- Security and Sysmon event logs
- Process details and command lines
- File hashes and metadata
- Relevant dump-file evidence
- Incident timeline and response actions

## 9. Closure criteria
Close the incident after investigation, containment, eradication and recovery have been documented and approved.

## 10. References
MITRE ATT&CK: T1003.001 - OS Credential Dumping: LSASS Memory

Note: Perform isolation, credential resets and evidence collection only under authorized incident response procedures.
