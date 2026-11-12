# Incident Investigation Report IR-02
## LSASS Process Access Correlated with Dump File Creation

### 1. Case Information
- Case ID: IR-02
- Incident Type: Potential LSASS Credential Dump Activity
- Data Source: EVTX-ATTACK-SAMPLES dataset
- Detection Rule: WIN-SYSMON-CORR-002
- Correlation Window: 60 seconds
- ATT&CK: T1003.001 - OS Credential Dumping: LSASS Memory
- Investigation Status: Dataset-based investigation

### 2. Detection Summary
The investigation correlated Sysmon Event ID 10 LSASS process access with Event ID 11 file creation activity using the same process GUID and host within a 60-second window.

### 3. Evidence
- LSASS Event ID 10 records: 26
- Dump file creation Event ID 11 records: 8
- GUID-matched pairs: 16
- Correlated pairs within 60 seconds: 16
- Unique correlated process GUIDs: 5
- Observed hosts:
  - MSEDGEWIN10
  - PC04.example.corp
  - alice.insecurebank.local
- Observed process names:
  - services.exe
  - procdump.exe
  - taskmgr.exe
  - Outflank-Dumpert.exe
  - rundll32.exe
  - AndrewSpecial.exe

### 4. Investigation Analysis
The correlation identified LSASS process access and file creation events associated with matching process GUIDs within the configured time window.

The 16 correlated pairs do not represent 16 unique incidents. Multiple Event ID 10 records can correlate with the same Event ID 11 record.

Some observed tools and processes may be legitimate in authorized administrative, diagnostic, or forensic contexts. Contextual investigation is required.

### 5. MITRE ATT&CK Mapping
- Tactic: Credential Access
- Technique: T1003.001 - OS Credential Dumping: LSASS Memory

### 6. Recommended Response
1. Preserve relevant event logs and file metadata.
2. Identify the executable responsible for the correlated events.
3. Validate dump file paths, hashes, signatures, and ownership.
4. Review process ancestry and user context.
5. Investigate whether the activity was authorized.
6. Escalate confirmed malicious activity for containment and forensic analysis.

### 7. Conclusion
Sixteen correlated event pairs across five unique process GUIDs were identified in the supplied dataset. The results indicate suspicious LSASS-related activity requiring contextual investigation. Event correlation alone does not establish that a dump file contains LSASS memory or that credentials were extracted.
