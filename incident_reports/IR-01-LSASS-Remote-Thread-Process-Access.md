# Incident Investigation Report IR-01
## LSASS Remote Thread Creation and Process Access

### 1. Case Information
- Case ID: IR-01
- Incident Type: Suspicious LSASS Process Activity
- Data Source: EVTX-ATTACK-SAMPLES dataset
- Host: IEWIN7
- Source EVTX: CA_sysmon_hashdump_cmd_meterpreter.evtx
- ATT&CK: T1003.001 - OS Credential Dumping: LSASS Memory
- Investigation Status: Dataset-based investigation

### 2. Detection Summary
The investigation identified remote thread creation targeting LSASS followed by LSASS process access from the same source process.

### 3. Evidence
- Unique Event ID 8 LSASS records: 2
- Event ID 10 LSASS records: 26
- GUID-matched event pairs: 1
- Correlated pairs within 60 seconds: 1
- Host: IEWIN7
- Source process: \\VBOXSVR\HTools\voice_mail.msg.exe
- Source Process GUID: {365abb72-4055-5cc8-0000-0010769d0b00}
- Event timestamps: 2019-04-30 12:43:43.784
- Time difference: 0 seconds

### 4. Investigation Analysis
Event ID 8 and Event ID 10 records were correlated using the source process GUID and host. One matching pair was identified within the 60-second investigation window.

The observed behavior is suspicious because remote thread creation and subsequent LSASS access can be associated with credential-dumping activity.

### 5. MITRE ATT&CK Mapping
- Tactic: Credential Access
- Technique: T1003.001 - OS Credential Dumping: LSASS Memory

### 6. Recommended Response
1. Preserve relevant Sysmon and Windows event logs.
2. Investigate the source executable and its origin.
3. Review process ancestry and related network activity.
4. Check endpoint security telemetry for additional LSASS access.
5. Escalate for forensic investigation if malicious activity is confirmed.

### 7. Conclusion
One correlated LSASS activity pair was identified in the supplied dataset. This is suspicious behavior requiring investigation. The correlation does not prove that credentials were successfully extracted or that the executable was malicious.
