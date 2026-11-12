# HUNT-02 - LSASS Access Correlated with Dump File Creation

## Objective
Investigate whether processes accessing LSASS also create `.dmp` files within a 60-second window, using matching process GUIDs and hostnames.

## Data source
- Dataset: `datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv`
- Event ID 10: Process access targeting `lsass.exe`
- Event ID 11: `.dmp` file creation
- Correlation keys: `Computer` and process GUID
- Event 10 GUID: `SourceProcessGUID`
- Event 11 GUID: `ProcessGuid`
- Time window: 60 seconds

## Test methodology
1. Filter Event ID 10 records where TargetImage ends with `lsass.exe`.
2. Filter Event ID 11 records where TargetFilename ends with `.dmp`.
3. Match records using hostname and process GUID.
4. Calculate timestamp difference between matching events.
5. Retain pairs whose absolute time difference is 60 seconds or less.

## Results
- GUID-matched event pairs: 16
- Correlated pairs within 60 seconds: 16
- Unique correlated process GUIDs observed: 5
- Hosts observed: 3
- Observed time differences: approximately -0.472 to +0.473 seconds.

## Notable observations
- MSEDGEWIN10: `services.exe` associated with `lsass.dmp`.
- PC04.example.corp: `procdump.exe` and `taskmgr.exe` associated with LSASS-named dump files.
- alice.insecurebank.local: `Outflank-Dumpert.exe`, `rundll32.exe`, and `AndrewSpecial.exe` associated with dump-file creation.
- Multiple Event 10 records can correlate with the same Event 11 record; therefore, 16 pairs must not be interpreted as 16 unique incidents.

## Assessment
The offline dataset test successfully identified process-level correlations between LSASS access and dump-file creation within the configured 60-second window.

These results support further investigation of potential credential-dumping activity. Event correlation alone does not prove that every `.dmp` file contains LSASS memory or that credentials were successfully extracted.

## MITRE ATT&CK
- T1003.001 - OS Credential Dumping: LSASS Memory

## Limitations
- Results depend on the available Sysmon telemetry.
- Duplicate event-pair matches can increase the correlation count.
- File creation telemetry alone does not verify dump-file contents.
- No claim of successful credential extraction is made.

## Conclusion
HUNT-02: PASS.

The dataset contains 16 correlated event pairs within the 60-second window. The findings provide evidence of suspicious process-level LSASS access and dump-file creation activity, requiring contextual investigation before confirming an incident.
