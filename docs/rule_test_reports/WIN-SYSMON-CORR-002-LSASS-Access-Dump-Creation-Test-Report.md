# Rule Test Report: LSASS Access and Dump File Creation Correlation

## 1. Rule Information

- Correlation rule: WIN-SYSMON-CORR-002-LSASS-Access-Dump-Creation.yml
- Supporting rule A: WIN-SYSMON-10-LSASS-Process-Access.yml
- Supporting rule B: WIN-SYSMON-11-LSASS-Dump-File-Creation.yml
- MITRE ATT&CK mapping: T1003.001 - OS Credential Dumping: LSASS Memory
- Rule status: Experimental
- Correlation type: temporal (unordered)
- Configured time window: 60 seconds
- Grouping: Process GUID and Computer

## 2. Objective

Identify process-level activity where a process accesses LSASS and creates a file with a .dmp extension within 60 seconds.

The correlation uses the process GUID to associate Sysmon Event ID 10 and Event ID 11 records.

## 3. Dataset and Method

Dataset: EVTX-ATTACK-SAMPLES
Input file: datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv

The test used Python and pandas to:

1. Select Event ID 10 records targeting lsass.exe.
2. Select Event ID 11 records creating files ending in .dmp.
3. Normalize process GUID values.
4. Join records using EVTX_FileName, Computer and process GUID.
5. Calculate the absolute timestamp difference.
6. Retain matching pairs within 60 seconds.
7. Count unique process-level correlations.

This is an offline dataset validation, not a live SIEM execution.

## 4. Test Results

| Measurement | Result |
|---|---:|
| Total dataset records | 4,633 |
| LSASS access events selected | 26 |
| .dmp file creation events selected | 8 |
| Matching event pairs within 60 seconds | 16 |
| Unique process-level correlations | 6 |

The 16 matching pairs are not 16 independent incidents. Repeated Event ID 10 records produced multiple pairs for the same process GUID and dump file.

## 5. Process-Level Findings

| Process | Observed dump file |
|---|---|
| services.exe | C:\Users\IEUser\Desktop\lsass.dmp |
| procdump.exe | C:\Users\IEUser\Desktop\lsass.exe_190317_120941.dmp |
| taskmgr.exe | C:\Users\IEUser\AppData\Local\Temp\lsass (2).DMP |
| Outflank-Dumpert.exe | C:\Windows\Temp\dumpert.dmp |
| rundll32.exe | C:\Windows\Temp\dumpert.dmp |
| AndrewSpecial.exe | C:\Users\administrator\Desktop\Andrew.dmp |

All six process-level correlations were observed within the configured 60-second window.

## 6. Interpretation

The dataset contains six distinct process-level combinations of LSASS access and .dmp file creation.

The observed process and file combinations are consistent with LSASS memory-dumping activity in the selected attack-simulation scenarios.

However, a .dmp extension alone does not prove that the file contains LSASS memory. The correlation also does not establish whether the activity was authorized or malicious in a real environment.

The services.exe observation must be interpreted using its surrounding process and scenario context; the process name alone is not sufficient to attribute the activity to a particular dumping tool.

## 7. False Positives and Limitations

Potential benign explanations include:

- Task Manager creating an authorized diagnostic dump.
- Approved endpoint security or forensic software accessing LSASS.
- Authorized troubleshooting and credential auditing.
- Other legitimate applications creating dump files.

Limitations:

- No independent benign enterprise baseline was available.
- The dataset is attack-simulation oriented.
- Repeated events can generate multiple event pairs.
- The .dmp extension does not validate file contents.
- No production SIEM or correlation backend execution was performed.
- Dataset scenario labels are not independent ground truth.

## 8. Tuning Considerations

Possible future improvements:

- Add process signer and hash reputation context.
- Enrich alerts with process command line and parent process.
- Validate dump file content or use additional forensic indicators where available.
- Apply allowlisting only to verified, approved diagnostic tools and workflows.
- Deduplicate repeated event pairs into one process-level alert.

Do not broadly exclude Task Manager or services.exe without environment-specific validation.

## 9. Conclusion

The offline test identified 16 matching event pairs representing six unique process-level correlations.

The result supports the feasibility of correlating LSASS access with dump-file creation using process GUID and host context.

The rule remains experimental. The findings demonstrate dataset matches, not six independently confirmed real-world attacks or a measured production detection rate.
