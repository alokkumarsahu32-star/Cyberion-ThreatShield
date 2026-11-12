# Rule Test Report: LSASS Remote Thread Creation Followed by Process Access

## 1. Rule Information

- Rule ID: 5b9e2c71-4a83-46d0-9f12-7c5a3e8b1046
- Rule Name: lsass_remote_thread_and_process_access
- Rule Title: LSASS Remote Thread Creation Followed by Process Access
- Rule File: WIN-SYSMON-CORR-003-LSASS-Remote-Thread-Process-Access.yml
- Correlation Type: temporal
- Base Rules:
  - lsass_remote_thread_creation
  - lsass_process_access
- Group By: process_guid
- Timespan: 60 seconds
- Severity: High
- Status: Experimental
- ATT&CK Technique: T1003.001 - LSASS Memory

## 2. Validation Results

| Validation | Result |
|---|---|
| YAML syntax parsing | PASS |
| UUID validation | PASS |
| Correlation field inspection | PASS |
| pySigma collection loading | PASS |
| Rule 13 found in collection | PASS |
| Both base-rule references resolved | PASS |
| Offline dataset correlation test | PASS - 1 pair |

The complete detection rules directory contained 14 YAML files during collection validation.

## 3. Dataset Overview

- Dataset: EVTX-ATTACK-SAMPLES/evtx_data.csv
- Total dataset records: 4,633
- Event ID 8 records: 101
- Event ID 8 records targeting LSASS: 3
- Unique Event ID 8 source process GUIDs: 2
- Event ID 10 records targeting LSASS: 25
- Unique Event ID 8 LSASS matches after deduplication: 2

## 4. Correlation Results

The offline test joined Event ID 8 and Event ID 10 records using the source process GUID and retained pairs with an absolute timestamp difference of 60 seconds or less.

- Correlation pairs within 60 seconds: 1
- Unique correlated source process GUIDs: 1
- Time difference: 0 seconds
- Source process: \\VBOXSVR\HTools\voice_mail.msg.exe
- Source process GUID: {365abb72-4055-5cc8-0000-0010769d0b00}
- Scenario: CA_sysmon_hashdump_cmd_meterpreter.evtx

The second unique Event ID 8 source process, rdrleakdiag.exe, did not produce a matching Event ID 10 LSASS-access event in the tested dataset.

## 5. Analysis

The dataset contains one process-level correlation in which a process created a remote thread targeting LSASS and also accessed LSASS within the configured 60-second window.

The matching events have identical timestamps and belong to the same EVTX scenario. This supports the intended correlation logic for this observed case.

The Event ID 8 base rule identified two unique source process GUIDs after duplicate removal. Only one of these produced a matching Event ID 10 event within the correlation window.

## 6. False Positives and Limitations

Potential legitimate activity includes:

- Authorized debugging and forensic activity.
- Legitimate endpoint security or diagnostic tools.
- Approved credential auditing and security testing.

Limitations:

- The dataset produced only one unique correlated source process.
- The observed correlation does not independently prove credential extraction or successful credential dumping.
- No representative benign baseline was available for false-positive-rate measurement.
- Offline pandas correlation testing does not demonstrate execution in a live SIEM.
- Backend conversion and live Windows endpoint validation have not been performed.

## 7. Final Assessment

**Status: PARTIALLY VALIDATED - EXPERIMENTAL**

YAML parsing, UUID validation, pySigma collection loading, base-rule reference resolution, and offline dataset correlation testing passed.

One matching process-level correlation was observed in the supplied dataset. Further validation using benign endpoint telemetry and a live SIEM or supported correlation backend is required before production deployment.
