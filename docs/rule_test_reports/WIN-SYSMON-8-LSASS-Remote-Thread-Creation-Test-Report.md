# Rule 13 - Remote Thread Creation Targeting LSASS
## Offline Dataset Test Report

### Rule details
- Rule file: `WIN-SYSMON-8-LSASS-Remote-Thread-Creation.yml`
- Rule name: `lsass_remote_thread_creation`
- Event source: Sysmon Event ID 8 - CreateRemoteThread
- Detection: Remote thread creation where TargetImage ends with `\lsass.exe`
- Severity: High
- Status: Experimental

### Validation results
| Validation | Result |
|---|---|
| YAML parsing | PASS |
| UUID validation | PASS |
| pySigma structural load | PASS |
| Offline dataset test | PASS |

### Dataset test
- Dataset: `EVTX-ATTACK-SAMPLES/evtx_data.csv`
- Total records: 4,633
- Event ID 8 records: 101
- LSASS-targeting records before deduplication: 3
- Unique matching events after deduplication: 2
- Unique source Process GUIDs: 2
- Matching scenarios: 2

### Observed matching scenarios

1. `CA_sysmon_hashdump_cmd_meterpreter.evtx`
   - Source process: `voice_mail.msg.exe`
   - Source Process GUID: `{365abb72-4055-5cc8-0000-0010769d0b00}`
   - Two duplicate dataset rows represent one unique event.
   - Timestamp: `2019-04-30 12:43:43.784`

2. `sysmon_rdrleakdiag_lsass_dump.evtx`
   - Source process: `rdrleakdiag.exe`
   - Source Process GUID: `{bc47d85c-db68-5f71-0000-0010b237ab01}`
   - Timestamp: `2020-09-28 12:47:36.204`

### Assessment
**PARTIALLY VALIDATED - EXPERIMENTAL**

The rule matched two unique LSASS-targeting remote thread creation events across two attack-sample scenarios. One event appeared twice in the dataset and was counted only once after deduplication.

The matches demonstrate that the selection logic identifies the observed LSASS-targeting remote thread events in this dataset. They do not independently establish successful credential extraction or malicious intent.

### False Positive Considerations
- Authorized debugging and forensic tools.
- Endpoint detection and response products.
- Approved security testing and diagnostics.

### Limitations
- The dataset is an attack-sample collection, not a representative benign baseline.
- No false-positive rate has been measured.
- No live Windows endpoint or production SIEM backend validation was performed.
- Remote thread creation targeting LSASS does not by itself prove credential dumping.
- This base rule is also used as a building block for CORR-003.

### Recommended follow-up
Evaluate against benign endpoint telemetry and additional LSASS remote-thread attack samples before production deployment.
