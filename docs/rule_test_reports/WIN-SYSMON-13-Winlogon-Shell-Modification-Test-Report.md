# Rule 15 - Suspicious Winlogon Shell Modification
## Offline Dataset Test Report

### Rule details
- Rule file: `WIN-SYSMON-13-Winlogon-Shell-Modification.yml`
- Rule name: `suspicious_winlogon_shell_modification`
- Event source: Sysmon Event ID 13 - Registry value set
- Detection: Winlogon Shell registry modification with an AppData Roaming path
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
- Matching events: 1
- Unique process GUIDs: 1

### Observed matching event
- Timestamp: `2019-06-14 22:22:21.519`
- Modifying process: `C:\Users\IEUser\Downloads\a.exe`
- Registry target: `HKU\...\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`
- Shell value: Executable under the user's `AppData\Roaming` directory, followed by `explorer.exe`
- Process GUID: `{365abb72-1e19-5d04-0000-0010dfc60a00}`
- Scenario: `sysmon_13_1_persistence_via_winlogon_shell.evtx`
- Dataset tactic label: Persistence

### Assessment
**PARTIALLY VALIDATED - EXPERIMENTAL**

The rule matched one Winlogon Shell modification in the supplied attack-sample dataset. The observed value referenced an executable under the user's AppData Roaming directory, which is suspicious in this scenario and may indicate persistence.

The test does not establish a benign false-positive rate because the dataset is an attack-sample collection and no representative benign baseline was evaluated. One match is not sufficient to establish broad detection coverage.

### Limitations
- Only one matching event was observed in this dataset.
- No benign baseline or production telemetry was tested.
- No live Windows endpoint or SIEM backend validation was performed.
- The registry modification alone does not prove successful execution or persistence.

### Recommended follow-up
Test against representative benign Winlogon configuration changes and additional attack samples before considering production deployment.
