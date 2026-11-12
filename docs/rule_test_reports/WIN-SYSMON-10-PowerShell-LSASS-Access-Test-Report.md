# PowerShell Accessing LSASS — Test Report

## Rule Details
- **Rule title:** PowerShell Accessing LSASS
- **Rule ID:** 9f31a2b7-6d84-4c50-b219-8e7f3a5d6012
- **Rule name:** powershell_lsass_access
- **Severity:** high
- **Status:** experimental
- **Log source:** Windows / Process Access
- **Detection condition:** SourceImage ends with `\\powershell.exe` AND TargetImage ends with `\\lsass.exe`
- **MITRE ATT&CK:** T1003 — OS Credential Dumping

## Validation Results
| Validation | Result |
|---|---|
| YAML parsing | PASS |
| UUID validation | PASS |
| pySigma structural loading | PASS |
| pySigma rules loaded | 1 |

## Dataset Test
- **Dataset:** `datasets/raw/EVTX-ATTACK-SAMPLES/evtx_data.csv`
- **Total records:** 4633
- **Sysmon Event ID 10 records:** 140
- **PowerShell-to-LSASS matching records:** 3
- **Unique source process paths:** 1
- **Unique target process paths:** 1

### Matching Process Paths
| SourceImage                                               |   Count |
|:----------------------------------------------------------|--------:|
| C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |       3 |

### EVTX Scenario Distribution
| EVTX_FileName                                  |   Count |
|:-----------------------------------------------|--------:|
| babyshark_mimikatz_powershell.evtx             |       2 |
| sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx |       1 |

### Tactic Distribution
_Field not available in dataset._

## Sample Matching Evidence
| SourceImage                                               | TargetImage                   | GrantedAccess   | CallTrace                                                                   | EVTX_FileName                                  |
|:----------------------------------------------------------|:------------------------------|:----------------|:----------------------------------------------------------------------------|:-----------------------------------------------|
| C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | C:\Windows\system32\lsass.exe | 0x00001010      | C:\Windows\SYSTEM32\ntdll.dll+4595c|C:\Windows\system32\KERNELBASE.dll+8185 | babyshark_mimikatz_powershell.evtx             |
| C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | C:\Windows\system32\lsass.exe | 0x0000143a      | C:\Windows\SYSTEM32\ntdll.dll+4595c|C:\Windows\system32\KERNELBASE.dll+8185 | sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx |

## Analysis
The dataset test identifies Sysmon Event ID 10 records where the source process path ends with `\\powershell.exe` and the target process path ends with `\\lsass.exe`.

A match indicates PowerShell process access to LSASS. It does not independently prove credential dumping. Investigation should examine GrantedAccess, CallTrace, command-line activity, preceding DLL-load events, process ancestry and surrounding telemetry.

## False Positive Considerations
- Authorized incident response and forensic investigations.
- Approved security testing.
- Legitimate administrative scripts accessing LSASS.

## Limitations
- Dataset matching is an offline, condition-equivalent test; it is not a live SIEM/backend execution.
- pySigma structural loading does not prove backend query conversion or execution.
- Case-insensitive matching was used in the Python dataset test. Case-handling in the target Sigma backend remains unverified.
- Temporal correlation with preceding DLL-load activity has not been tested by this standalone rule test.
- No benign enterprise dataset was used to measure false-positive rate.

## Final Status
**PARTIALLY VALIDATED**

YAML, UUID, pySigma loading and offline dataset matching were tested. Backend conversion, live endpoint testing, temporal correlation and benign-data false-positive testing remain outstanding.
